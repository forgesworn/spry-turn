use base64::{Engine, engine::general_purpose::STANDARD};
use secp256k1::{Keypair, SecretKey, schnorr};
use serde_json::json;
use spry_access::{hash, hex};
use std::{
    io::{Read, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    process::{Child, Command, Stdio},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

struct Service(Child);
impl Drop for Service {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn request(address: SocketAddr, method: &str, path: &str, auth: Option<&str>) -> String {
    let mut socket = TcpStream::connect_timeout(&address, Duration::from_secs(2)).unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    socket
        .set_write_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let authorization = auth.map_or(String::new(), |value| format!("Authorization: {value}\r\n"));
    write!(socket, "{method} {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nContent-Type: application/json\r\n{authorization}Content-Length: 2\r\n\r\n{{}}").unwrap();
    let mut bytes = Vec::new();
    socket.take(32_768).read_to_end(&mut bytes).unwrap();
    String::from_utf8(bytes).unwrap()
}

#[test]
fn standalone_host_uses_owner_signatures_without_an_archipelago_installation() {
    let signing = Keypair::from_secret_key(&SecretKey::from_secret_bytes([1; 32]).unwrap());
    let public = hex(&signing.x_only_public_key().0.to_byte_array());
    let reserved = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = reserved.local_addr().unwrap();
    drop(reserved);
    let child = Command::new(env!("CARGO_BIN_EXE_spry-node"))
        .env_clear()
        .env("SPRY_PUBLIC_URL", "https://relay.example:3744")
        .env("SPRY_KITHMOOT_URL", "https://calls.example/j/")
        .env("SPRY_OWNER_KEYS", &public)
        .env(
            "SPRY_TURN_SECRET",
            "synthetic-test-secret-not-for-deployment",
        )
        .env("SPRY_HTTP_PORT", address.port().to_string())
        // A documentation address cannot start the relay or touch live sockets.
        .env("SPRY_RELAY_IP", "192.0.2.1")
        .env(
            "SPRY_STATE_FILE",
            "uncreated-standalone-fixture/pairings.json",
        )
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut service = Service(child);
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if TcpStream::connect_timeout(&address, Duration::from_millis(50)).is_ok() {
            break;
        }
        assert!(service.0.try_wait().unwrap().is_none(), "service exited");
        assert!(Instant::now() < deadline, "service did not listen");
        std::thread::sleep(Duration::from_millis(10));
    }
    let index = request(address, "GET", "/", None);
    assert!(index.starts_with("HTTP/1.1 200"));
    assert!(index.contains("YOUR SPRY RELAY"));
    assert!(!index.contains("nostr-provider.js"));
    assert!(!index.contains("ARCHIPELAGO"));
    let status = request(address, "GET", "/v1/status", None);
    assert!(status.contains("\"ready\":false"));
    assert!(request(address, "GET", "/nostr-provider.js", None).starts_with("HTTP/1.1 404"));
    assert!(request(address, "POST", "/v1/pairings/list", None).starts_with("HTTP/1.1 401"));
    // Public mode is off unless the operator turns it on.
    assert!(request(address, "POST", "/v1/public/credentials", None).starts_with("HTTP/1.1 404"));

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let mut nonce = [0_u8; 32];
    getrandom::fill(&mut nonce).unwrap();
    let tags = json!([
        ["u", "https://relay.example:3744/v1/pairings/list"],
        ["method", "POST"],
        ["payload", &hash(b"{}")],
        [
            "nonce",
            &base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(nonce)
        ],
    ]);
    let id = hash(serde_json::to_vec(&json!([0, public, now, 27235, tags, ""])).unwrap());
    let digest: Vec<u8> = id
        .as_bytes()
        .chunks_exact(2)
        .map(|bytes| u8::from_str_radix(std::str::from_utf8(bytes).unwrap(), 16).unwrap())
        .collect();
    let signature = hex(&schnorr::sign_with_aux_rand(&digest, &signing, &[0; 32]).to_byte_array());
    let auth = format!("Nostr {}", STANDARD.encode(serde_json::to_vec(&json!({
        "kind":27235,"created_at":now,"tags":tags,"content":"", "pubkey":public,"id":id,"sig":signature
    })).unwrap()));
    let allowed = request(address, "POST", "/v1/pairings/list", Some(&auth));
    assert!(allowed.starts_with("HTTP/1.1 200"), "{allowed}");
    assert!(allowed.contains("\"pairings\":[]"));
    assert!(request(address, "POST", "/v1/pairings/list", Some(&auth)).starts_with("HTTP/1.1 401"));
}

fn refused_setup(extra: &[(&str, &str)]) -> String {
    let signing = Keypair::from_secret_key(&SecretKey::from_secret_bytes([1; 32]).unwrap());
    let reserved = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = reserved.local_addr().unwrap().port();
    drop(reserved);
    let mut command = Command::new(env!("CARGO_BIN_EXE_spry-node"));
    command
        .env_clear()
        .env("SPRY_PUBLIC_URL", "https://relay.example")
        .env("SPRY_OWNER_URL", "https://owner.example")
        .env("SPRY_KITHMOOT_URL", "https://calls.example/j/")
        .env(
            "SPRY_OWNER_KEYS",
            hex(&signing.x_only_public_key().0.to_byte_array()),
        )
        .env(
            "SPRY_TURN_SECRET",
            "synthetic-test-secret-not-for-deployment",
        )
        .env("SPRY_HTTP_PORT", port.to_string())
        .env("SPRY_RELAY_IP", "192.0.2.1")
        .env("SPRY_STATE_FILE", "uncreated-public-fixture/pairings.json");
    for (name, value) in extra {
        command.env(name, value);
    }
    let mut child = command
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            assert!(!status.success());
            let mut stderr = String::new();
            child
                .stderr
                .take()
                .unwrap()
                .read_to_string(&mut stderr)
                .unwrap();
            return stderr;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("invalid settings did not stop the service within five seconds");
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

#[test]
fn public_mode_refuses_the_private_node_profile_and_bad_settings_clearly() {
    let private = refused_setup(&[
        ("SPRY_PUBLIC", "true"),
        ("SPRY_PEER_BIND", "[fd12:3456::2]:3745"),
    ]);
    assert!(
        private.contains("SPRY_PUBLIC=true needs the standard profile"),
        "{private}"
    );
    let region = refused_setup(&[("SPRY_PUBLIC", "true"), ("SPRY_PUBLIC_REGION", "gb")]);
    assert!(region.contains("SPRY_PUBLIC_REGION"), "{region}");
    let relays = refused_setup(&[
        ("SPRY_PUBLIC", "true"),
        ("SPRY_PUBLIC_RELAYS", r#"["ws://relay.example/"]"#),
    ]);
    assert!(relays.contains("SPRY_PUBLIC_RELAYS"), "{relays}");
    assert!(!relays.contains("relay.example"), "{relays}");
    let ported = refused_setup(&[
        ("SPRY_PUBLIC_URL", "https://relay.example:3744"),
        ("SPRY_PUBLIC", "true"),
        ("SPRY_PUBLIC_RELAYS", r#"["wss://nostr.example/"]"#),
    ]);
    assert!(ported.contains("without a port"), "{ported}");
    for (name, value) in [
        ("SPRY_TURN_PORT", "0"),
        ("SPRY_TLS_PORT", "3478"),
        ("SPRY_RELAY_PORTS", "3478:3479"),
        ("SPRY_BYTES_PER_SECOND", "0"),
        ("SPRY_BYTES_PER_SECOND", "18446744073709551616"),
        ("SPRY_ROOM_SEAL", "yes"),
        ("SPRY_ROOM_SEAL", ""),
        ("SPRY_ROOM_SEAL", "Required"),
    ] {
        let refusal = refused_setup(&[(name, value)]);
        assert!(refusal.contains(name), "{refusal}");
        assert!(
            !refusal.contains("synthetic-test-secret"),
            "settings errors must not expose the secret"
        );
    }
    let custom_advert = refused_setup(&[
        ("SPRY_PUBLIC", "true"),
        ("SPRY_TURN_PORT", "3479"),
        ("SPRY_PUBLIC_RELAYS", r#"["wss://nostr.example/"]"#),
    ]);
    assert!(
        custom_advert.contains("SPRY_PUBLIC_URL"),
        "custom ports do not relax advert rules: {custom_advert}"
    );
}

mod profiles {
    use super::*;
    use serde_json::Value;
    use spry_turn::{auth, wire};
    use std::{
        fs,
        net::UdpSocket,
        path::{Path, PathBuf},
    };

    struct Profile {
        child: Child,
        directory: PathBuf,
        http: SocketAddr,
        turn: SocketAddr,
        tls_port: u16,
        relay_ports: (u16, u16),
        secret: String,
        _blocked_turn: Option<UdpSocket>,
    }
    impl Drop for Profile {
        fn drop(&mut self) {
            #[cfg(unix)]
            {
                // The service and its real relay child have one owned group.
                let group = format!("-{}", self.child.id());
                let _ = Command::new("/bin/kill")
                    .args(["-TERM", "--", &group])
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .status();
                let until = Instant::now() + Duration::from_secs(2);
                while self.child.try_wait().ok().flatten().is_none() && Instant::now() < until {
                    std::thread::sleep(Duration::from_millis(10));
                }
                if self.child.try_wait().ok().flatten().is_none() {
                    let _ = Command::new("/bin/kill")
                        .args(["-KILL", "--", &group])
                        .stdout(Stdio::null())
                        .stderr(Stdio::null())
                        .status();
                }
            }
            #[cfg(windows)]
            {
                let _ = Command::new("taskkill")
                    .args(["/F", "/T", "/PID", &self.child.id().to_string()])
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .status();
            }
            let _ = self.child.kill();
            let _ = self.child.wait();
            let _ = fs::remove_dir_all(&self.directory);
        }
    }

    struct Http {
        status: u16,
        headers: Vec<(String, String)>,
        body: String,
    }
    impl Http {
        fn header(&self, name: &str) -> Option<&str> {
            self.headers
                .iter()
                .find_map(|(key, value)| key.eq_ignore_ascii_case(name).then_some(value.as_str()))
        }
        fn json(&self) -> Value {
            serde_json::from_str(&self.body).unwrap()
        }
    }

    fn real_relay() -> PathBuf {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap();
        let configured = std::env::var_os("SPRY_TEST_RELAY_BINARY")
            .map(PathBuf::from)
            .unwrap_or_else(|| {
                PathBuf::from(format!(
                    "target/release/spry-turn{}",
                    std::env::consts::EXE_SUFFIX
                ))
            });
        let binary = if configured.is_absolute() {
            configured
        } else {
            root.join(configured)
        };
        assert!(
            binary.is_file(),
            "Build the real relay first: cargo build --locked --release --features tls --bin spry-turn; set SPRY_TEST_RELAY_BINARY if using another output path"
        );
        binary
    }

    impl Profile {
        fn start(block_turn: bool, private: bool) -> Self {
            let binary = real_relay();
            // Stay outside normal host ephemeral ranges, reserve every socket
            // together, and never share fixed ports with another test process.
            let (base, tcp, udp) = (0..64)
                .find_map(|_| {
                    let mut random = [0; 2];
                    getrandom::fill(&mut random).unwrap();
                    let base = 12_000 + (u16::from_be_bytes(random) % 1_000) * 8;
                    let ports = [base, base + 1, base + 2, base + 4, base + 5];
                    let tcp = ports
                        .iter()
                        .map(|port| TcpListener::bind(("127.0.0.1", *port)))
                        .collect::<std::io::Result<Vec<_>>>()
                        .ok()?;
                    let udp = ports
                        .iter()
                        .map(|port| UdpSocket::bind(("127.0.0.1", *port)))
                        .collect::<std::io::Result<Vec<_>>>()
                        .ok()?;
                    Some((base, tcp, udp))
                })
                .expect("isolated fixture ports unavailable");
            let mut random = [0; 16];
            getrandom::fill(&mut random).unwrap();
            let label = hex(&random);
            let directory =
                std::env::temp_dir().join(format!("spry-standard-{}-{label}", std::process::id()));
            fs::create_dir(&directory).unwrap();
            let secret = format!("synthetic-standard-profile-{label}");
            let http = format!("127.0.0.1:{base}").parse().unwrap();
            let turn = format!("127.0.0.1:{}", base + 1).parse().unwrap();
            let mut command = Command::new(env!("CARGO_BIN_EXE_spry-node"));
            command
                .env_clear()
                .env("SPRY_PUBLIC_URL", format!("https://relay.example:{base}"))
                .env(
                    "SPRY_OWNER_KEYS",
                    "1b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f",
                )
                .env("SPRY_TURN_SECRET", &secret)
                .env("SPRY_HTTP_PORT", base.to_string())
                .env("SPRY_RELAY_IP", "127.0.0.1")
                .env("SPRY_LOCAL_TEST", "true")
                .env("SPRY_RELAY_BINARY", binary)
                .env("SPRY_STATE_FILE", directory.join("pairings.json"))
                .env("SPRY_TURN_PORT", (base + 1).to_string())
                .env("SPRY_TLS_PORT", (base + 2).to_string())
                .env("SPRY_RELAY_PORTS", format!("{}:{}", base + 4, base + 5))
                .env("SPRY_BYTES_PER_SECOND", "8388608")
                .env("SPRY_TLS_GATE", "true")
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null());
            if private {
                command
                    .env("SPRY_PEER_BIND", "[fd12:3456::2]:3745")
                    // These new standard-only settings must not affect it.
                    .env("SPRY_TLS_PORT", "not-a-port")
                    .env("SPRY_RELAY_PORTS", "not-a-range")
                    .env("SPRY_BYTES_PER_SECOND", "0");
            } else {
                command.env("SPRY_PUBLIC", "true");
            }
            #[cfg(unix)]
            {
                use std::os::unix::process::CommandExt;
                command.process_group(0);
            }
            drop(tcp);
            drop(udp);
            let blocked = block_turn.then(|| UdpSocket::bind(turn).unwrap());
            let child = match command.spawn() {
                Ok(child) => child,
                Err(error) => {
                    let _ = fs::remove_dir_all(&directory);
                    panic!("service spawn failed: {error}");
                }
            };
            let mut profile = Self {
                child,
                directory,
                http,
                turn,
                tls_port: base + 2,
                relay_ports: (base + 4, base + 5),
                secret,
                _blocked_turn: blocked,
            };
            let deadline = Instant::now() + Duration::from_secs(8);
            loop {
                assert!(
                    profile.child.try_wait().unwrap().is_none(),
                    "configured service exited"
                );
                if let Ok(status) = profile.http("GET", "/v1/status", "", None) {
                    let ready = status.json()["ready"].as_bool().unwrap();
                    if ready == (!block_turn && !private) {
                        break;
                    }
                }
                assert!(
                    Instant::now() < deadline,
                    "configured service did not reach its own readiness state"
                );
                std::thread::sleep(Duration::from_millis(10));
            }
            profile
        }

        fn http(
            &self,
            method: &str,
            path: &str,
            body: &str,
            origin: Option<&str>,
        ) -> std::io::Result<Http> {
            let mut stream = TcpStream::connect_timeout(&self.http, Duration::from_millis(100))?;
            stream.set_read_timeout(Some(Duration::from_secs(2)))?;
            stream.set_write_timeout(Some(Duration::from_secs(2)))?;
            let origin = origin.map_or(String::new(), |value| format!("Origin: {value}\r\n"));
            let preflight = if method == "OPTIONS" {
                "Access-Control-Request-Method: POST\r\nAccess-Control-Request-Headers: content-type\r\n"
            } else {
                ""
            };
            write!(
                stream,
                "{method} {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nContent-Type: application/json\r\n{origin}{preflight}Content-Length: {}\r\n\r\n{body}",
                body.len()
            )?;
            let mut bytes = Vec::new();
            stream.take(32_768).read_to_end(&mut bytes)?;
            let text = String::from_utf8(bytes).map_err(std::io::Error::other)?;
            let (head, body) = text
                .split_once("\r\n\r\n")
                .ok_or_else(|| std::io::Error::other("missing HTTP response"))?;
            let mut lines = head.lines();
            let status = lines
                .next()
                .unwrap()
                .split_whitespace()
                .nth(1)
                .unwrap()
                .parse()
                .unwrap();
            let headers = lines
                .filter_map(|line| {
                    line.split_once(':')
                        .map(|(key, value)| (key.to_string(), value.trim().to_string()))
                })
                .collect();
            Ok(Http {
                status,
                headers,
                body: body.to_string(),
            })
        }

        fn lease(&self) -> Value {
            let before = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs();
            let preflight = self
                .http(
                    "OPTIONS",
                    "/v1/public/credentials",
                    "",
                    Some("https://viewer.example"),
                )
                .unwrap();
            assert_eq!(preflight.status, 204);
            assert_eq!(preflight.header("access-control-allow-origin"), Some("*"));
            let response = self
                .http(
                    "POST",
                    "/v1/public/credentials",
                    r#"{"v":1}"#,
                    Some("https://viewer.example"),
                )
                .unwrap();
            assert_eq!(response.status, 200);
            assert_eq!(response.header("cache-control"), Some("no-store"));
            assert_eq!(response.header("access-control-allow-origin"), Some("*"));
            let lease = response.json();
            let fields = lease.as_object().unwrap();
            assert_eq!(fields.len(), 4);
            assert!(fields.keys().all(|key| {
                ["urls", "username", "credential", "expiresAt"].contains(&key.as_str())
            }));
            assert_eq!(
                lease["urls"],
                json!([
                    format!("turn:relay.example:{}?transport=udp", self.turn.port()),
                    format!("turn:relay.example:{}?transport=tcp", self.turn.port()),
                    format!("turns:relay.example:{}?transport=tcp", self.tls_port)
                ])
            );
            let expiry = lease["expiresAt"].as_u64().unwrap();
            let after = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs();
            assert!((before + 3600..=after + 3600).contains(&expiry));
            let user = lease["username"].as_str().unwrap();
            let label = user.strip_prefix(&format!("{expiry}:pub-")).unwrap();
            assert_eq!(label.len(), 24);
            assert!(
                label
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            );
            assert_eq!(
                lease["credential"],
                auth::credential(self.secret.as_bytes(), user)
            );
            assert_eq!(
                self.http("POST", "/v1/pairings/list", "{}", None)
                    .unwrap()
                    .status,
                401
            );
            lease
        }

        fn allocate(&self, lease: &Value, accepted: bool) {
            let mut socket =
                TcpStream::connect_timeout(&self.turn, Duration::from_secs(2)).unwrap();
            socket
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            socket
                .set_write_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let mut request = wire::Builder::new(wire::ALLOCATE, 0, [1; 12]);
            request.attr(wire::TRANSPORT, &[17, 0, 0, 0]);
            socket.write_all(&request.finish(None)).unwrap();
            let challenge = frame(&mut socket);
            let message = wire::Message::parse(&challenge).unwrap();
            assert_eq!(message.class, 3);
            let realm = std::str::from_utf8(message.attr(wire::REALM).unwrap()).unwrap();
            let user = lease["username"].as_str().unwrap();
            let key = auth::key(user, realm, lease["credential"].as_str().unwrap());
            let mut request = wire::Builder::new(wire::ALLOCATE, 0, [2; 12]);
            request
                .attr(wire::TRANSPORT, &[17, 0, 0, 0])
                .attr(wire::USERNAME, user.as_bytes())
                .attr(wire::REALM, realm.as_bytes())
                .attr(wire::NONCE, message.attr(wire::NONCE).unwrap());
            socket.write_all(&request.finish(Some(&key))).unwrap();
            let response = frame(&mut socket);
            let message = wire::Message::parse(&response).unwrap();
            if accepted {
                assert_eq!(message.class, 2);
                assert!(message.verify(&key));
                let allocated = message.address(wire::RELAYED).unwrap();
                assert!((self.relay_ports.0..=self.relay_ports.1).contains(&allocated.port()));
            } else {
                assert_eq!(message.class, 3);
                let code = message.attr(wire::ERROR).unwrap();
                assert_eq!(u16::from(code[2]) * 100 + u16::from(code[3]), 401);
            }
        }
    }

    fn frame(socket: &mut TcpStream) -> Vec<u8> {
        let mut header = [0; 20];
        socket.read_exact(&mut header).unwrap();
        let size = usize::from(u16::from_be_bytes([header[2], header[3]]));
        assert!(size <= 4096);
        let mut bytes = header.to_vec();
        bytes.resize(20 + size, 0);
        socket.read_exact(&mut bytes[20..]).unwrap();
        bytes
    }

    #[test]
    fn distinct_standard_profiles_issue_only_their_own_urls_and_relay_credentials() {
        let first = Profile::start(false, false);
        let second = Profile::start(false, false);
        let a = first.lease();
        let b = second.lease();
        first.allocate(&a, true);
        second.allocate(&b, true);
        first.allocate(&b, false);
        second.allocate(&a, false);
        let blocked = Profile::start(true, false);
        let unavailable = blocked
            .http(
                "POST",
                "/v1/public/credentials",
                r#"{"v":1}"#,
                Some("https://viewer.example"),
            )
            .unwrap();
        assert_eq!(unavailable.status, 503);
        assert!(
            unavailable.json().get("credential").is_none(),
            "another profile cannot make this relay ready"
        );
    }

    #[test]
    fn private_profile_does_not_parse_the_new_standard_only_settings() {
        let private = Profile::start(false, true);
        assert_eq!(
            private
                .http(
                    "POST",
                    "/v1/public/credentials",
                    r#"{"v":1}"#,
                    Some("https://viewer.example")
                )
                .unwrap()
                .status,
            404
        );
    }
}
