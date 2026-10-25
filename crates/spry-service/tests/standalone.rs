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
    let output = command.stdin(Stdio::null()).output().unwrap();
    assert!(!output.status.success());
    String::from_utf8(output.stderr).unwrap()
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
}
