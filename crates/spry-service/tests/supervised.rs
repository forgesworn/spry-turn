//! `spry-node supervised` as a host application runs it: a child process
//! with a held stdin pipe, a generated loopback Nostr relay for control, and
//! a real TURN allocation through the embedded relay. Local evidence only;
//! no router, NAT or remote network is involved.
use futures_util::{SinkExt, StreamExt};
use serde_json::{Value, json};
use spry_link::{
    control::{self, ControlEndpoint, RelayPolicy},
    identity::{Event, Identity},
    standard::StandardCard,
};
use spry_turn::{auth, wire};
use std::{
    io::{BufRead, BufReader, Read, Write},
    net::{TcpListener, TcpStream, UdpSocket},
    process::{Child, ChildStdin, Command, Stdio},
    sync::mpsc,
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tokio::sync::broadcast;
use tokio_tungstenite::{accept_async, connect_async, tungstenite::Message};

const SECRET: &str = "synthetic-supervised-secret-not-for-deployment";
const PUBLIC_IP: &str = "203.0.113.7";

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// A loopback relay that answers every subscription with EOSE and passes
/// every event to every subscription. Recipients filter for themselves.
async fn fixture_relay() -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("ws://{}/", listener.local_addr().unwrap());
    let (events, _) = broadcast::channel::<Value>(256);
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            let events = events.clone();
            tokio::spawn(async move {
                let Ok(mut socket) = accept_async(stream).await else {
                    return;
                };
                let mut receiver = events.subscribe();
                let mut subscriptions: Vec<Value> = Vec::new();
                loop {
                    tokio::select! {
                        message = socket.next() => {
                            let Some(Ok(message)) = message else { return };
                            let Message::Text(text) = message else { continue };
                            let Ok(value) = serde_json::from_str::<Value>(&text) else { continue };
                            match value[0].as_str() {
                                Some("REQ") => {
                                    subscriptions.push(value[1].clone());
                                    let _ = socket.send(Message::Text(json!(["EOSE", value[1]]).to_string().into())).await;
                                }
                                Some("EVENT") => {
                                    let _ = socket.send(Message::Text(json!(["OK", value[1]["id"], true, ""]).to_string().into())).await;
                                    let _ = events.send(value[1].clone());
                                }
                                _ => {}
                            }
                        }
                        event = receiver.recv() => {
                            let Ok(event) = event else { continue };
                            for subscription in &subscriptions {
                                let _ = socket.send(Message::Text(json!(["EVENT", subscription, event]).to_string().into())).await;
                            }
                        }
                    }
                }
            });
        }
    });
    url
}

/// Held from reserving ports until the node has bound them or exited, so
/// parallel tests never pick the same free ports.
static STARTING: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Loopback ports for the listener and two allocation ports, reserved
/// together and released just before the node binds them.
fn ports() -> (u16, u16, u16) {
    for _ in 0..64 {
        let mut random = [0; 2];
        getrandom::fill(&mut random).unwrap();
        let base = 20_000 + (u16::from_be_bytes(random) % 1_000) * 8;
        let candidates = [base, base + 2, base + 3];
        let tcp: Option<Vec<_>> = candidates
            .iter()
            .map(|port| TcpListener::bind(("127.0.0.1", *port)).ok())
            .collect();
        let udp: Option<Vec<_>> = candidates
            .iter()
            .map(|port| UdpSocket::bind(("127.0.0.1", *port)).ok())
            .collect();
        if tcp.is_some() && udp.is_some() {
            return (base, base + 2, base + 3);
        }
    }
    panic!("isolated fixture ports unavailable");
}

struct Node {
    child: Child,
    stdin: Option<ChildStdin>,
    lines: mpsc::Receiver<Value>,
    directory: std::path::PathBuf,
}
impl Drop for Node {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.directory);
    }
}
impl Node {
    fn line(&self, event: &str) -> Value {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            let line = self
                .lines
                .recv_timeout(left)
                .unwrap_or_else(|_| panic!("no {event} line"));
            if line["event"] == event {
                return line;
            }
        }
    }
}

fn scratch() -> std::path::PathBuf {
    let mut random = [0_u8; 16];
    getrandom::fill(&mut random).unwrap();
    let directory = std::env::temp_dir().join(format!(
        "spry-supervised-node-{}",
        spry_access::hex(&random)
    ));
    std::fs::create_dir(&directory).unwrap();
    directory
}

fn spawn(relay: &str, listen: u16, first: u16, second: u16, host: &str) -> Node {
    let directory = scratch();
    let mut command = Command::new(env!("CARGO_BIN_EXE_spry-node"));
    command
        .env_clear()
        .env("SPRY_TURN_SECRET", SECRET)
        .env("SPRY_LOCAL_TEST", "true")
        .args(["supervised", "--exit-on-stdin-close", "--pairing-key", host])
        .arg("--state-file")
        .arg(directory.join("state.json"))
        .args([
            "--control-relay",
            relay,
            "--bind",
            "127.0.0.1",
            "--public-ip",
            PUBLIC_IP,
            "--listen-port",
            &listen.to_string(),
            "--public-udp-port",
            "51000",
            "--public-tcp-port",
            "51001",
            "--relay-port-map",
            &format!("{first}:51002"),
            "--relay-port-map",
            &format!("{second}:51003"),
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    let mut child = command.spawn().unwrap();
    let stdin = child.stdin.take();
    let stdout = child.stdout.take().unwrap();
    let (send, lines) = mpsc::channel();
    thread::spawn(move || {
        for line in BufReader::new(stdout).lines().map_while(Result::ok) {
            // Every stdout line is one JSON object.
            let value: Value = serde_json::from_str(&line).expect("stdout line is JSON");
            if send.send(value).is_err() {
                return;
            }
        }
    });
    Node {
        child,
        stdin,
        lines,
        directory,
    }
}

type Socket =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

async fn client(relay: &str) -> Socket {
    let (mut socket, _) = connect_async(relay).await.unwrap();
    socket
        .send(Message::Text(
            json!(["REQ", "client", {"kinds":[control::RESPONSE_KIND]}])
                .to_string()
                .into(),
        ))
        .await
        .unwrap();
    socket
}

async fn ask(
    socket: &mut Socket,
    signer: &Identity,
    target: &ControlEndpoint,
    path: &str,
    body: Value,
) -> (u16, Value) {
    let request = control::request(signer, target, path, &body, now()).unwrap();
    socket
        .send(Message::Text(json!(["EVENT", request]).to_string().into()))
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let Some(Ok(Message::Text(text))) = socket.next().await else {
                continue;
            };
            let value: Value = serde_json::from_str(&text).unwrap();
            if value[0] != "EVENT" || value[2]["kind"] != control::RESPONSE_KIND {
                continue;
            }
            let event: Event = serde_json::from_value(value[2].clone()).unwrap();
            if let Ok(answer) = control::open_response(signer, &request, target, &event, now()) {
                return answer;
            }
        }
    })
    .await
    .unwrap_or_else(|_| panic!("no answer on {path}"))
}

/// A long-term-credential UDP allocation: the relayed address, or the
/// refusal's error code.
fn allocate(listen: u16, issued: &Value) -> Result<std::net::SocketAddr, u16> {
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    socket.connect(("127.0.0.1", listen)).unwrap();
    let mut request = wire::Builder::new(wire::ALLOCATE, 0, [1; 12]);
    request.attr(wire::TRANSPORT, &[17, 0, 0, 0]);
    socket.send(&request.finish(None)).unwrap();
    let mut bytes = [0; 2048];
    let size = socket.recv(&mut bytes).unwrap();
    let challenge = wire::Message::parse(&bytes[..size]).unwrap();
    assert_eq!(challenge.class, 3);
    let realm = std::str::from_utf8(challenge.attr(wire::REALM).unwrap())
        .unwrap()
        .to_owned();
    let nonce = challenge.attr(wire::NONCE).unwrap().to_vec();
    let user = issued["username"].as_str().unwrap();
    let key = auth::key(user, &realm, issued["credential"].as_str().unwrap());
    let mut request = wire::Builder::new(wire::ALLOCATE, 0, [2; 12]);
    request
        .attr(wire::TRANSPORT, &[17, 0, 0, 0])
        .attr(wire::USERNAME, user.as_bytes())
        .attr(wire::REALM, realm.as_bytes())
        .attr(wire::NONCE, &nonce);
    socket.send(&request.finish(Some(&key))).unwrap();
    let size = socket.recv(&mut bytes).unwrap();
    let response = wire::Message::parse(&bytes[..size]).unwrap();
    if response.class != 2 {
        let code = response.attr(wire::ERROR).unwrap();
        return Err(u16::from(code[2]) * 100 + u16::from(code[3]));
    }
    assert!(response.verify(&key));
    Ok(response.address(wire::RELAYED).unwrap())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_supervised_node_answers_room_grants_over_control_and_dies_with_its_supervisor() {
    let relay = fixture_relay().await;
    let host = Identity::from_secret(&[2; 32]).unwrap();
    let guest = Identity::from_secret(&[3; 32]).unwrap();
    let starting = STARTING
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let (listen, first, second) = ports();
    let mut node = spawn(&relay, listen, first, second, &host.public_key());

    let ready = node.line("ready");
    drop(starting);
    let node_key = Identity::derive(SECRET.as_bytes()).unwrap().public_key();
    let target = ControlEndpoint::new(
        node_key.clone(),
        vec![relay.clone()],
        RelayPolicy::LocalFixture,
    )
    .unwrap();
    assert_eq!(ready["endpoint"], target.uri().unwrap());
    let urls = json!([
        format!("turn:{PUBLIC_IP}:51000?transport=udp"),
        format!("turn:{PUBLIC_IP}:51001?transport=tcp")
    ]);
    assert_eq!(ready["urls"], urls);
    assert_eq!(
        ready["relayPortMap"],
        json!([[first, 51002], [second, 51003]])
    );
    let pairing = ready["pairing"].as_str().unwrap().to_owned();
    assert_eq!(pairing.len(), 43);
    assert_eq!(
        ready.as_object().unwrap().len(),
        6,
        "no field beyond v, event, endpoint, pairing, urls and relayPortMap: {ready}"
    );
    let connected = node.line("control");
    assert_eq!(connected["relays"], 1);

    let mut socket = client(&relay).await;
    let (status, granted) = ask(
        &mut socket,
        &host,
        &target,
        "/v1/grants",
        json!({"pairing":pairing,"scope":spry_access::hash("synthetic-room")}),
    )
    .await;
    assert_eq!(status, 200, "{granted}");
    assert_eq!(granted["endpoint"], ready["endpoint"]);
    let card = StandardCard::verify(
        serde_json::from_value(granted["node"].clone()).unwrap(),
        now(),
    )
    .unwrap();
    assert_eq!(card.event.pubkey, node_key);
    let token = granted["token"].as_str().unwrap().to_owned();

    // Sealed from the start: an unregistered guest is refused with no card.
    let (status, refused) = ask(
        &mut socket,
        &guest,
        &target,
        "/v1/credentials",
        json!({"grant":token}),
    )
    .await;
    assert_eq!(
        (status, refused),
        (403, json!({"error":"Call access has expired."}))
    );
    // Claim codes, self-removal and peer routes do not exist here.
    for (path, body) in [
        ("/v1/pairings/claim", json!({"code":"A".repeat(43)})),
        ("/v1/pairings/remove-self", json!({"id":pairing})),
        (
            "/v1/peers",
            json!({"pairing":pairing,"scope":"0".repeat(64),"device":"0".repeat(64),"revision":1,"peers":[]}),
        ),
    ] {
        let answer = ask(&mut socket, &host, &target, path, body).await;
        assert_eq!(answer, (404, json!({"error":"Not found."})), "{path}");
    }
    let (status, registered) = ask(
        &mut socket,
        &host,
        &target,
        "/v1/grants/devices",
        json!({"v":1,"pairing":pairing,"grant":token,"add":[host.public_key(), guest.public_key()],"revision":1}),
    )
    .await;
    assert_eq!(status, 200, "{registered}");
    assert_eq!(registered["enforced"], true);
    let (status, issued) = ask(
        &mut socket,
        &guest,
        &target,
        "/v1/credentials",
        json!({"grant":token}),
    )
    .await;
    assert_eq!(status, 200, "{issued}");
    assert_eq!(issued["urls"], urls);
    assert!(
        StandardCard::verify(
            serde_json::from_value(issued["node"].clone()).unwrap(),
            now()
        )
        .is_ok()
    );

    // The embedded relay accepts those credentials and advertises the
    // supervisor's public address and mapped port, not the local bind.
    let relayed = allocate(listen, &issued).unwrap();
    assert_eq!(relayed.ip().to_string(), PUBLIC_IP);
    assert!([51002, 51003].contains(&relayed.port()), "{relayed}");
    // A wrong password is refused by the same relay.
    let mut forged = issued.clone();
    forged["credential"] = json!(auth::credential(
        b"another-secret-of-at-least-32-bytes!",
        forged["username"].as_str().unwrap()
    ));
    assert_eq!(allocate(listen, &forged), Err(401));

    // The TCP port is the TURN listener, not an HTTP service.
    let mut probe = TcpStream::connect(("127.0.0.1", listen)).unwrap();
    probe
        .set_read_timeout(Some(Duration::from_millis(500)))
        .unwrap();
    probe
        .write_all(b"GET /v1/status HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .unwrap();
    let mut reply = Vec::new();
    let _ = probe.take(4096).read_to_end(&mut reply);
    assert!(
        !reply.starts_with(b"HTTP/"),
        "no HTTP answer on the listener"
    );

    // Closing the supervisor's pipe ends the node and frees its ports.
    drop(node.stdin.take());
    let deadline = Instant::now() + Duration::from_secs(3);
    let status = loop {
        if let Some(status) = node.child.try_wait().unwrap() {
            break status;
        }
        assert!(Instant::now() < deadline, "node outlived its stdin pipe");
        thread::sleep(Duration::from_millis(10));
    };
    assert!(status.success());
    UdpSocket::bind(("127.0.0.1", listen)).expect("listener UDP port freed");
    TcpListener::bind(("127.0.0.1", listen)).expect("listener TCP port freed");
    UdpSocket::bind(("127.0.0.1", first)).expect("mapped port freed");
    UdpSocket::bind(("127.0.0.1", second)).expect("mapped port freed");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_port_in_use_stops_the_node_before_it_writes_state_or_reports_ready() {
    let relay = fixture_relay().await;
    let host = Identity::from_secret(&[2; 32]).unwrap();
    let _starting = STARTING
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let (listen, first, second) = ports();
    let occupied = UdpSocket::bind(("127.0.0.1", listen)).unwrap();
    let mut node = spawn(&relay, listen, first, second, &host.public_key());
    let deadline = Instant::now() + Duration::from_secs(5);
    let status = loop {
        if let Some(status) = node.child.try_wait().unwrap() {
            break status;
        }
        assert!(Instant::now() < deadline, "node started on a port in use");
        thread::sleep(Duration::from_millis(10));
    };
    assert!(!status.success());
    assert!(node.lines.recv_timeout(Duration::from_millis(200)).is_err());
    assert!(!node.directory.join("state.json").exists());
    drop(occupied);
}

fn refused(arguments: &[&str], environment: &[(&str, &str)]) -> String {
    let directory = scratch();
    let state = directory.join("state.json");
    let mut command = Command::new(env!("CARGO_BIN_EXE_spry-node"));
    command
        .env_clear()
        .env("SPRY_TURN_SECRET", SECRET)
        .arg("supervised")
        .args(arguments)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for (name, value) in environment {
        command.env(name, value);
    }
    if !arguments.contains(&"--state-file") {
        command.arg("--state-file").arg(&state);
    }
    let mut child = command.spawn().unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    let result = loop {
        if let Some(status) = child.try_wait().unwrap() {
            assert!(!status.success());
            let mut stdout = String::new();
            child
                .stdout
                .take()
                .unwrap()
                .read_to_string(&mut stdout)
                .unwrap();
            assert!(stdout.is_empty(), "no readiness line on refusal: {stdout}");
            let mut stderr = String::new();
            child
                .stderr
                .take()
                .unwrap()
                .read_to_string(&mut stderr)
                .unwrap();
            break stderr;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("refused settings did not stop the node");
        }
        thread::sleep(Duration::from_millis(10));
    };
    assert!(!state.exists(), "a refused start writes no state: {result}");
    let _ = std::fs::remove_dir_all(directory);
    result
}

#[test]
fn other_profiles_settings_and_open_modes_refuse_to_start() {
    let host = Identity::from_secret(&[2; 32]).unwrap().public_key();
    let valid: Vec<&str> = vec![
        "--exit-on-stdin-close",
        "--pairing-key",
        &host,
        "--control-relay",
        "wss://relay.example/",
        "--bind",
        "192.168.1.20",
        "--public-ip",
        // Outside every refused range; never contacted.
        "100.128.0.7",
        "--listen-port",
        "41000",
        "--public-udp-port",
        "51000",
        "--public-tcp-port",
        "51001",
        "--relay-port-map",
        "41002:51002",
    ];
    for (name, value) in [
        ("SPRY_PUBLIC", "true"),
        ("SPRY_PUBLIC_RELAYS", r#"["wss://nostr.example/"]"#),
        ("SPRY_HTTP_PORT", "3744"),
        ("SPRY_HTTP_BIND", "127.0.0.1"),
        ("SPRY_PUBLIC_URL", "https://relay.example"),
        ("SPRY_OWNER_KEYS", host.as_str()),
        ("SPRY_PEER_BIND", "[fd12:3456::2]:3745"),
        ("SPRY_PEER_INTERFACE", "fips0"),
        ("SPRY_RELAY_IP", "192.168.1.20"),
        ("SPRY_RELAY_BINARY", "spry-turn"),
        ("SPRY_CONTROL_RELAYS", r#"["wss://nostr.example/"]"#),
    ] {
        let refusal = refused(&valid, &[(name, value)]);
        assert!(
            refusal.contains("unset every other SPRY_ setting"),
            "{name}: {refusal}"
        );
        assert!(!refusal.contains(value) || value == "true", "{refusal}");
        assert!(!refusal.contains(SECRET), "{refusal}");
    }
    for seal in ["auto", "off"] {
        let refusal = refused(&valid, &[("SPRY_ROOM_SEAL", seal)]);
        assert!(refusal.contains("SPRY_ROOM_SEAL"), "{refusal}");
    }
    let unwatched: Vec<&str> = valid[1..].to_vec();
    assert!(refused(&unwatched, &[]).contains("--exit-on-stdin-close is required"));
    let mut private_bind = valid.clone();
    private_bind[8] = "203.0.113.7";
    assert!(refused(&private_bind, &[]).contains("--public-ip"));
    let refusal = {
        let mut command = Command::new(env!("CARGO_BIN_EXE_spry-node"));
        let output = command
            .env_clear()
            .env("SPRY_TURN_SECRET", "too-short")
            .arg("supervised")
            .args(&valid)
            .args(["--state-file", "uncreated-supervised-fixture/state.json"])
            .stdin(Stdio::null())
            .output()
            .unwrap();
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
        String::from_utf8(output.stderr).unwrap()
    };
    assert!(refusal.contains("SPRY_TURN_SECRET"), "{refusal}");
    assert!(!refusal.contains("too-short"), "{refusal}");
}
