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
    spawn_with(relay, listen, first, second, host, &[])
}

fn spawn_with(
    relay: &str,
    listen: u16,
    first: u16,
    second: u16,
    host: &str,
    extra: &[&str],
) -> Node {
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
        .args(extra)
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

/// A live long-term-credential UDP allocation and what it needs to keep
/// talking to the relay.
struct Open {
    socket: UdpSocket,
    key: Vec<u8>,
    user: String,
    realm: String,
    nonce: Vec<u8>,
    relayed: std::net::SocketAddr,
}

/// A long-term-credential UDP allocation: the open allocation, or the
/// refusal's error code.
fn open_allocation(listen: u16, issued: &Value) -> Result<Open, u16> {
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
    let user = issued["username"].as_str().unwrap().to_owned();
    let key = auth::key(&user, &realm, issued["credential"].as_str().unwrap()).to_vec();
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
    let relayed = response.address(wire::RELAYED).unwrap();
    Ok(Open {
        socket,
        key,
        user,
        realm,
        nonce,
        relayed,
    })
}

fn allocate(listen: u16, issued: &Value) -> Result<std::net::SocketAddr, u16> {
    open_allocation(listen, issued).map(|open| open.relayed)
}

impl Open {
    /// Let `peer`'s address send to this allocation.
    fn permit(&self, peer: std::net::SocketAddr) {
        let mut request = wire::Builder::new(wire::PERMISSION, 0, [3; 12]);
        request
            .address(wire::PEER, peer)
            .attr(wire::USERNAME, self.user.as_bytes())
            .attr(wire::REALM, self.realm.as_bytes())
            .attr(wire::NONCE, &self.nonce);
        self.socket.send(&request.finish(Some(&self.key))).unwrap();
        let mut bytes = [0; 2048];
        let size = self.socket.recv(&mut bytes).unwrap();
        let response = wire::Message::parse(&bytes[..size]).unwrap();
        assert_eq!(response.class, 2, "{:?}", response.attr(wire::ERROR));
    }
    /// A Send indication: the relay answers nothing, forwarded or not.
    fn send(&self, peer: std::net::SocketAddr, payload: &[u8]) {
        let mut indication = wire::Builder::new(wire::SEND, 1, [4; 12]);
        indication
            .address(wire::PEER, peer)
            .attr(wire::DATA, payload);
        self.socket.send(&indication.finish(None)).unwrap();
    }
}

/// Data indications that reach a client before it has been quiet for 300 ms.
fn data_indications(client: &UdpSocket) -> usize {
    client
        .set_read_timeout(Some(Duration::from_millis(300)))
        .unwrap();
    let mut bytes = [0; 2048];
    let mut count = 0;
    while let Ok(size) = client.recv(&mut bytes) {
        let message = wire::Message::parse(&bytes[..size]);
        if message.is_some_and(|message| message.method == wire::DATA_METHOD) {
            count += 1;
        }
    }
    count
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

/// Every status line is exactly these keys with numbers (or null), so
/// nothing that names a guest, a room or an address can ride on it.
fn assert_counts_only(status: &Value) {
    let object = status.as_object().unwrap();
    let mut keys: Vec<_> = object.keys().map(String::as_str).collect();
    keys.sort_unstable();
    assert_eq!(
        keys,
        [
            "allocations",
            "bytesRelayed",
            "event",
            "lastAllocation",
            "v"
        ],
        "{status}"
    );
    assert_eq!(
        (&status["v"], &status["event"]),
        (&json!(1), &json!("status"))
    );
    for key in ["allocations", "bytesRelayed"] {
        assert!(status[key].is_u64(), "{key}: {status}");
    }
    assert!(
        status["lastAllocation"].is_null() || status["lastAllocation"].is_u64(),
        "{status}"
    );
    assert!(status.to_string().len() < 160, "bounded: {status}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_aggregate_cap_is_shared_by_all_allocations_and_the_status_line_is_counts_only() {
    let relay = fixture_relay().await;
    let host = Identity::from_secret(&[2; 32]).unwrap();
    let guest = Identity::from_secret(&[3; 32]).unwrap();
    let starting = STARTING
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let (listen, first, second) = ports();
    // 5000 bytes a second in all, against 125,000 for each allocation.
    let node = spawn_with(
        &relay,
        listen,
        first,
        second,
        &host.public_key(),
        &["--aggregate-bytes-per-second", "5000"],
    );
    let ready = node.line("ready");
    drop(starting);
    // The first count is printed with ready, before anything has happened.
    let idle = node.line("status");
    assert_counts_only(&idle);
    assert_eq!(
        idle,
        json!({"v":1,"event":"status","allocations":0,"bytesRelayed":0,"lastAllocation":null})
    );
    node.line("control");

    let node_key = Identity::derive(SECRET.as_bytes()).unwrap().public_key();
    let target = ControlEndpoint::new(
        node_key.clone(),
        vec![relay.clone()],
        RelayPolicy::LocalFixture,
    )
    .unwrap();
    let pairing = ready["pairing"].as_str().unwrap().to_owned();
    let mut socket = client(&relay).await;
    let room = spry_access::hash("synthetic-room-for-the-status-line");
    let (status, granted) = ask(
        &mut socket,
        &host,
        &target,
        "/v1/grants",
        json!({"pairing":pairing,"scope":room}),
    )
    .await;
    assert_eq!(status, 200, "{granted}");
    let token = granted["token"].as_str().unwrap().to_owned();
    let (status, registered) = ask(
        &mut socket,
        &host,
        &target,
        "/v1/grants/devices",
        json!({"v":1,"pairing":pairing,"grant":token,"add":[host.public_key(), guest.public_key()],"revision":1}),
    )
    .await;
    assert_eq!(status, 200, "{registered}");
    let (status, issued) = ask(
        &mut socket,
        &guest,
        &target,
        "/v1/credentials",
        json!({"grant":token}),
    )
    .await;
    assert_eq!(status, 200, "{issued}");

    // Two allocations, each far inside its own allowance of 125,000 a
    // second. In mapped mode a peer on the node's own address must be one of
    // its allocation ports, so the first allocation sends to the second:
    // every packet is spent once on the way out and once on the way in, by
    // two different allocations, against the one shared allowance.
    let a = open_allocation(listen, &issued).unwrap();
    let b = open_allocation(listen, &issued).unwrap();
    let local = |open: &Open| {
        let port = if open.relayed.port() == 51002 {
            first
        } else {
            second
        };
        std::net::SocketAddr::from(([127, 0, 0, 1], port))
    };
    a.permit(local(&b));
    b.permit(local(&a));
    let payload = [0x5a; 1000];
    for _ in 0..10 {
        a.send(local(&b), &payload);
    }
    let arrived = data_indications(&b.socket);
    assert!(arrived <= 5, "{arrived} of 1000 bytes reached the second");

    // The next count that differs is printed within a few seconds: both
    // allocations, the bytes that crossed, and no time because both clients
    // are on this machine.
    let deadline = Instant::now() + Duration::from_secs(15);
    let busy = loop {
        let status = node.line("status");
        assert_counts_only(&status);
        if status["allocations"] == 2 && status["bytesRelayed"].as_u64().unwrap() >= 4000 {
            break status;
        }
        assert!(Instant::now() < deadline, "no busy status line");
    };
    assert_eq!(busy["lastAllocation"], Value::Null);
    // Twenty thousand bytes were asked for and 5000 a second allowed; each
    // allocation alone spent far less than its own allowance, so only the
    // total can have stopped them.
    let moved = busy["bytesRelayed"].as_u64().unwrap();
    assert!(
        (4000..=6000).contains(&moved) && moved % 1000 == 0,
        "{busy}"
    );

    // Nothing that identifies anyone or anything is anywhere in the line.
    let text = busy.to_string();
    for secret in [
        host.public_key(),
        guest.public_key(),
        node_key,
        pairing,
        token,
        room,
        a.user.clone(),
        issued["credential"].as_str().unwrap().to_owned(),
        a.socket.local_addr().unwrap().port().to_string(),
        b.socket.local_addr().unwrap().port().to_string(),
        first.to_string(),
        second.to_string(),
        a.relayed.port().to_string(),
        listen.to_string(),
        "127.0.0.1".to_owned(),
        PUBLIC_IP.to_owned(),
        relay.clone(),
        "wss".to_owned(),
        "turn:".to_owned(),
    ] {
        assert!(!text.contains(&secret), "{secret} appears in {text}");
    }
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

// ---------------------------------------------------------------------------
// `--map-ports`: the node asks the router for its public values. The router is
// one of the in-house fake gateways on loopback; nothing real is involved.
// ---------------------------------------------------------------------------

use spry_portmap::{
    Protocol,
    fake::{
        EXTERNAL, FakeNatGateway, FakeUpnpGateway, NatBehaviour, NatPmpMode, PcpMode, UpnpBehaviour,
    },
    record::Ledger,
};
use std::net::SocketAddrV4;
use std::path::Path;

impl Node {
    /// The next line of any kind.
    fn next(&self) -> Value {
        self.lines
            .recv_timeout(Duration::from_secs(10))
            .expect("no further line")
    }
    /// The next `portmap` line, with the state it must be in.
    fn portmap(&self, state: &str) -> Value {
        let line = self.line("portmap");
        assert_eq!(line["state"], state, "{line}");
        line
    }
    /// Wait for the process to end.
    fn exit(&mut self, seconds: u64) -> std::process::ExitStatus {
        let deadline = Instant::now() + Duration::from_secs(seconds);
        loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                return status;
            }
            assert!(Instant::now() < deadline, "node did not exit");
            thread::sleep(Duration::from_millis(10));
        }
    }
}

fn mapped_node(
    relay: &str,
    host: &str,
    listen: u16,
    gateway: &FakeNatGateway,
    ssdp: Option<SocketAddrV4>,
    directory: Option<&Path>,
) -> Node {
    let directory = directory.map_or_else(scratch, Path::to_path_buf);
    let mut command = Command::new(env!("CARGO_BIN_EXE_spry-node"));
    command
        .env_clear()
        .env("SPRY_TURN_SECRET", SECRET)
        .env("SPRY_LOCAL_TEST", "true")
        .args([
            "supervised",
            "--exit-on-stdin-close",
            "--map-ports",
            "--pairing-key",
            host,
        ])
        .arg("--state-file")
        .arg(directory.join("state.json"))
        .args([
            "--control-relay",
            relay,
            "--bind",
            "127.0.0.1",
            "--listen-port",
            &listen.to_string(),
            "--gateway",
            "127.0.0.1",
            "--gateway-port",
            &gateway.address().port().to_string(),
        ]);
    if let Some(ssdp) = ssdp {
        command.args(["--ssdp", &ssdp.to_string()]);
    }
    command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command.spawn().unwrap();
    let stdin = child.stdin.take();
    let stdout = child.stdout.take().unwrap();
    let (send, lines) = mpsc::channel();
    thread::spawn(move || {
        for line in BufReader::new(stdout).lines().map_while(Result::ok) {
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

fn record(node: &Node) -> Vec<spry_portmap::record::Entry> {
    Ledger::load(node.directory.join("state.json.mappings"))
        .unwrap()
        .entries()
        .to_vec()
}

/// A guest admitted to a fresh sealed grant, able to ask for credentials.
struct Guest {
    socket: Socket,
    target: ControlEndpoint,
    identity: Identity,
    token: String,
}
async fn admit(relay: &str, ready: &Value, host: &Identity) -> Guest {
    let identity = Identity::from_secret(&[3; 32]).unwrap();
    let node_key = Identity::derive(SECRET.as_bytes()).unwrap().public_key();
    let target =
        ControlEndpoint::new(node_key, vec![relay.to_owned()], RelayPolicy::LocalFixture).unwrap();
    assert_eq!(ready["endpoint"], target.uri().unwrap());
    let pairing = ready["pairing"].as_str().unwrap().to_owned();
    let mut socket = client(relay).await;
    let (status, granted) = ask(
        &mut socket,
        host,
        &target,
        "/v1/grants",
        json!({"pairing":pairing,"scope":spry_access::hash("synthetic-mapped-room")}),
    )
    .await;
    assert_eq!(status, 200, "{granted}");
    let token = granted["token"].as_str().unwrap().to_owned();
    let (status, registered) = ask(
        &mut socket,
        host,
        &target,
        "/v1/grants/devices",
        json!({"v":1,"pairing":pairing,"grant":token,"add":[host.public_key(), identity.public_key()],"revision":1}),
    )
    .await;
    assert_eq!(status, 200, "{registered}");
    Guest {
        socket,
        target,
        identity,
        token,
    }
}
impl Guest {
    async fn credentials(&mut self) -> Value {
        let (status, issued) = ask(
            &mut self.socket,
            &self.identity,
            &self.target,
            "/v1/credentials",
            json!({"grant":self.token}),
        )
        .await;
        assert_eq!(status, 200, "{issued}");
        issued
    }
}

fn turn_urls(ip: impl std::fmt::Display, udp: u16, tcp: u16) -> Value {
    json!([
        format!("turn:{ip}:{udp}?transport=udp"),
        format!("turn:{ip}:{tcp}?transport=tcp")
    ])
}

/// The keys a `portmap` line may carry, by state.
fn assert_portmap_shape(line: &Value) {
    let mut keys: Vec<_> = line
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    keys.sort_unstable();
    let expected: &[&str] = match line["state"].as_str().unwrap() {
        "mapped" => &[
            "allocationPorts",
            "event",
            "method",
            "permanent",
            "requested",
            "state",
            "v",
        ],
        "changed" => &[
            "allocationPorts",
            "event",
            "method",
            "permanent",
            "reason",
            "requested",
            "state",
            "v",
        ],
        "cleaned" | "released" => &["event", "remaining", "removed", "state", "v"],
        "failed" | "lost" => &["event", "reason", "state", "v"],
        other => panic!("unknown state {other}"),
    };
    assert_eq!(keys, expected, "{line}");
    assert!(line.to_string().len() < 200, "bounded: {line}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_mapped_node_opens_the_router_first_serves_what_it_was_given_and_closes_it_again() {
    let relay = fixture_relay().await;
    let host = Identity::from_secret(&[2; 32]).unwrap();
    let router = FakeNatGateway::start(NatBehaviour::default());
    let starting = STARTING
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let (listen, ..) = ports();
    let mut node = mapped_node(&relay, &host.public_key(), listen, &router, None, None);

    // The router is asked, and the grant reported, before the relay is ready.
    let mapped = node.next();
    drop(starting);
    assert_portmap_shape(&mapped);
    assert_eq!(
        mapped,
        json!({"v":1,"event":"portmap","state":"mapped","method":"pcp",
               "allocationPorts":8,"requested":8,"permanent":false})
    );
    let ready = node.next();
    assert_eq!(ready["event"], "ready");
    assert_eq!(
        ready.as_object().unwrap().len(),
        6,
        "ready keeps its shape: {ready}"
    );
    assert_eq!(ready["urls"], turn_urls(EXTERNAL, listen, listen));
    let map = ready["relayPortMap"].as_array().unwrap().clone();
    assert_eq!(map.len(), 8);
    // The router holds the listener on UDP and TCP and one UDP port per pair.
    let held = router.mappings();
    assert_eq!(held.len(), 10);
    assert!(
        held.iter()
            .any(|m| m.protocol == Protocol::Udp && m.internal_port == listen)
    );
    assert!(
        held.iter()
            .any(|m| m.protocol == Protocol::Tcp && m.internal_port == listen)
    );
    for pair in &map {
        let (local, public) = (pair[0].as_u64().unwrap(), pair[1].as_u64().unwrap());
        assert!((49152..=65535).contains(&local) && local == public);
        assert!(
            held.iter()
                .any(|m| u64::from(m.internal_port) == local && m.protocol == Protocol::Udp)
        );
    }
    // And all of it is in the record, with the nonce that can delete it.
    let recorded = record(&node);
    assert_eq!(recorded.len(), 10);
    assert!(recorded.iter().all(|entry| entry.nonce.is_some()));
    // The state file's directory holds the node's private files only.
    assert!(node.directory.join("state.json").exists());

    // The relay hands out the router's address and a granted port.
    node.line("control");
    let mut guest = admit(&relay, &ready, &host).await;
    let issued = guest.credentials().await;
    assert_eq!(issued["urls"], ready["urls"]);
    let relayed = allocate(listen, &issued).unwrap();
    assert_eq!(relayed.ip().to_string(), EXTERNAL.to_string());
    assert!(
        map.iter()
            .any(|pair| pair[1].as_u64() == Some(u64::from(relayed.port()))),
        "{relayed}"
    );

    // Closing the pipe ends the node, which gives back only what it made.
    drop(node.stdin.take());
    assert!(node.exit(3).success());
    assert!(router.mappings().is_empty(), "the router was cleared");
    assert!(record(&node).is_empty(), "and so was the record");
    UdpSocket::bind(("127.0.0.1", listen)).expect("listener UDP port freed");
    let released = node.portmap("released");
    assert_portmap_shape(&released);
    assert_eq!(released["removed"], 10);
    assert_eq!(released["remaining"], 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_killed_node_leaves_its_mappings_and_the_next_launch_removes_exactly_those() {
    let relay = fixture_relay().await;
    let host = Identity::from_secret(&[2; 32]).unwrap();
    let router = FakeNatGateway::start(NatBehaviour::default());
    let starting = STARTING
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let (listen, ..) = ports();
    let mut first = mapped_node(&relay, &host.public_key(), listen, &router, None, None);
    first.portmap("mapped");
    first.line("ready");
    drop(starting);
    let old = router.mappings();
    assert_eq!(old.len(), 10);
    // A crash: no chance to clean up.
    first.child.kill().unwrap();
    first.child.wait().unwrap();
    assert_eq!(router.mappings(), old, "the router still holds them");
    assert_eq!(record(&first).len(), 10, "and the record remembers them");

    // The router would refuse a new owner for the same listener port, so
    // the next launch can only start by removing the old mappings first.
    let starting = STARTING
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let mut second = mapped_node(
        &relay,
        &host.public_key(),
        listen,
        &router,
        None,
        Some(&first.directory.clone()),
    );
    let cleaned = second.portmap("cleaned");
    assert_portmap_shape(&cleaned);
    assert_eq!(
        (&cleaned["removed"], &cleaned["remaining"]),
        (&json!(10), &json!(0))
    );
    let mapped = second.portmap("mapped");
    assert_eq!(mapped["allocationPorts"], 8);
    second.line("ready");
    drop(starting);
    let now = router.mappings();
    assert_eq!(now.len(), 10);
    assert!(
        now.iter()
            .all(|new| old.iter().all(|o| o.nonce != new.nonce)),
        "only the second run's mappings are left"
    );
    drop(second.stdin.take());
    assert!(second.exit(3).success());
    assert!(router.mappings().is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_permanent_lease_is_used_reported_recorded_and_removed_after_a_crash() {
    let relay = fixture_relay().await;
    let host = Identity::from_secret(&[2; 32]).unwrap();
    // PCP and NAT-PMP decline at once; the UPnP router grants only
    // permanent leases.
    let router = FakeNatGateway::start(NatBehaviour {
        pcp: PcpMode::Refuse(2),
        natpmp: NatPmpMode::Refuse(2),
        ..NatBehaviour::default()
    });
    let upnp = FakeUpnpGateway::start(UpnpBehaviour {
        permanent_only: true,
        ..UpnpBehaviour::default()
    });
    let starting = STARTING
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let (listen, ..) = ports();
    let mut first = mapped_node(
        &relay,
        &host.public_key(),
        listen,
        &router,
        Some(upnp.ssdp()),
        None,
    );
    let mapped = first.portmap("mapped");
    assert_portmap_shape(&mapped);
    assert_eq!(mapped["method"], "upnp");
    assert_eq!(
        mapped["permanent"], true,
        "the supervisor can tell the person a mapping may outlive a crash"
    );
    first.line("ready");
    drop(starting);
    assert!(upnp.mappings().iter().all(|m| m.lease == 0));
    let recorded = record(&first);
    assert_eq!(recorded.len(), 10);
    assert!(recorded.iter().all(|entry| entry.expires.is_none()));

    first.child.kill().unwrap();
    first.child.wait().unwrap();
    assert_eq!(
        upnp.mappings().len(),
        10,
        "a permanent lease outlives the crash"
    );

    let starting = STARTING
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let mut second = mapped_node(
        &relay,
        &host.public_key(),
        listen,
        &router,
        Some(upnp.ssdp()),
        Some(&first.directory.clone()),
    );
    let cleaned = second.portmap("cleaned");
    assert_eq!(
        (&cleaned["removed"], &cleaned["remaining"]),
        (&json!(10), &json!(0))
    );
    second.portmap("mapped");
    second.line("ready");
    drop(starting);
    drop(second.stdin.take());
    assert!(second.exit(3).success());
    assert!(upnp.mappings().is_empty(), "removed on stop as well");
    assert!(record(&second).is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_router_that_refuses_stops_the_node_with_its_own_exit_code_and_nothing_open() {
    let relay = fixture_relay().await;
    let host = Identity::from_secret(&[2; 32]).unwrap();
    let router = FakeNatGateway::start(NatBehaviour {
        pcp: PcpMode::Refuse(2),
        natpmp: NatPmpMode::Refuse(2),
        ..NatBehaviour::default()
    });
    let upnp = FakeUpnpGateway::start(UpnpBehaviour {
        refuse: Some(718),
        ..UpnpBehaviour::default()
    });
    let _starting = STARTING
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let (listen, ..) = ports();
    let mut node = mapped_node(
        &relay,
        &host.public_key(),
        listen,
        &router,
        Some(upnp.ssdp()),
        None,
    );
    let failed = node.portmap("failed");
    assert_portmap_shape(&failed);
    assert_eq!(failed["reason"], "refused");
    let status = node.exit(10);
    assert_eq!(
        status.code(),
        Some(3),
        "not a crash: do not restart blindly"
    );
    // Nothing listened, nothing was written, no ready line was printed.
    assert!(node.lines.recv_timeout(Duration::from_millis(200)).is_err());
    assert!(!node.directory.join("state.json").exists());
    UdpSocket::bind(("127.0.0.1", listen)).expect("the listener was never bound");
    TcpListener::bind(("127.0.0.1", listen)).expect("the listener was never bound");
    assert!(router.mappings().is_empty() && upnp.mappings().is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_change_at_the_router_restarts_the_relay_and_new_credentials_carry_the_new_address() {
    let relay = fixture_relay().await;
    let host = Identity::from_secret(&[2; 32]).unwrap();
    // A four second lease, so renewal (at half) takes two seconds.
    let behaviour = NatBehaviour {
        max_lifetime: 4,
        ..NatBehaviour::default()
    };
    let router = FakeNatGateway::start(behaviour.clone());
    let starting = STARTING
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let (listen, ..) = ports();
    let mut node = mapped_node(&relay, &host.public_key(), listen, &router, None, None);
    node.portmap("mapped");
    let ready = node.line("ready");
    drop(starting);
    node.line("control");
    let mut guest = admit(&relay, &ready, &host).await;
    let before = guest.credentials().await;
    assert_eq!(before["urls"], turn_urls(EXTERNAL, listen, listen));
    assert_eq!(
        allocate(listen, &before).unwrap().ip().to_string(),
        EXTERNAL.to_string()
    );

    // The internet address changes at the next renewal.
    let moved: std::net::Ipv4Addr = "100.128.0.9".parse().unwrap();
    router.set(NatBehaviour {
        external: moved,
        ..behaviour
    });
    let changed = node.portmap("changed");
    assert_portmap_shape(&changed);
    assert_eq!(changed["reason"], "address");
    let urls = node.line("urls");
    assert_eq!(urls["urls"], turn_urls(moved, listen, listen));
    assert_eq!(urls["relayPortMap"].as_array().unwrap().len(), 8);
    assert_eq!(urls.as_object().unwrap().len(), 4, "{urls}");

    // The same pairing and grant keep working, and now say the new address.
    let after = guest.credentials().await;
    assert_eq!(after["urls"], urls["urls"]);
    let relayed = allocate(listen, &after).unwrap();
    assert_eq!(relayed.ip().to_string(), moved.to_string());
    drop(node.stdin.take());
    assert!(node.exit(3).success());
    assert!(router.mappings().is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_router_that_goes_quiet_for_good_ends_the_node_with_the_cannot_host_code() {
    let relay = fixture_relay().await;
    let host = Identity::from_secret(&[2; 32]).unwrap();
    let behaviour = NatBehaviour {
        max_lifetime: 4,
        ..NatBehaviour::default()
    };
    let router = FakeNatGateway::start(behaviour.clone());
    let starting = STARTING
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let (listen, ..) = ports();
    let mut node = mapped_node(&relay, &host.public_key(), listen, &router, None, None);
    node.portmap("mapped");
    node.line("ready");
    drop(starting);
    router.set(NatBehaviour {
        pcp: PcpMode::Silent,
        natpmp: NatPmpMode::Silent,
        ..behaviour
    });
    let lost = node.portmap("lost");
    assert_portmap_shape(&lost);
    assert_eq!(lost["reason"], "expired");
    assert_eq!(node.exit(20).code(), Some(3));
    // It could not remove them from a silent router, and says so.
    let released = node.portmap("released");
    assert_eq!(released["removed"], 0);
    assert_eq!(released["remaining"], 10);
    assert_eq!(record(&node).len(), 10, "left for the next launch");
}

#[test]
fn map_ports_refuses_explicit_public_values_and_names_the_setting() {
    let output = Command::new(env!("CARGO_BIN_EXE_spry-node"))
        .env_clear()
        .env("SPRY_TURN_SECRET", SECRET)
        .env("SPRY_LOCAL_TEST", "true")
        .args([
            "supervised",
            "--exit-on-stdin-close",
            "--map-ports",
            "--public-ip",
            "203.0.113.7",
            "--pairing-key",
            &Identity::from_secret(&[2; 32]).unwrap().public_key(),
            "--state-file",
            "unused.json",
            "--control-relay",
            "ws://127.0.0.1:1/",
            "--bind",
            "127.0.0.1",
            "--listen-port",
            "41000",
        ])
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    let message = String::from_utf8(output.stderr).unwrap();
    assert!(
        message.contains("--map-ports takes the public address and ports"),
        "{message}"
    );
    assert!(!message.contains("203.0.113.7"));
}
