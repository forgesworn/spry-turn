//! The C ABI driven from Rust through its exported functions, as a C host
//! would call them: real nodes in this process, a generated loopback Nostr
//! relay for control and the in-house fake router for port mapping. Local
//! evidence only; no router, NAT or remote network is involved.
#![allow(unsafe_code, clippy::undocumented_unsafe_blocks)]

use futures_util::{SinkExt, StreamExt};
use serde_json::{Value, json};
use spry_portmap::{
    Protocol,
    fake::{FakeNatGateway, NatBehaviour},
};
use spry_relay::*;
use std::{
    ffi::{CString, c_char},
    net::{TcpListener, UdpSocket},
    path::PathBuf,
    ptr,
    sync::{
        atomic::{AtomicU32, Ordering},
        mpsc,
    },
    thread,
    time::{Duration, Instant},
};
use tokio::sync::broadcast;
use tokio_tungstenite::{accept_async, tungstenite::Message};

const SECRET: &str = "synthetic-supervised-secret-not-for-deployment";
const HOST_KEY: &str = "1b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f";
const PUBLIC_IP: &str = "203.0.113.7";

/// A loopback Nostr relay on its own thread for the whole test binary: it
/// answers every subscription with EOSE and passes every event on.
fn fixture_relay() -> String {
    let (sent, url) = mpsc::channel();
    thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async move {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            sent.send(format!("ws://{}/", listener.local_addr().unwrap()))
                .unwrap();
            let (events, _) = broadcast::channel::<Value>(256);
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
    });
    url.recv().unwrap()
}

/// A loopback listener port and two allocation ports, free on UDP and TCP.
/// Each call takes a different slot, so tests running at the same time in
/// this process never probe the same ports and then race to bind them. The
/// range stays below 49152, where a mapped node picks its own ports.
fn ports() -> (u16, u16, u16) {
    static NEXT: AtomicU32 = AtomicU32::new(0);
    let start = std::process::id() % 3_000;
    for _ in 0..256 {
        let slot = (start + NEXT.fetch_add(1, Ordering::Relaxed)) % 3_000;
        let base = 20_000 + (slot as u16) * 8;
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

fn scratch(name: &str) -> PathBuf {
    let directory = std::env::temp_dir().join(format!(
        "spry-ffi-{name}-{}-{:?}",
        std::process::id(),
        thread::current().id()
    ));
    let _ = std::fs::remove_dir_all(&directory);
    std::fs::create_dir_all(&directory).unwrap();
    directory
}

/// A started handle, freed on drop if a test did not free it itself.
struct Relay(*mut SpryRelay);
impl Drop for Relay {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe { spry_relay_free(self.0) };
        }
    }
}
impl Relay {
    fn start(args: &[&str], settings: &[&str]) -> Self {
        let args: Vec<CString> = args.iter().map(|arg| CString::new(*arg).unwrap()).collect();
        let settings: Vec<CString> = settings
            .iter()
            .map(|setting| CString::new(*setting).unwrap())
            .collect();
        let argv: Vec<*const c_char> = args.iter().map(|arg| arg.as_ptr()).collect();
        let envp: Vec<*const c_char> = settings.iter().map(|setting| setting.as_ptr()).collect();
        let mut relay = ptr::null_mut();
        let code = unsafe {
            spry_relay_start(
                argv.as_ptr(),
                argv.len(),
                envp.as_ptr(),
                envp.len(),
                &mut relay,
            )
        };
        assert_eq!(code, SPRY_RELAY_OK);
        assert!(!relay.is_null());
        // The strings are the caller's to drop as soon as the call returns.
        drop((args, settings, argv, envp));
        Self(relay)
    }
    /// The next line, or `None` once the node has ended and been read out.
    fn next(&self) -> Option<Value> {
        let deadline = Instant::now() + Duration::from_secs(15);
        let mut buffer = vec![0_u8; SPRY_RELAY_LINE_BUFFER];
        loop {
            let mut length = usize::MAX;
            let code = unsafe {
                spry_relay_next_line(self.0, 200, buffer.as_mut_ptr(), buffer.len(), &mut length)
            };
            match code {
                SPRY_RELAY_OK => {
                    let text = std::str::from_utf8(&buffer[..length]).expect("UTF-8 line");
                    assert!(!text.contains('\n'), "one line: {text}");
                    return Some(serde_json::from_str(text).expect("a JSON line"));
                }
                SPRY_RELAY_ENDED => {
                    assert_eq!(length, 0);
                    return None;
                }
                SPRY_RELAY_NO_LINE => {
                    assert_eq!(length, 0);
                    assert!(Instant::now() < deadline, "no line in time");
                }
                other => panic!("next_line returned {other}"),
            }
        }
    }
    /// Lines up to and including the first `event` line.
    fn until(&self, event: &str) -> Vec<Value> {
        let mut seen = Vec::new();
        loop {
            let line = self
                .next()
                .unwrap_or_else(|| panic!("ended before {event}: {seen:?}"));
            let found = line["event"] == event;
            seen.push(line);
            if found {
                return seen;
            }
        }
    }
    fn stop(&self) {
        assert_eq!(unsafe { spry_relay_stop(self.0) }, SPRY_RELAY_OK);
    }
    fn exit_code(&self) -> i32 {
        unsafe { spry_relay_exit_code(self.0) }
    }
    fn free(mut self) -> i32 {
        let relay = std::mem::replace(&mut self.0, ptr::null_mut());
        unsafe { spry_relay_free(relay) }
    }
}

fn secret() -> String {
    format!("SPRY_TURN_SECRET={SECRET}")
}

fn explicit_args<'a>(
    relay: &'a str,
    state: &'a str,
    listen: &'a str,
    first: &'a str,
    second: &'a str,
) -> Vec<&'a str> {
    vec![
        "--pairing-key",
        HOST_KEY,
        "--state-file",
        state,
        "--control-relay",
        relay,
        "--bind",
        "127.0.0.1",
        "--public-ip",
        PUBLIC_IP,
        "--listen-port",
        listen,
        "--public-udp-port",
        "51000",
        "--public-tcp-port",
        "51001",
        "--relay-port-map",
        first,
        "--relay-port-map",
        second,
    ]
}

#[test]
fn the_header_states_the_same_values_as_the_library() {
    let header = include_str!("../include/spry_relay.h");
    let define = |name: &str| -> i64 {
        let prefix = format!("#define {name} ");
        let line = header
            .lines()
            .find(|line| line.starts_with(&prefix))
            .unwrap_or_else(|| panic!("{name} is not defined"));
        line[prefix.len()..]
            .split_whitespace()
            .next()
            .unwrap()
            .parse()
            .unwrap()
    };
    let expected: [(&str, i64); 16] = [
        ("SPRY_RELAY_ABI_VERSION", SPRY_RELAY_ABI_VERSION.into()),
        ("SPRY_RELAY_OK", SPRY_RELAY_OK.into()),
        ("SPRY_RELAY_NO_LINE", SPRY_RELAY_NO_LINE.into()),
        ("SPRY_RELAY_ENDED", SPRY_RELAY_ENDED.into()),
        ("SPRY_RELAY_ERR_ARGUMENT", SPRY_RELAY_ERR_ARGUMENT.into()),
        ("SPRY_RELAY_ERR_BUFFER", SPRY_RELAY_ERR_BUFFER.into()),
        ("SPRY_RELAY_ERR_START", SPRY_RELAY_ERR_START.into()),
        ("SPRY_RELAY_ERR_PANIC", SPRY_RELAY_ERR_PANIC.into()),
        ("SPRY_RELAY_ERR_DETACHED", SPRY_RELAY_ERR_DETACHED.into()),
        ("SPRY_RELAY_RUNNING", SPRY_RELAY_RUNNING.into()),
        ("SPRY_RELAY_MAX_ARGS", SPRY_RELAY_MAX_ARGS as i64),
        ("SPRY_RELAY_MAX_SETTINGS", SPRY_RELAY_MAX_SETTINGS as i64),
        ("SPRY_RELAY_MAX_TEXT", SPRY_RELAY_MAX_TEXT as i64),
        ("SPRY_RELAY_MAX_QUEUED", SPRY_RELAY_MAX_QUEUED as i64),
        ("SPRY_RELAY_LINE_BUFFER", SPRY_RELAY_LINE_BUFFER as i64),
        ("SPRY_RELAY_ABI_VERSION", spry_relay_abi_version().into()),
    ];
    for (name, value) in expected {
        assert_eq!(define(name), value, "{name}");
    }
    for function in [
        "spry_relay_abi_version",
        "spry_relay_start",
        "spry_relay_next_line",
        "spry_relay_stop",
        "spry_relay_exit_code",
        "spry_relay_free",
    ] {
        assert!(header.contains(&format!(" {function}(")), "{function}");
    }
}

#[cfg(feature = "panic-probe")]
#[test]
fn a_panic_inside_the_library_becomes_an_error_code() {
    assert_eq!(spry_relay_panic_probe(), SPRY_RELAY_ERR_PANIC);
    // And the library still works afterwards.
    assert_eq!(spry_relay_abi_version(), SPRY_RELAY_ABI_VERSION);
}

#[test]
fn malformed_calls_are_refused_and_nothing_is_started() {
    let arg = CString::new("--map-ports").unwrap();
    let setting = CString::new("SPRY_TURN_SECRET").unwrap();
    let argv = [arg.as_ptr()];
    let null: [*const c_char; 1] = [ptr::null()];
    let start = |argv: *const *const c_char, argc, envp: *const *const c_char, envc, out| unsafe {
        spry_relay_start(argv, argc, envp, envc, out)
    };
    assert_eq!(
        start(argv.as_ptr(), 1, ptr::null(), 0, ptr::null_mut()),
        SPRY_RELAY_ERR_ARGUMENT
    );
    for (argv, argc, envp, envc) in [
        (ptr::null(), 1, ptr::null(), 0),
        (null.as_ptr(), 1, ptr::null(), 0),
        (argv.as_ptr(), 1, null.as_ptr(), 1),
        // A setting without `=`.
        (argv.as_ptr(), 1, [setting.as_ptr()].as_ptr(), 1),
        (argv.as_ptr(), SPRY_RELAY_MAX_ARGS + 1, ptr::null(), 0),
        (argv.as_ptr(), 1, ptr::null(), SPRY_RELAY_MAX_SETTINGS + 1),
    ] {
        let mut relay = ptr::dangling_mut::<SpryRelay>();
        assert_eq!(
            start(argv, argc, envp, envc, &mut relay),
            SPRY_RELAY_ERR_ARGUMENT
        );
        assert!(relay.is_null(), "the handle is cleared on refusal");
    }
    let mut relay = ptr::null_mut();
    let long = CString::new("x".repeat(SPRY_RELAY_MAX_TEXT + 1)).unwrap();
    assert_eq!(
        start([long.as_ptr()].as_ptr(), 1, ptr::null(), 0, &mut relay),
        SPRY_RELAY_ERR_ARGUMENT
    );
    let not_utf8 = CString::new(vec![0xff_u8, 0xfe]).unwrap();
    assert_eq!(
        start([not_utf8.as_ptr()].as_ptr(), 1, ptr::null(), 0, &mut relay),
        SPRY_RELAY_ERR_ARGUMENT
    );
    let mut length = 7;
    let mut byte = 0_u8;
    unsafe {
        assert_eq!(
            spry_relay_next_line(ptr::null(), 0, &mut byte, 1, &mut length),
            SPRY_RELAY_ERR_ARGUMENT
        );
        assert_eq!(spry_relay_stop(ptr::null()), SPRY_RELAY_ERR_ARGUMENT);
        assert_eq!(spry_relay_exit_code(ptr::null()), SPRY_RELAY_ERR_ARGUMENT);
        assert_eq!(spry_relay_free(ptr::null_mut()), SPRY_RELAY_OK);
    }
}

#[test]
fn a_refused_setting_ends_the_node_with_a_stopped_line_that_names_it() {
    // No secret: the child process would print this refusal and exit 1.
    let relay = Relay::start(&["--map-ports"], &[]);
    assert_eq!(
        relay.next().unwrap(),
        json!({"v":1,"event":"stopped","code":1,
               "refusal":"SPRY_TURN_SECRET must contain at least 32 bytes"})
    );
    assert_eq!(relay.next(), None);
    assert_eq!(relay.exit_code(), 1);
    // Reading after the end keeps saying so, and stop is harmless.
    assert_eq!(relay.next(), None);
    relay.stop();
    assert_eq!(relay.free(), SPRY_RELAY_OK);

    // The stdin guard has no meaning inside the host's process.
    let secret = secret();
    let relay = Relay::start(&["--exit-on-stdin-close"], &[&secret]);
    let stopped = relay.next().unwrap();
    assert_eq!(stopped["code"], 1);
    assert!(
        stopped["refusal"]
            .as_str()
            .unwrap()
            .starts_with("--exit-on-stdin-close does not apply")
    );
    // So does a setting the host's process happens to carry.
    let relay = Relay::start(&["--map-ports"], &[&secret, "HOME=/"]);
    assert_eq!(relay.next().unwrap()["code"], 1);
    assert_eq!(relay.next(), None);
}

#[test]
fn a_node_started_through_the_c_abi_reports_relays_and_stops_on_request() {
    let control = fixture_relay();
    let directory = scratch("explicit");
    let state = directory.join("state.json");
    let state = state.to_str().unwrap();
    let (listen, first, second) = ports();
    let (listen_text, first_map, second_map) = (
        listen.to_string(),
        format!("{first}:51002"),
        format!("{second}:51003"),
    );
    let secret = secret();
    let relay = Relay::start(
        &explicit_args(&control, state, &listen_text, &first_map, &second_map),
        &[&secret, "SPRY_LOCAL_TEST=true"],
    );

    // A buffer too small keeps the line and says how much it needs.
    let deadline = Instant::now() + Duration::from_secs(15);
    let needed = loop {
        let mut length = 0;
        let mut byte = 0_u8;
        let code = unsafe { spry_relay_next_line(relay.0, 200, &mut byte, 1, &mut length) };
        if code == SPRY_RELAY_ERR_BUFFER {
            break length;
        }
        assert_eq!(code, SPRY_RELAY_NO_LINE);
        assert!(Instant::now() < deadline, "no ready line");
    };
    let mut length = 0;
    assert_eq!(
        unsafe { spry_relay_next_line(relay.0, 0, ptr::null_mut(), 0, &mut length) },
        SPRY_RELAY_ERR_BUFFER
    );
    assert_eq!(length, needed);
    let ready = relay.next().unwrap();
    assert_eq!(ready["event"], "ready", "{ready}");
    assert_eq!(serde_json::to_vec(&ready).unwrap().len(), needed);
    assert!(ready["endpoint"].as_str().unwrap().starts_with("spry://"));
    assert_eq!(ready["pairing"].as_str().unwrap().len(), 43);
    assert_eq!(
        ready["urls"],
        json!([
            format!("turn:{PUBLIC_IP}:51000?transport=udp"),
            format!("turn:{PUBLIC_IP}:51001?transport=tcp")
        ])
    );
    assert_eq!(
        ready["relayPortMap"],
        json!([[first, 51002], [second, 51003]])
    );
    assert_eq!(
        relay.next().unwrap(),
        json!({"v":1,"event":"status","allocations":0,"bytesRelayed":0,"lastAllocation":null})
    );
    assert_eq!(
        relay.until("control").last().unwrap(),
        &json!({"v":1,"event":"control","relays":1})
    );
    assert_eq!(relay.exit_code(), SPRY_RELAY_RUNNING);
    // The relay holds its listener in this process.
    assert!(UdpSocket::bind(("127.0.0.1", listen)).is_err());
    assert!(TcpListener::bind(("127.0.0.1", listen)).is_err());

    // Stop returns at once; the node ends on its own and says how.
    let asked = Instant::now();
    relay.stop();
    relay.stop();
    let rest = relay.until("stopped");
    assert_eq!(
        rest.last().unwrap(),
        &json!({"v":1,"event":"stopped","code":0})
    );
    assert_eq!(relay.next(), None);
    assert!(
        asked.elapsed() < Duration::from_secs(3),
        "{:?}",
        asked.elapsed()
    );
    assert_eq!(relay.exit_code(), 0);
    UdpSocket::bind(("127.0.0.1", listen)).expect("listener UDP port freed");
    TcpListener::bind(("127.0.0.1", listen)).expect("listener TCP port freed");
    UdpSocket::bind(("127.0.0.1", first)).expect("allocation port freed");
    assert_eq!(relay.free(), SPRY_RELAY_OK);
    let _ = std::fs::remove_dir_all(directory);
}

#[test]
fn stopping_a_mapped_node_removes_the_router_mappings_it_made() {
    let control = fixture_relay();
    let router = FakeNatGateway::start(NatBehaviour::default());
    let directory = scratch("mapped");
    let state = directory.join("state.json");
    let (listen, ..) = ports();
    let listen_text = listen.to_string();
    let gateway_port = router.address().port().to_string();
    let secret = secret();
    let relay = Relay::start(
        &[
            "--map-ports",
            "--pairing-key",
            HOST_KEY,
            "--state-file",
            state.to_str().unwrap(),
            "--control-relay",
            &control,
            "--bind",
            "127.0.0.1",
            "--listen-port",
            &listen_text,
            "--gateway",
            "127.0.0.1",
            "--gateway-port",
            &gateway_port,
        ],
        &[&secret, "SPRY_LOCAL_TEST=true"],
    );
    assert_eq!(
        relay.next().unwrap(),
        json!({"v":1,"event":"portmap","state":"mapped","method":"pcp",
               "allocationPorts":8,"requested":8,"permanent":false})
    );
    let ready = relay.next().unwrap();
    assert_eq!(ready["event"], "ready", "{ready}");
    assert_eq!(ready["relayPortMap"].as_array().unwrap().len(), 8);
    let held = router.mappings();
    assert_eq!(held.len(), 10, "listener on UDP and TCP and eight ports");
    assert!(
        held.iter()
            .any(|m| m.protocol == Protocol::Tcp && m.internal_port == listen)
    );

    relay.stop();
    let rest = relay.until("stopped");
    let released = rest
        .iter()
        .find(|line| line["event"] == "portmap")
        .expect("a released line before stopped");
    assert_eq!(
        released,
        &json!({"v":1,"event":"portmap","state":"released","removed":10,"remaining":0})
    );
    assert_eq!(rest.last().unwrap()["code"], 0);
    assert!(router.mappings().is_empty(), "the router was cleared");
    UdpSocket::bind(("127.0.0.1", listen)).expect("listener UDP port freed");
    assert_eq!(relay.free(), SPRY_RELAY_OK);
    let _ = std::fs::remove_dir_all(directory);
}

#[test]
fn freeing_a_running_node_stops_it_first() {
    let control = fixture_relay();
    let directory = scratch("free");
    let state = directory.join("state.json");
    let state = state.to_str().unwrap();
    let (listen, first, second) = ports();
    let (listen_text, first_map, second_map) = (
        listen.to_string(),
        format!("{first}:51002"),
        format!("{second}:51003"),
    );
    let secret = secret();
    let relay = Relay::start(
        &explicit_args(&control, state, &listen_text, &first_map, &second_map),
        &[&secret, "SPRY_LOCAL_TEST=true"],
    );
    relay.until("ready");
    let freeing = Instant::now();
    assert_eq!(relay.free(), SPRY_RELAY_OK);
    assert!(freeing.elapsed() < Duration::from_secs(3));
    UdpSocket::bind(("127.0.0.1", listen)).expect("listener UDP port freed");
    let _ = std::fs::remove_dir_all(directory);
}
