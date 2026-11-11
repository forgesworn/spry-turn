#![cfg(all(feature = "runtime", feature = "turn"))]

use std::{
    io::{BufRead, BufReader, Write},
    process::{Child, Command, ExitStatus, Stdio},
    sync::mpsc,
    thread,
    time::{Duration, Instant},
};

struct Relay(Child);
impl Drop for Relay {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn command() -> Command {
    let mut secret = [0; 32];
    getrandom::fill(&mut secret).unwrap();
    let secret: String = secret.iter().map(|byte| format!("{byte:02x}")).collect();
    let mut command = Command::new(env!("CARGO_BIN_EXE_spry-turn"));
    command
        .env_clear()
        .env("SPRY_TURN_SECRET", secret)
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    command
}

fn listener_address() -> std::net::SocketAddr {
    for _ in 0..16 {
        // UDP :0 may select a port already occupied in the independent TCP
        // namespace, including TIME_WAIT. Preflight both while holding guards;
        // release them only when returning the address for the child to bind.
        let tcp = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = tcp.local_addr().unwrap();
        match std::net::UdpSocket::bind(address) {
            Ok(_udp) => return address,
            Err(error) if error.kind() == std::io::ErrorKind::AddrInUse => continue,
            Err(error) => panic!("fixture UDP bind failed: {error}"),
        }
    }
    panic!("could not find a joint UDP/TCP fixture address within 16 attempts");
}

fn start(watch: bool, piped: bool) -> Relay {
    let mut command = command();
    command.args(["serve", "--listen", &listener_address().to_string()]);
    if watch {
        command.arg("--exit-on-stdin-close");
    }
    command.stdin(if piped { Stdio::piped() } else { Stdio::null() });
    let mut relay = Relay(command.spawn().unwrap());
    if let Err(error) = readiness(&mut relay) {
        panic!("relay startup failed: {error}");
    }
    relay
}

fn readiness(relay: &mut Relay) -> Result<(), String> {
    let stderr = relay.0.stderr.take().unwrap();
    let (send, receive) = mpsc::channel();
    thread::spawn(move || {
        let mut transcript = std::collections::VecDeque::new();
        for line in BufReader::new(stderr).lines() {
            let line = match line {
                Ok(line) => line,
                Err(error) => {
                    let _ = send.send(Err(format!("stderr read failed: {error}")));
                    return;
                }
            };
            if line.starts_with("spry-turn ") && line.contains(" ready (UDP/TCP 127.0.0.1:") {
                let _ = send.send(Ok(()));
                return;
            }
            if transcript.len() == 16 {
                transcript.pop_front();
            }
            transcript.push_back(line.chars().take(1024).collect::<String>());
        }
        let _ = send.send(Err(format!(
            "stderr ended before readiness: {}",
            transcript.into_iter().collect::<Vec<_>>().join(" | ")
        )));
    });
    receive
        .recv_timeout(Duration::from_secs(5))
        .map_err(|error| {
            format!(
                "readiness observation failed: {error}; child exit status: {:?}",
                relay.0.try_wait()
            )
        })?
        .map_err(|error| format!("{error}; child exit status: {:?}", relay.0.try_wait()))
}

fn wait_for_exit(relay: &mut Relay) -> ExitStatus {
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        if let Some(status) = relay.0.try_wait().unwrap() {
            return status;
        }
        assert!(
            Instant::now() < deadline,
            "relay did not exit after stdin EOF"
        );
        thread::sleep(Duration::from_millis(10));
    }
}

#[test]
fn closed_stdin_does_not_change_default_serve_lifetime() {
    for piped in [false, true] {
        let mut relay = start(false, piped);
        drop(relay.0.stdin.take());
        thread::sleep(Duration::from_millis(150));
        assert!(relay.0.try_wait().unwrap().is_none());
    }
}

#[cfg(unix)]
#[test]
fn readiness_reports_startup_bind_failure_instead_of_disconnected_channel() {
    // A bound TCP listener deliberately prevents the relay from sharing its
    // UDP-selected port. This tests diagnostic reporting, not a hypothesised
    // cause of an earlier unexplained startup failure.
    let occupied = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = occupied.local_addr().unwrap().to_string();
    let mut relay = Relay(
        command()
            .args(["serve", "--listen", &address])
            .stdin(Stdio::null())
            .spawn()
            .unwrap(),
    );
    let error = readiness(&mut relay).unwrap_err();
    assert!(error.contains("stderr ended before readiness"), "{error}");
    assert!(error.contains("Address already in use"), "{error}");
    assert!(error.contains("child exit status:"), "{error}");
    assert!(!wait_for_exit(&mut relay).success());
}

#[test]
fn watched_stdin_accepts_bytes_then_exits_on_eof() {
    let mut relay = start(true, true);
    relay
        .0
        .stdin
        .as_mut()
        .unwrap()
        .write_all(b"still supervised\n")
        .unwrap();
    thread::sleep(Duration::from_millis(150));
    assert!(relay.0.try_wait().unwrap().is_none());
    drop(relay.0.stdin.take());
    assert!(wait_for_exit(&mut relay).success());
}

#[test]
fn watched_stdin_already_at_eof_exits_without_waiting_for_readiness() {
    let mut relay = Relay(
        command()
            .args([
                "serve",
                "--listen",
                &listener_address().to_string(),
                "--exit-on-stdin-close",
            ])
            .stdin(Stdio::null())
            .spawn()
            .unwrap(),
    );
    assert!(wait_for_exit(&mut relay).success());
}

#[cfg(unix)]
#[test]
fn watched_stdin_read_error_exits_unsuccessfully() {
    // Reading a directory fails rather than reporting ordinary pipe EOF.
    let directory = std::fs::File::open(std::env::temp_dir()).unwrap();
    let mut relay = Relay(
        command()
            .args([
                "serve",
                "--listen",
                &listener_address().to_string(),
                "--exit-on-stdin-close",
            ])
            .stdin(Stdio::from(directory))
            .spawn()
            .unwrap(),
    );
    assert_eq!(wait_for_exit(&mut relay).code(), Some(1));
}

#[test]
fn invalid_or_credential_lifetime_flags_are_refused() {
    for args in [
        vec!["credential", "--exit-on-stdin-close"],
        vec!["serve", "--exit-on-stdin-close=true"],
        vec!["serve", "--exit-on-stdin-close", "--exit-on-stdin-close"],
    ] {
        let output = command().args(args).stdin(Stdio::null()).output().unwrap();
        assert!(!output.status.success());
    }
}
