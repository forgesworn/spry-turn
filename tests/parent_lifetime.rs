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

fn start(watch: bool, piped: bool) -> Relay {
    let mut command = command();
    command.args(["serve", "--listen", "127.0.0.1:0"]);
    if watch {
        command.arg("--exit-on-stdin-close");
    }
    command.stdin(if piped { Stdio::piped() } else { Stdio::null() });
    let mut relay = Relay(command.spawn().unwrap());
    let stderr = relay.0.stderr.take().unwrap();
    let (send, receive) = mpsc::channel();
    thread::spawn(move || {
        for line in BufReader::new(stderr).lines().map_while(Result::ok) {
            if line.starts_with("spry-turn ") && line.contains(" ready (UDP/TCP 127.0.0.1:") {
                let _ = send.send(());
                break;
            }
        }
    });
    receive.recv_timeout(Duration::from_secs(5)).unwrap();
    relay
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
            .args(["serve", "--listen", "127.0.0.1:0", "--exit-on-stdin-close"])
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
            .args(["serve", "--listen", "127.0.0.1:0", "--exit-on-stdin-close"])
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
