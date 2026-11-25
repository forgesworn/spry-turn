//! A fixed-rate STUN control-request probe for bare-metal qualification.
//!
//! It sends Binding requests on an absolute schedule, rotating across many
//! UDP source addresses. In `bare` mode the requests carry no nonce; in
//! `nonce` mode each carries the nonce the relay issued to that source, so a
//! relay with per-source request budgets must check it. Both modes first ask
//! each source for one challenge, so setup work is identical.
//!
//! The probe only talks to loopback or the 198.18.0.0/15 benchmarking range
//! (RFC 2544). Sources outside loopback need those addresses to be local, for
//! example `ip route add local 198.18.0.0/16 dev lo` on Linux.
use mio::{Events, Interest, Poll, Token, net::UdpSocket as MioUdpSocket};
use spry_turn::wire::*;
use std::{
    env, io,
    net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4, UdpSocket},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

#[derive(Clone, Copy, PartialEq)]
enum Mode {
    Bare,
    Nonce,
}

fn benchmark_address(ip: Ipv4Addr) -> bool {
    ip.is_loopback() || u32::from(ip) & 0xfffe_0000 == u32::from(Ipv4Addr::new(198, 18, 0, 0))
}

fn transaction(kind: u8, index: u64) -> [u8; 12] {
    let mut transaction = [kind; 12];
    transaction[4..].copy_from_slice(&index.to_be_bytes());
    transaction
}

/// The request a datagram answers, from its transaction ID.
fn answers(bytes: &[u8]) -> Option<usize> {
    let m = Message::parse(bytes)?;
    if m.class != 2 || m.method != BINDING || m.transaction[..4] != [2; 4] {
        return None;
    }
    let k = u64::from_be_bytes(m.transaction[4..].try_into().ok()?);
    usize::try_from(k).ok()
}

/// Answer times in nanoseconds after `start`, zero while unanswered.
struct Received {
    at: Vec<u64>,
    unexpected: u64,
}

/// Reads every socket as soon as it is readable, so the sender never waits
/// for an answer and a slow answer cannot delay the next request.
fn receive(
    mut poll: Poll,
    sockets: &[MioUdpSocket],
    requests: usize,
    start: Instant,
    sent_all: &AtomicBool,
) -> io::Result<Received> {
    let mut events = Events::with_capacity(1024);
    let mut buffer = vec![0; 2048];
    let mut received = Received {
        at: vec![0; requests],
        unexpected: 0,
    };
    let mut count = 0;
    let mut quiet = None;
    while count < requests {
        poll.poll(&mut events, Some(Duration::from_millis(10)))?;
        let mut read = false;
        for event in &events {
            let index = event.token().0;
            loop {
                match sockets[index].recv(&mut buffer) {
                    Ok(n) => {
                        read = true;
                        let at = (start.elapsed().as_nanos() as u64).max(1);
                        match answers(&buffer[..n]).filter(|&k| {
                            k < requests && k % sockets.len() == index && received.at[k] == 0
                        }) {
                            Some(k) => {
                                received.at[k] = at;
                                count += 1;
                            }
                            None => received.unexpected += 1,
                        }
                    }
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                    Err(error) => return Err(error),
                }
            }
        }
        // After the last request, stop once nothing has arrived for 200 ms.
        if sent_all.load(Ordering::Acquire) {
            if read {
                quiet = None;
            } else if quiet.get_or_insert_with(Instant::now).elapsed() >= Duration::from_millis(200)
            {
                break;
            }
        }
    }
    Ok(received)
}

fn challenge(socket: &UdpSocket, index: u64, buffer: &mut [u8]) -> io::Result<Vec<u8>> {
    let id = transaction(1, index);
    let mut b = Builder::new(ALLOCATE, 0, id);
    b.attr(TRANSPORT, &[17, 0, 0, 0]);
    socket.send(&b.finish(None))?;
    loop {
        let n = socket.recv(buffer)?;
        let Some(m) = Message::parse(&buffer[..n]) else {
            continue;
        };
        if m.transaction != id {
            continue;
        }
        if m.class != 3 {
            return Err(io::Error::other("setup request was not challenged"));
        }
        return m
            .attr(NONCE)
            .map(<[u8]>::to_vec)
            .ok_or_else(|| io::Error::other("challenge without a nonce"));
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().skip(1).collect();
    let server: SocketAddr = args.first().ok_or("server address required")?.parse()?;
    let mut mode = None;
    let mut first = None;
    let mut sources = 0_usize;
    let mut requests = 0_usize;
    let mut rate = 0_u64;
    for option in args.get(1..).unwrap_or_default().chunks(2) {
        let value = option.get(1).ok_or("probe option requires a value")?;
        match option[0].as_str() {
            "--mode" => {
                mode = Some(match value.as_str() {
                    "bare" => Mode::Bare,
                    "nonce" => Mode::Nonce,
                    _ => return Err("mode must be bare or nonce".into()),
                })
            }
            "--first-source" => first = Some(value.parse::<Ipv4Addr>()?),
            "--sources" => sources = value.parse()?,
            "--requests" => requests = value.parse()?,
            "--rate" => rate = value.parse()?,
            _ => return Err("unknown probe option".into()),
        }
    }
    let mode = mode.ok_or("--mode required")?;
    let first = first.ok_or("--first-source required")?;
    let IpAddr::V4(server_ip) = server.ip() else {
        return Err("probe is restricted to IPv4".into());
    };
    if !(1..=4096).contains(&sources)
        || !(1..=1_000_000).contains(&requests)
        || !(1..=10_000).contains(&rate)
    {
        return Err("invalid probe bounds".into());
    }
    let last = u32::from(first)
        .checked_add(sources as u32 - 1)
        .map(Ipv4Addr::from)
        .ok_or("source range overflows")?;
    if !benchmark_address(server_ip) || !benchmark_address(first) || !benchmark_address(last) {
        return Err("probe is restricted to loopback and 198.18.0.0/15".into());
    }
    let mut buffer = vec![0; 2048];
    let setup = Instant::now();
    let mut sockets = Vec::with_capacity(sources);
    let mut nonces = Vec::with_capacity(sources);
    for i in 0..sources {
        let ip = Ipv4Addr::from(u32::from(first) + i as u32);
        let socket = UdpSocket::bind(SocketAddrV4::new(ip, 0))?;
        socket.connect(server)?;
        socket.set_read_timeout(Some(Duration::from_secs(3)))?;
        nonces.push(challenge(&socket, i as u64, &mut buffer)?);
        sockets.push(socket);
    }
    let setup_ms = setup.elapsed().as_secs_f64() * 1000.0;
    let poll = Poll::new()?;
    let mut probe_sockets = Vec::with_capacity(sources);
    for (i, socket) in sockets.into_iter().enumerate() {
        socket.set_nonblocking(true)?;
        let mut socket = MioUdpSocket::from_std(socket);
        poll.registry()
            .register(&mut socket, Token(i), Interest::READABLE)?;
        probe_sockets.push(socket);
    }
    let sockets = Arc::new(probe_sockets);
    let sent_all = Arc::new(AtomicBool::new(false));
    let interval = Duration::from_secs_f64(1.0 / rate as f64);
    // A short lead lets the receiver start polling before the first request.
    let start = Instant::now() + Duration::from_millis(20);
    let receiver = {
        let sockets = Arc::clone(&sockets);
        let sent_all = Arc::clone(&sent_all);
        std::thread::spawn(move || receive(poll, &sockets, requests, start, &sent_all))
    };
    let mut sent_at = Vec::with_capacity(requests);
    let mut missed_slots = 0_u64;
    let mut lateness = Vec::with_capacity(requests);
    for k in 0..requests {
        // Absolute schedule, never reset after a slow or missing response.
        let due = start + Duration::from_secs_f64(k as f64 / rate as f64);
        // Spin rather than sleep: a sleep can overshoot by a timer tick, which
        // at 1,000 a second is a whole slot.
        while Instant::now() < due {
            std::hint::spin_loop();
        }
        let sent = Instant::now();
        let late = sent.saturating_duration_since(due);
        lateness.push(late.as_nanos() as u64);
        if late >= interval {
            missed_slots += 1;
        }
        let index = k % sources;
        let mut b = Builder::new(BINDING, 0, transaction(2, k as u64));
        if mode == Mode::Nonce {
            b.attr(NONCE, &nonces[index]);
        }
        sockets[index].send(&b.finish(None))?;
        sent_at.push(sent.duration_since(start).as_nanos() as u64);
    }
    let elapsed = start.elapsed().as_secs_f64();
    sent_all.store(true, Ordering::Release);
    let received = receiver
        .join()
        .map_err(|_| io::Error::other("probe receiver panicked"))??;
    let mut answered = 0_u64;
    let mut late_answers = 0_u64;
    let mut round_trips = Vec::with_capacity(requests);
    for (k, (&at, &sent)) in received.at.iter().zip(&sent_at).enumerate() {
        if at == 0 {
            continue;
        }
        answered += 1;
        round_trips.push(at.saturating_sub(sent));
        // Answered only after the next request was due.
        if u128::from(at) * u128::from(rate) > (k as u128 + 1) * 1_000_000_000 {
            late_answers += 1;
        }
    }
    let unanswered = requests as u64 - answered;
    let unexpected = received.unexpected;
    round_trips.sort_unstable();
    lateness.sort_unstable();
    let percentile = |values: &[u64], percent: usize| {
        values
            .get(values.len() * percent / 100)
            .copied()
            .unwrap_or(0) as f64
            / 1000.0
    };
    let mode_name = match mode {
        Mode::Bare => "bare",
        Mode::Nonce => "nonce",
    };
    println!(
        "{{\"probe\":\"spry-control-probe-v1\",\"mode\":\"{mode_name}\",\"sources\":{sources},\"setup_requests\":{sources},\"requests\":{requests},\"offered_requests_per_second\":{rate},\"answered\":{answered},\"unanswered\":{unanswered},\"late_answers\":{late_answers},\"unexpected_responses\":{unexpected},\"seconds\":{elapsed:.6},\"setup_ms\":{setup_ms:.3},\"round_trip_p50_us\":{:.3},\"round_trip_p99_us\":{:.3},\"dispatch_lateness_p99_us\":{:.3},\"missed_dispatch_slots\":{missed_slots}}}",
        percentile(&round_trips, 50),
        percentile(&round_trips, 99),
        percentile(&lateness, 99),
    );
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("control probe failed: {error}");
        std::process::exit(1);
    }
}
