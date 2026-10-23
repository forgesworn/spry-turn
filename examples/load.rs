//! A socket-level load generator shared by spry-turn and coturn benchmarks.
//! Measures delivered payloads, with no protocol implementation in the server process.
use spry_turn::{auth, turn::unix_time, wire::*};
use std::{
    env, io,
    net::{SocketAddr, UdpSocket},
    time::{Duration, Instant},
};

struct Pair {
    client: UdpSocket,
    peer: UdpSocket,
    relay: SocketAddr,
    sent: u64,
    received: u64,
}

fn request(
    socket: &UdpSocket,
    method: u16,
    transaction: [u8; 12],
    fields: &[(u16, &[u8])],
    key: Option<&[u8]>,
) -> io::Result<Vec<u8>> {
    let mut b = Builder::new(method, 0, transaction);
    for (typ, value) in fields {
        b.attr(*typ, value);
    }
    socket.send(&b.finish(key))?;
    let mut bytes = vec![0; 4096];
    let n = socket.recv(&mut bytes)?;
    bytes.truncate(n);
    let message = Message::parse(&bytes).ok_or_else(|| io::Error::other("invalid response"))?;
    if message.transaction != transaction || (key.is_some() && !message.verify(key.unwrap())) {
        return Err(io::Error::other("invalid response transaction/integrity"));
    }
    Ok(bytes)
}

fn pair(server: SocketAddr, secret: &[u8], index: usize) -> io::Result<Pair> {
    let client = UdpSocket::bind("127.0.0.1:0")?;
    client.connect(server)?;
    client.set_read_timeout(Some(Duration::from_secs(3)))?;
    let peer = UdpSocket::bind("127.0.0.1:0")?;
    peer.set_read_timeout(Some(Duration::from_secs(3)))?;
    let challenge = request(
        &client,
        ALLOCATE,
        [1; 12],
        &[(TRANSPORT, &[17, 0, 0, 0])],
        None,
    )?;
    let message = Message::parse(&challenge).ok_or_else(|| io::Error::other("challenge"))?;
    let nonce = message
        .attr(NONCE)
        .ok_or_else(|| io::Error::other("missing nonce"))?;
    let realm = message
        .attr(REALM)
        .ok_or_else(|| io::Error::other("missing realm"))?;
    let realm_str = std::str::from_utf8(realm).map_err(io::Error::other)?;
    let username = format!("{}:bench{index}", unix_time() + 3600);
    let password = auth::credential(secret, &username);
    let key = auth::key(&username, realm_str, &password);
    let fields = [
        (USERNAME, username.as_bytes()),
        (REALM, realm),
        (NONCE, nonce),
    ];
    let mut allocate = fields.to_vec();
    allocate.push((TRANSPORT, &[17, 0, 0, 0]));
    let allocated = request(&client, ALLOCATE, [2; 12], &allocate, Some(&key))?;
    let allocation = Message::parse(&allocated).ok_or_else(|| io::Error::other("allocation"))?;
    let relay = allocation
        .address(RELAYED)
        .ok_or_else(|| io::Error::other("allocation rejected"))?;
    let (address, len) = address_value(peer.local_addr()?, &[3; 12]);
    let mut bind = fields.to_vec();
    bind.push((PEER, &address[..len]));
    bind.push((CHANNEL, &[0x40, 0, 0, 0]));
    let bound = request(&client, CHANNEL_BIND, [3; 12], &bind, Some(&key))?;
    if Message::parse(&bound).is_none_or(|m| m.class != 2) {
        return Err(io::Error::other("channel rejected"));
    }
    Ok(Pair {
        client,
        peer,
        relay,
        sent: 0,
        received: 0,
    })
}

fn batch(pair: &mut Pair, count: usize, packet: &mut [u8], buffer: &mut [u8]) -> io::Result<()> {
    for _ in 0..count {
        packet[4..12].copy_from_slice(&pair.sent.to_be_bytes());
        pair.client.send(packet)?;
        pair.sent += 1;
    }
    for _ in 0..count {
        let (n, source) = pair.peer.recv_from(buffer)?;
        if n != packet.len() - 4 || source != pair.relay {
            return Err(io::Error::other("invalid relayed payload"));
        }
        pair.peer.send_to(&buffer[..n], source)?;
    }
    for _ in 0..count {
        let n = pair.client.recv(buffer)?;
        if n != packet.len() || buffer[..4] != packet[..4] {
            return Err(io::Error::other("invalid return payload"));
        }
        let seq = u64::from_be_bytes(buffer[4..12].try_into().expect("checked packet length"));
        if seq != pair.received {
            return Err(io::Error::other("loss, duplication or reordering"));
        }
        if buffer[12..n].iter().any(|b| *b != 0x5a) {
            return Err(io::Error::other("payload corruption"));
        }
        pair.received += 1;
    }
    Ok(())
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().skip(1).collect();
    let server: SocketAddr = args.first().ok_or("server address required")?.parse()?;
    if !server.ip().is_loopback() {
        return Err("benchmark is restricted to loopback".into());
    }
    let clients: usize = args.get(1).map(|s| s.parse()).transpose()?.unwrap_or(1);
    let requests: usize = args
        .get(2)
        .map(|s| s.parse())
        .transpose()?
        .unwrap_or(100_000);
    let size: usize = args.get(3).map(|s| s.parse()).transpose()?.unwrap_or(1200);
    let window: usize = args.get(4).map(|s| s.parse()).transpose()?.unwrap_or(32);
    if clients == 0
        || clients > 512
        || !(8..=1400).contains(&size)
        || window == 0
        || window > 64
        || requests < clients
    {
        return Err("invalid benchmark bounds".into());
    }
    let secret = env::var("SPRY_TURN_SECRET")?;
    let setup = Instant::now();
    let mut pairs = (0..clients)
        .map(|i| pair(server, secret.as_bytes(), i))
        .collect::<io::Result<Vec<_>>>()?;
    let setup_ms = setup.elapsed().as_secs_f64() * 1000.0;
    let mut packet = vec![0x5a; size + 4];
    packet[..2].copy_from_slice(&0x4000u16.to_be_bytes());
    packet[2..4].copy_from_slice(&(size as u16).to_be_bytes());
    let mut buffer = vec![0; 65536];
    for pair in &mut pairs {
        batch(pair, 16, &mut packet, &mut buffer)?;
    }
    let mut latency = Vec::with_capacity(2000);
    for i in 0..2000 {
        let start = Instant::now();
        batch(&mut pairs[i % clients], 1, &mut packet, &mut buffer)?;
        latency.push(start.elapsed().as_nanos() as u64);
    }
    latency.sort_unstable();
    let start = Instant::now();
    let workers = clients.min(4);
    let chunk_size = clients.div_ceil(workers);
    let chunks = clients.div_ceil(chunk_size);
    std::thread::scope(|scope| -> io::Result<()> {
        let mut handles = Vec::new();
        for (worker, pairs) in pairs.chunks_mut(chunk_size).enumerate() {
            handles.push(scope.spawn(move || -> io::Result<()> {
                let mut packet = vec![0x5a; size + 4];
                packet[..2].copy_from_slice(&0x4000u16.to_be_bytes());
                packet[2..4].copy_from_slice(&(size as u16).to_be_bytes());
                let mut buffer = vec![0; 65536];
                let total = requests / chunks + usize::from(worker < requests % chunks);
                let mut done = 0;
                let mut index = 0;
                while done < total {
                    let count = window.min(total - done);
                    batch(
                        &mut pairs[index % pairs.len()],
                        count,
                        &mut packet,
                        &mut buffer,
                    )?;
                    done += count;
                    index += 1;
                }
                Ok(())
            }));
        }
        for handle in handles {
            handle
                .join()
                .map_err(|_| io::Error::other("load worker panicked"))??;
        }
        Ok(())
    })?;
    let elapsed = start.elapsed().as_secs_f64();
    println!(
        "{{\"clients\":{clients},\"load_workers\":{chunks},\"payload_bytes\":{size},\"window\":{window},\"round_trips\":{requests},\"delivered_forwarded_packets\":{},\"seconds\":{elapsed:.6},\"packets_per_second\":{:.1},\"payload_mbps\":{:.1},\"round_trip_p50_us\":{:.3},\"round_trip_p99_us\":{:.3},\"setup_ms\":{setup_ms:.3},\"loss_or_corruption\":0}}",
        requests * 2,
        requests as f64 * 2.0 / elapsed,
        requests as f64 * 2.0 * size as f64 * 8.0 / elapsed / 1e6,
        latency[1000] as f64 / 1000.0,
        latency[1980] as f64 / 1000.0
    );
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("load test failed: {error}");
        std::process::exit(1);
    }
}
