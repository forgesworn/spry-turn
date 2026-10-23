//! A native, real-socket load generator shared by spry-turn and coturn.
//! Closed-loop throughput is workload delivery rate, not maximum server capacity.
use spry_turn::{auth, turn::unix_time, wire::*};
use std::{
    env,
    io::{self, Read, Write},
    net::{SocketAddr, TcpStream, UdpSocket},
    time::{Duration, Instant},
};

#[derive(Clone, Copy)]
enum Transport {
    Udp,
    Tcp,
    Tls,
}
impl Transport {
    fn name(self) -> &'static str {
        match self {
            Self::Udp => "udp",
            Self::Tcp => "tcp",
            Self::Tls => "tls",
        }
    }
}

enum Client {
    Udp(UdpSocket),
    Tcp(TcpStream),
    #[cfg(feature = "tls")]
    Tls(Box<rustls::StreamOwned<rustls::ClientConnection, TcpStream>>),
}

impl Client {
    fn connect(server: SocketAddr, mode: Transport, ca: Option<&str>) -> io::Result<Self> {
        if matches!(mode, Transport::Udp) {
            let socket = UdpSocket::bind("127.0.0.1:0")?;
            socket.connect(server)?;
            socket.set_read_timeout(Some(Duration::from_secs(3)))?;
            socket.set_write_timeout(Some(Duration::from_secs(3)))?;
            return Ok(Self::Udp(socket));
        }
        let socket = TcpStream::connect_timeout(&server, Duration::from_secs(3))?;
        socket.set_nodelay(true)?;
        socket.set_read_timeout(Some(Duration::from_secs(3)))?;
        socket.set_write_timeout(Some(Duration::from_secs(3)))?;
        if matches!(mode, Transport::Tcp) {
            return Ok(Self::Tcp(socket));
        }
        #[cfg(feature = "tls")]
        {
            let mut roots = rustls::RootCertStore::empty();
            let mut file = io::BufReader::new(std::fs::File::open(
                ca.ok_or_else(|| io::Error::other("TLS requires --ca"))?,
            )?);
            for cert in rustls_pemfile::certs(&mut file) {
                roots.add(cert?).map_err(io::Error::other)?;
            }
            if roots.is_empty() {
                return Err(io::Error::other("empty TLS trust store"));
            }
            let config = rustls::ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth();
            let connection = rustls::ClientConnection::new(
                std::sync::Arc::new(config),
                "localhost".try_into().map_err(io::Error::other)?,
            )
            .map_err(io::Error::other)?;
            Ok(Self::Tls(Box::new(rustls::StreamOwned::new(
                connection, socket,
            ))))
        }
        #[cfg(not(feature = "tls"))]
        {
            let _ = ca;
            Err(io::Error::other("TLS load testing requires --features tls"))
        }
    }

    fn tls_parameters(&self) -> Option<(String, String)> {
        #[cfg(feature = "tls")]
        if let Self::Tls(stream) = self {
            return Some((
                format!("{:?}", stream.conn.protocol_version()?),
                format!("{:?}", stream.conn.negotiated_cipher_suite()?.suite()),
            ));
        }
        None
    }

    fn send(&mut self, bytes: &[u8]) -> io::Result<()> {
        match self {
            Self::Udp(socket) => {
                if socket.send(bytes)? != bytes.len() {
                    return Err(io::Error::other("short UDP send"));
                }
                Ok(())
            }
            Self::Tcp(socket) => write_frame(socket, bytes),
            #[cfg(feature = "tls")]
            Self::Tls(socket) => write_frame(socket.as_mut(), bytes),
        }
    }

    fn receive(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        match self {
            Self::Udp(socket) => socket.recv(bytes),
            Self::Tcp(socket) => read_frame(socket, bytes),
            #[cfg(feature = "tls")]
            Self::Tls(socket) => read_frame(socket.as_mut(), bytes),
        }
    }
}

fn write_frame(stream: &mut impl Write, bytes: &[u8]) -> io::Result<()> {
    stream.write_all(bytes)?;
    if bytes[0] >> 6 == 1 {
        let padding = (4 - bytes.len() % 4) % 4;
        stream.write_all(&[0; 3][..padding])?;
    }
    stream.flush()
}

fn read_frame(stream: &mut impl Read, bytes: &mut [u8]) -> io::Result<usize> {
    stream.read_exact(&mut bytes[..4])?;
    let payload = u16::from_be_bytes([bytes[2], bytes[3]]) as usize;
    let (actual, framed) = match bytes[0] >> 6 {
        0 => (20 + payload, 20 + payload),
        1 => (4 + payload, 4 + payload.next_multiple_of(4)),
        _ => return Err(io::Error::other("invalid stream frame")),
    };
    if framed > bytes.len() {
        return Err(io::Error::other("oversized stream frame"));
    }
    stream.read_exact(&mut bytes[4..framed])?;
    Ok(actual)
}

struct Pair {
    client: Client,
    peer: UdpSocket,
    relay: SocketAddr,
    sent: u64,
    received: u64,
}

fn request(
    socket: &mut Client,
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
    let mut bytes = vec![0; 65536];
    let n = socket.receive(&mut bytes)?;
    bytes.truncate(n);
    let message = Message::parse(&bytes).ok_or_else(|| io::Error::other("invalid response"))?;
    if message.transaction != transaction || key.is_some_and(|key| !message.verify(key)) {
        return Err(io::Error::other("invalid response transaction/integrity"));
    }
    Ok(bytes)
}

fn pair(
    server: SocketAddr,
    secret: &[u8],
    index: usize,
    mode: Transport,
    ca: Option<&str>,
) -> io::Result<Pair> {
    let mut client = Client::connect(server, mode, ca)?;
    let peer = UdpSocket::bind("127.0.0.1:0")?;
    peer.set_read_timeout(Some(Duration::from_secs(3)))?;
    peer.set_write_timeout(Some(Duration::from_secs(3)))?;
    let challenge = request(
        &mut client,
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
    let allocated = request(&mut client, ALLOCATE, [2; 12], &allocate, Some(&key))?;
    let allocation = Message::parse(&allocated).ok_or_else(|| io::Error::other("allocation"))?;
    let relay = allocation
        .address(RELAYED)
        .ok_or_else(|| io::Error::other("allocation rejected"))?;
    let (address, len) = address_value(peer.local_addr()?, &[3; 12]);
    let mut bind = fields.to_vec();
    bind.push((PEER, &address[..len]));
    bind.push((CHANNEL, &[0x40, 0, 0, 0]));
    let bound = request(&mut client, CHANNEL_BIND, [3; 12], &bind, Some(&key))?;
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

// A bounded deterministic reservoir samples the complete loaded phase rather
// than retaining only startup samples. Every worker has its own reservoir.
#[derive(Default)]
struct Latency {
    values: Vec<u64>,
    count: u64,
    random: u64,
}
impl Latency {
    fn add(&mut self, elapsed: Duration) {
        self.count += 1;
        let value = elapsed.as_nanos() as u64;
        if self.values.len() < 4096 {
            self.values.push(value);
        } else {
            self.random = self
                .random
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1);
            let index = (self.random >> 1) % self.count;
            if let Some(slot) = self.values.get_mut(index as usize) {
                *slot = value;
            }
        }
    }
}

fn batch(
    pair: &mut Pair,
    count: usize,
    packet: &mut [u8],
    buffer: &mut [u8],
    latency: &mut Latency,
) -> io::Result<()> {
    let mut timestamps = [None; 64];
    for timestamp in timestamps.iter_mut().take(count) {
        packet[4..12].copy_from_slice(&pair.sent.to_be_bytes());
        // Every 64th packet per allocation; includes queued window time and
        // client/echo scheduling as well as both server forwarding directions.
        if pair.sent % 64 == 0 {
            *timestamp = Some(Instant::now());
        }
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
    for timestamp in timestamps.iter().take(count) {
        let n = pair.client.receive(buffer)?;
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
        if let Some(start) = timestamp {
            latency.add(start.elapsed());
        }
        pair.received += 1;
    }
    Ok(())
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().skip(1).collect();
    let server: SocketAddr = args.first().ok_or("server address required")?.parse()?;
    if !server.ip().is_loopback() || !server.is_ipv4() {
        return Err("benchmark is restricted to IPv4 loopback".into());
    }
    let clients: usize = args.get(1).map(|s| s.parse()).transpose()?.unwrap_or(1);
    let requests: usize = args
        .get(2)
        .map(|s| s.parse())
        .transpose()?
        .unwrap_or(100_000);
    let size: usize = args.get(3).map(|s| s.parse()).transpose()?.unwrap_or(1200);
    let window: usize = args.get(4).map(|s| s.parse()).transpose()?.unwrap_or(32);
    let mut mode = Transport::Udp;
    let mut ca = None;
    let mut workers = clients.min(4);
    let mut min_seconds = 0.0;
    let mut resource_hold_ms = 0;
    for option in args.get(5..).unwrap_or_default().chunks(2) {
        let value = option.get(1).ok_or("benchmark option requires a value")?;
        match option[0].as_str() {
            "--transport" => {
                mode = match value.as_str() {
                    "udp" => Transport::Udp,
                    "tcp" => Transport::Tcp,
                    "tls" => Transport::Tls,
                    _ => return Err("invalid transport".into()),
                }
            }
            "--ca" => ca = Some(value.as_str()),
            "--workers" => workers = value.parse()?,
            "--min-seconds" => min_seconds = value.parse::<f64>()?,
            "--resource-hold-ms" => resource_hold_ms = value.parse::<u64>()?,
            _ => return Err("unknown benchmark option".into()),
        }
    }
    if clients == 0
        || clients > 512
        || !(8..=1400).contains(&size)
        || !(1..=64).contains(&window)
        || !(clients..=100_000_000).contains(&requests)
        || workers == 0
        || workers > clients.min(64)
        || !min_seconds.is_finite()
        || !(0.0..=60.0).contains(&min_seconds)
        || resource_hold_ms > 30000
    {
        return Err("invalid benchmark bounds".into());
    }
    let secret = env::var("SPRY_TURN_SECRET")?;
    let setup = Instant::now();
    let mut pairs = (0..clients)
        .map(|i| pair(server, secret.as_bytes(), i, mode, ca))
        .collect::<io::Result<Vec<_>>>()?;
    let tls = pairs[0].client.tls_parameters();
    if pairs.iter().any(|pair| pair.client.tls_parameters() != tls) {
        return Err("mixed TLS protocol/cipher within one workload".into());
    }
    let tls_metadata = tls.map_or_else(
        || "null".to_owned(),
        |(protocol, cipher)| format!("{{\"protocol\":\"{protocol}\",\"cipher\":\"{cipher}\"}}"),
    );
    let setup_ms = setup.elapsed().as_secs_f64() * 1000.0;
    let make_packet = || {
        let mut packet = vec![0x5a; size + 4];
        packet[..2].copy_from_slice(&0x4000u16.to_be_bytes());
        packet[2..4].copy_from_slice(&(size as u16).to_be_bytes());
        packet
    };
    let mut packet = make_packet();
    let mut buffer = vec![0; 65536];
    let mut ignored = Latency::default();
    for pair in &mut pairs {
        batch(pair, 16, &mut packet, &mut buffer, &mut ignored)?;
    }
    let mut latency = Vec::with_capacity(2000);
    for i in 0..2000 {
        let start = Instant::now();
        batch(
            &mut pairs[i % clients],
            1,
            &mut packet,
            &mut buffer,
            &mut ignored,
        )?;
        latency.push(start.elapsed().as_nanos() as u64);
    }
    latency.sort_unstable();
    let start = Instant::now();
    let chunk_size = clients.div_ceil(workers);
    let chunks = clients.div_ceil(chunk_size);
    let (completed, mut loaded, loaded_count) = std::thread::scope(|scope| -> io::Result<_> {
        let mut handles = Vec::new();
        for (worker, pairs) in pairs.chunks_mut(chunk_size).enumerate() {
            handles.push(scope.spawn(move || -> io::Result<_> {
                let mut packet = make_packet();
                let mut buffer = vec![0; 65536];
                let mut loaded = Latency::default();
                let total = requests / chunks + usize::from(worker < requests % chunks);
                let mut done = 0;
                let mut index = 0;
                while done < total || start.elapsed().as_secs_f64() < min_seconds {
                    let count = if done < total {
                        window.min(total - done)
                    } else {
                        window
                    };
                    batch(
                        &mut pairs[index % pairs.len()],
                        count,
                        &mut packet,
                        &mut buffer,
                        &mut loaded,
                    )?;
                    done += count;
                    index += 1;
                }
                Ok((done, loaded))
            }));
        }
        let mut completed = 0;
        let mut loaded = Vec::new();
        let mut loaded_count = 0;
        for handle in handles {
            let (done, samples) = handle
                .join()
                .map_err(|_| io::Error::other("load worker panicked"))??;
            completed += done;
            loaded.extend(samples.values);
            loaded_count += samples.count;
        }
        Ok((completed, loaded, loaded_count))
    })?;
    let elapsed = start.elapsed().as_secs_f64();
    loaded.sort_unstable();
    let percentile = |percent: usize| {
        loaded
            .get(loaded.len() * percent / 100)
            .copied()
            .unwrap_or(0) as f64
            / 1000.0
    };
    println!(
        "{{\"transport\":\"{}\",\"tls\":{tls_metadata},\"clients\":{clients},\"load_workers\":{chunks},\"payload_bytes\":{size},\"window\":{window},\"round_trips\":{completed},\"minimum_seconds\":{min_seconds},\"delivered_forwarded_packets\":{},\"seconds\":{elapsed:.6},\"packets_per_second\":{:.1},\"payload_mbps\":{:.1},\"round_trip_p50_us\":{:.3},\"round_trip_p99_us\":{:.3},\"loaded_round_trip_p50_us\":{:.3},\"loaded_round_trip_p99_us\":{:.3},\"loaded_latency_observations\":{loaded_count},\"loaded_latency_retained\":{},\"setup_ms\":{setup_ms:.3},\"loss_or_corruption\":0}}",
        mode.name(),
        completed * 2,
        completed as f64 * 2.0 / elapsed,
        completed as f64 * 2.0 * size as f64 * 8.0 / elapsed / 1e6,
        latency[1000] as f64 / 1000.0,
        latency[1980] as f64 / 1000.0,
        percentile(50),
        percentile(99),
        loaded.len()
    );
    io::stdout().flush()?;
    if resource_hold_ms != 0 {
        // Keep all allocations and connections alive while the parent samples
        // descriptors/socket memory. EOF, acknowledgement or timeout releases
        // them; this cannot wait indefinitely if orchestration disappears.
        let (send, receive) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let mut acknowledgement = [0; 1];
            let _ = io::stdin().read_exact(&mut acknowledgement);
            let _ = send.send(());
        });
        let _ = receive.recv_timeout(Duration::from_millis(resource_hold_ms));
    }
    // Preserve the clients until after the resource-observation handshake.
    drop(pairs);
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("load test failed: {error}");
        std::process::exit(1);
    }
}
