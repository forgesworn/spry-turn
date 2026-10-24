//! Optional private-IPv6 peer adapter. No Archipelago or overlay SDK dependency.
use socket2::{Domain, Protocol, Socket, Type};
use spry_link::{
    identity::{Event, Identity},
    peer::{self, Datagram, FIRST_RELAY, LAST_RELAY, MAX_PEERS, PacketSession, PeerCard},
};
use spry_turn::turn::{Config, Server};
use std::{
    collections::{HashMap, HashSet},
    io,
    net::{IpAddr, Ipv4Addr, SocketAddrV4, SocketAddrV6},
    sync::{
        Arc, RwLock,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    thread,
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
    sync::{Semaphore, mpsc, watch},
    task::{JoinHandle, JoinSet},
    time::{interval, timeout},
};

type Allowed = Arc<RwLock<HashMap<String, PeerCard>>>;
type Ports = Arc<RwLock<HashSet<u16>>>;
type Established = (TcpStream, PacketSession);
const HANDSHAKE: Duration = Duration::from_secs(3);

pub struct MeshConfig {
    pub client_listen: SocketAddrV4,
    pub peer_listen: SocketAddrV6,
    pub secret: Vec<u8>,
}
pub struct Mesh {
    identity: Arc<Identity>,
    address: SocketAddrV6,
    card: std::sync::Mutex<Option<(u64, Event)>>,
    updates: watch::Sender<Vec<PeerCard>>,
    allowed: Allowed,
    connected: Arc<AtomicUsize>,
    stop: Arc<AtomicBool>,
    core: Option<thread::JoinHandle<()>>,
    manager: JoinHandle<()>,
}
struct Connected(Arc<AtomicUsize>);
impl Connected {
    fn new(count: Arc<AtomicUsize>) -> Self {
        count.fetch_add(1, Ordering::Relaxed);
        Self(count)
    }
}
impl Drop for Connected {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Relaxed);
    }
}
fn failure() -> io::Error {
    io::Error::other("peer link refused")
}
fn now() -> u64 {
    super::now()
}
impl Mesh {
    pub async fn start(config: MeshConfig) -> io::Result<Self> {
        let identity = Arc::new(Identity::derive(&config.secret).map_err(|_| failure())?);
        // A signed card validates the exact private listener and fixed port.
        PeerCard::sign(&identity, config.peer_listen, now()).map_err(|_| failure())?;
        let listener = TcpListener::bind(config.peer_listen).await?;
        let alias = peer::relay_alias(&identity.public_key()).map_err(|_| failure())?;
        let mut turn = Config::local(config.secret);
        turn.listen = config.client_listen.into();
        turn.relay_ip = alias.into();
        turn.local_peer_bridge = true;
        turn.relay_port_range = Some((FIRST_RELAY, LAST_RELAY));
        turn.max_allocations = 32;
        turn.max_per_user = 8;
        turn.max_connections = 32;
        turn.bytes_per_second = 1_000_000;
        let mut server = Server::bind(turn)?;
        let allowed: Allowed = Arc::new(RwLock::new(HashMap::new()));
        let ports: Ports = Arc::new(RwLock::new(HashSet::new()));
        let stop = Arc::new(AtomicBool::new(false));
        let (stop_core, core_peers, core_ports) = (stop.clone(), allowed.clone(), ports.clone());
        let core = thread::Builder::new()
            .name("spry-forwarding".into())
            .spawn(move || {
                let mut last_peers = HashSet::new();
                while !stop_core.load(Ordering::Acquire) {
                    let desired: HashSet<_> = match core_peers.read() {
                        Ok(cards) => cards
                            .values()
                            .filter(|card| card.expires_at > now())
                            .map(|card| card.alias)
                            .collect(),
                        Err(_) => break,
                    };
                    if desired != last_peers {
                        if server.set_bridge_peer_ips(desired.clone()).is_err() {
                            break;
                        }
                        last_peers = desired;
                    }
                    if server.poll_once(Duration::from_millis(20)).is_err() {
                        break;
                    }
                    let active: HashSet<_> = server.allocated_relay_ports().collect();
                    if let Ok(mut ports) = core_ports.write() {
                        if *ports != active {
                            *ports = active;
                        }
                    } else {
                        break;
                    }
                }
                if let Ok(mut ports) = core_ports.write() {
                    ports.clear();
                }
                stop_core.store(true, Ordering::Release);
            })?;
        let (updates, receive) = watch::channel(Vec::new());
        let connected = Arc::new(AtomicUsize::new(0));
        let shared = Arc::new(Manager {
            identity: identity.clone(),
            alias,
            allowed: allowed.clone(),
            ports,
            connected: connected.clone(),
        });
        let manager = tokio::spawn(manage(listener, shared, receive, stop.clone()));
        Ok(Self {
            identity,
            address: config.peer_listen,
            card: std::sync::Mutex::new(None),
            updates,
            allowed,
            connected,
            stop,
            core: Some(core),
            manager,
        })
    }
    pub fn public_key(&self) -> String {
        self.identity.public_key()
    }
    pub(crate) fn identity(&self) -> Arc<Identity> {
        self.identity.clone()
    }
    pub fn card(&self) -> io::Result<Event> {
        // Stable cards prevent descriptor replies from creating a publication loop.
        let bucket = now() / 240 * 240;
        let mut cached = self.card.lock().map_err(|_| failure())?;
        if cached.as_ref().is_none_or(|(time, _)| *time != bucket) {
            *cached = Some((
                bucket,
                PeerCard::sign(&self.identity, self.address, bucket)
                    .map_err(|_| failure())?
                    .event,
            ));
        }
        cached
            .as_ref()
            .map(|(_, event)| event.clone())
            .ok_or_else(failure)
    }
    pub fn connected_peers(&self) -> usize {
        self.connected.load(Ordering::Relaxed)
    }
    pub fn healthy(&self) -> bool {
        !self.stop.load(Ordering::Acquire) && !self.manager.is_finished()
    }
    /// The host authorises scopes first; this revalidates every card and alias.
    pub fn set_peers(&self, cards: Vec<PeerCard>) -> io::Result<()> {
        if cards.len() > MAX_PEERS || !self.healthy() {
            return Err(failure());
        }
        let mut aliases =
            HashSet::from([peer::relay_alias(&self.public_key()).map_err(|_| failure())?]);
        let mut valid = HashMap::new();
        for card in cards {
            let card = PeerCard::verify(card.event, now()).map_err(|_| failure())?;
            if !aliases.insert(card.alias)
                || valid.insert(card.event.pubkey.clone(), card).is_some()
            {
                return Err(failure());
            }
        }
        let cards = valid.values().cloned().collect();
        *self.allowed.write().map_err(|_| failure())? = valid;
        self.updates.send_replace(cards);
        Ok(())
    }
}
impl Drop for Mesh {
    fn drop(&mut self) {
        self.manager.abort();
        self.stop.store(true, Ordering::Release);
        if let Some(core) = self.core.take() {
            let _ = core.join();
        }
    }
}

struct Worker {
    address: SocketAddrV6,
    incoming: mpsc::Sender<Established>,
    task: JoinHandle<()>,
}
impl Drop for Worker {
    fn drop(&mut self) {
        self.task.abort();
    }
}
struct Manager {
    identity: Arc<Identity>,
    alias: Ipv4Addr,
    allowed: Allowed,
    ports: Ports,
    connected: Arc<AtomicUsize>,
}
async fn manage(
    listener: TcpListener,
    shared: Arc<Manager>,
    mut updates: watch::Receiver<Vec<PeerCard>>,
    stop: Arc<AtomicBool>,
) {
    let mut workers: HashMap<String, Worker> = HashMap::new();
    let (incoming_tx, mut incoming_rx) = mpsc::channel::<(String, Established)>(MAX_PEERS);
    let permits = Arc::new(Semaphore::new(16));
    let mut pending = JoinSet::new();
    let mut tick = interval(Duration::from_secs(1));
    loop {
        tokio::select! {
            _=tick.tick()=>{},
            changed=updates.changed()=>if changed.is_err(){break;},
            Some((key,connection))=incoming_rx.recv()=>{
                if let Some(worker)=workers.get(&key){let _=worker.incoming.try_send(connection);}continue;
            },
            Some(_)=pending.join_next()=>continue,
            accepted=listener.accept()=>{
                let Ok((stream,_))=accepted else {break;};
                let Ok(permit)=permits.clone().try_acquire_owned()else{drop(stream);continue;};
                let state=shared.clone();let output=incoming_tx.clone();
                pending.spawn(async move{
                    let _permit=permit;
                    let mut stream=stream;
                    if let Ok(Ok((key,session)))=timeout(HANDSHAKE,accept_proof(&state,&mut stream)).await {
                        let _=output.try_send((key,(stream,session)));
                    }
                });
                continue;
            }
        }
        if stop.load(Ordering::Acquire) {
            break;
        }
        let cards = {
            match shared.allowed.write() {
                Ok(mut cards) => {
                    cards.retain(|_, card| card.expires_at > now());
                    cards.clone()
                }
                Err(_) => break,
            }
        };
        workers.retain(|key, worker| {
            cards
                .get(key)
                .is_some_and(|card| card.address == worker.address)
                && !worker.task.is_finished()
        });
        for (key, card) in cards {
            if workers.contains_key(&key) {
                continue;
            }
            let (send, receive) = mpsc::channel(1);
            let address = card.address;
            let state = shared.clone();
            let task = tokio::spawn(async move {
                let _ = peer_worker(state, card, receive).await;
            });
            workers.insert(
                key,
                Worker {
                    address,
                    incoming: send,
                    task,
                },
            );
        }
    }
    stop.store(true, Ordering::Release);
}

async fn write_event(stream: &mut TcpStream, event: &Event) -> io::Result<()> {
    let bytes = serde_json::to_vec(event).map_err(|_| failure())?;
    if bytes.len() > 2048 {
        return Err(failure());
    }
    stream.write_u16(bytes.len() as u16).await?;
    stream.write_all(&bytes).await
}
async fn read_event(stream: &mut TcpStream) -> io::Result<Event> {
    let length = usize::from(stream.read_u16().await?);
    if length > 2048 {
        return Err(failure());
    }
    let mut bytes = vec![0; length];
    stream.read_exact(&mut bytes).await?;
    Event::parse(&bytes).map_err(|_| failure())
}
async fn accept_proof(
    shared: &Manager,
    stream: &mut TcpStream,
) -> io::Result<(String, PacketSession)> {
    let mut challenge = [0; 32];
    getrandom::fill(&mut challenge).map_err(|_| failure())?;
    stream.write_all(b"SPRY\x01").await?;
    stream.write_all(&challenge).await?;
    let event = read_event(stream).await?;
    let own = shared.identity.public_key();
    if event.pubkey >= own
        || shared
            .allowed
            .read()
            .map_err(|_| failure())?
            .get(&event.pubkey)
            .is_none_or(|card| card.expires_at <= now())
    {
        return Err(failure());
    }
    let client_nonce = spry_link::unhex::<32>(event.tag("nonce").map_err(|_| failure())?)
        .map_err(|_| failure())?;
    peer::verify_hello(
        &event,
        &event.pubkey,
        &own,
        &challenge,
        &client_nonce,
        now(),
    )
    .map_err(|_| failure())?;
    write_event(
        stream,
        &peer::hello(
            &shared.identity,
            &event.pubkey,
            &challenge,
            &client_nonce,
            now(),
        )
        .map_err(|_| failure())?,
    )
    .await?;
    let session = PacketSession::new(
        &shared.identity,
        &event.pubkey,
        &challenge,
        &client_nonce,
        false,
    )
    .map_err(|_| failure())?;
    Ok((event.pubkey, session))
}
async fn connect_proof(
    identity: &Identity,
    card: &PeerCard,
    stream: &mut TcpStream,
) -> io::Result<PacketSession> {
    let mut magic = [0; 5];
    stream.read_exact(&mut magic).await?;
    if &magic != b"SPRY\x01" {
        return Err(failure());
    }
    let mut challenge = [0; 32];
    stream.read_exact(&mut challenge).await?;
    let mut nonce = [0; 32];
    getrandom::fill(&mut nonce).map_err(|_| failure())?;
    write_event(
        stream,
        &peer::hello(identity, &card.event.pubkey, &challenge, &nonce, now())
            .map_err(|_| failure())?,
    )
    .await?;
    let event = read_event(stream).await?;
    peer::verify_hello(
        &event,
        &card.event.pubkey,
        &identity.public_key(),
        &challenge,
        &nonce,
        now(),
    )
    .map_err(|_| failure())?;
    PacketSession::new(identity, &card.event.pubkey, &challenge, &nonce, true)
        .map_err(|_| failure())
}
fn mirror(alias: Ipv4Addr, port: u16) -> io::Result<UdpSocket> {
    let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    socket.set_nonblocking(true)?;
    socket.set_recv_buffer_size(8192)?;
    socket.set_send_buffer_size(8192)?;
    socket.bind(&SocketAddrV4::new(alias, port).into())?;
    UdpSocket::from_std(socket.into())
}
async fn peer_worker(
    shared: Arc<Manager>,
    card: PeerCard,
    mut incoming: mpsc::Receiver<Established>,
) -> io::Result<()> {
    let mut mirrors = Vec::new();
    let mut readers = JoinSet::new();
    let (outgoing, mut packets) = mpsc::channel(32);
    for port in FIRST_RELAY..=LAST_RELAY {
        let socket = Arc::new(mirror(card.alias, port)?);
        mirrors.push(socket.clone());
        let state = shared.clone();
        let output = outgoing.clone();
        readers.spawn(async move {
            let mut bytes = [0; peer::MAX_DATAGRAM + 1];
            while let Ok((length, source)) = socket.recv_from(&mut bytes).await {
                if length == 0
                    || length > peer::MAX_DATAGRAM
                    || source.ip() != IpAddr::V4(state.alias)
                    || !state
                        .ports
                        .read()
                        .is_ok_and(|ports| ports.contains(&source.port()))
                {
                    continue;
                }
                let _ = output.try_send(Datagram {
                    source_port: source.port(),
                    destination_port: port,
                    bytes: bytes[..length].to_vec(),
                });
            }
        });
    }
    let mirrors = Arc::new(mirrors);
    let initiator = shared.identity.public_key() < card.event.pubkey;
    loop {
        if !shared.allowed.read().is_ok_and(|cards| {
            cards
                .get(&card.event.pubkey)
                .is_some_and(|next| next.expires_at > now() && next.address == card.address)
        }) {
            return Ok(());
        }
        let established = if initiator {
            match timeout(Duration::from_secs(13), async {
                let mut stream = timeout(Duration::from_secs(10), TcpStream::connect(card.address))
                    .await
                    .map_err(|_| failure())??;
                stream.set_nodelay(true)?;
                let session = timeout(
                    HANDSHAKE,
                    connect_proof(&shared.identity, &card, &mut stream),
                )
                .await
                .map_err(|_| failure())??;
                Ok::<_, io::Error>((stream, session))
            })
            .await
            {
                Ok(Ok(connection)) => Some(connection),
                _ => None,
            }
        } else {
            timeout(Duration::from_secs(2), incoming.recv())
                .await
                .unwrap_or_default()
        };
        if let Some((stream, session)) = established {
            let _connected = Connected::new(shared.connected.clone());
            let _ = connection(
                shared.clone(),
                &card,
                mirrors.clone(),
                stream,
                session,
                &mut packets,
            )
            .await;
        }
        tokio::time::sleep(Duration::from_millis(300)).await;
    }
}
async fn connection(
    shared: Arc<Manager>,
    card: &PeerCard,
    mirrors: Arc<Vec<Arc<UdpSocket>>>,
    stream: TcpStream,
    session: PacketSession,
    packets: &mut mpsc::Receiver<Datagram>,
) -> io::Result<()> {
    let (mut input, mut output) = stream.into_split();
    let (mut seal, mut open) = session.into_directions();
    let state = shared.clone();
    let key = card.event.pubkey.clone();
    let mut readers = JoinSet::new();
    readers.spawn(async move {
        let mut second = Instant::now();
        let mut received = 0_usize;
        loop {
            let length = usize::from(
                timeout(Duration::from_secs(45), input.read_u16())
                    .await
                    .map_err(|_| failure())??,
            );
            if length > peer::MAX_WIRE_PACKET {
                return Err(failure());
            }
            if second.elapsed() >= Duration::from_secs(1) {
                received = 0;
                second = Instant::now();
            }
            received += length;
            if received > 4_000_000 {
                return Err(failure());
            }
            let mut bytes = vec![0; length];
            timeout(Duration::from_secs(3), input.read_exact(&mut bytes))
                .await
                .map_err(|_| failure())??;
            if !state
                .allowed
                .read()
                .is_ok_and(|cards| cards.get(&key).is_some_and(|card| card.expires_at > now()))
            {
                return Err(failure());
            }
            if let Some(packet) = open.open(&bytes).map_err(|_| failure())? {
                if !state
                    .ports
                    .read()
                    .is_ok_and(|ports| ports.contains(&packet.destination_port))
                {
                    continue;
                }
                let socket = &mirrors[usize::from(packet.source_port - FIRST_RELAY)];
                socket
                    .send_to(
                        &packet.bytes,
                        SocketAddrV4::new(state.alias, packet.destination_port),
                    )
                    .await?;
            }
        }
        #[allow(unreachable_code)]
        Ok::<(), io::Error>(())
    });
    let mut heartbeat = interval(Duration::from_secs(15));
    let mut second = Instant::now();
    let mut sent = 0_usize;
    loop {
        let packet = tokio::select! {
            Some(packet)=packets.recv()=>Some(packet),
            _=heartbeat.tick()=>None,
            _=readers.join_next()=>return Err(failure()),
        };
        let bytes = seal.seal(packet.as_ref()).map_err(|_| failure())?;
        if second.elapsed() >= Duration::from_secs(1) {
            sent = 0;
            second = Instant::now();
        }
        sent += bytes.len();
        if sent > 4_000_000 {
            return Err(failure());
        }
        timeout(Duration::from_secs(2), async {
            output.write_u16(bytes.len() as u16).await?;
            output.write_all(&bytes).await
        })
        .await
        .map_err(|_| failure())??;
    }
}
