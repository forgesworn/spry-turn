//! One non-blocking event loop, bounded per-allocation sockets and state.
use crate::{
    auth,
    limits::{Bucket, SWEEP_INTERVAL, SourceTable, Stats},
    wire::{self, *},
};
use mio::{
    Events, Interest, Poll, Token,
    net::{TcpListener, TcpStream, UdpSocket},
};
use std::collections::{HashMap, VecDeque};
use std::hash::{BuildHasher, RandomState};
use std::sync::Arc;
use std::{
    collections::HashSet,
    io::{self, Read, Write},
    net::{IpAddr, SocketAddr},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

const UDP: Token = Token(0);
const TCP: Token = Token(1);
const TLS: Token = Token(2);
const MAX_PACKET: usize = 65_536;
const HEADROOM: usize = 64;
const MAX_QUEUE: usize = 131_072;

/// Live, host-owned admission for a short-lived TURN username. A host must
/// return promptly and deny when its authorisation state is unavailable.
pub type CredentialAuthorizer = Arc<dyn Fn(&str) -> bool + Send + Sync>;
// Keep ordinary control replies admissible when relayed UDP fills the queue.
// Control traffic retains the full queue cap and its existing close policy.
const STREAM_CONTROL_RESERVE: usize = 1024;
const MAX_PEERS: usize = 32;
const STREAM_READS_PER_TURN: usize = 16;
const STREAM_BYTES_PER_TURN: usize = MAX_QUEUE;
const STREAM_FRAMES_PER_TURN: usize = 64;
/// Control requests a client with a live allocation may always make, apart
/// from the budget every source shares. Enough for refreshes, permissions and
/// channel binds during ICE; small enough to bound integrity checks.
const ALLOCATION_REQUESTS_PER_SECOND: u64 = 10;
const ALLOCATION_REQUEST_BURST: u64 = 30;
/// Control requests from sources the relay can reach back: TCP and TLS
/// connections, loopback, and UDP requests carrying a nonce this relay issued
/// to that address. They share one budget. Each source has a soft allowance
/// within it: a source over its allowance may still use what the budget
/// holds above a reserve, so one address on its own can use the whole
/// refill, but sources within their allowance are served first and cannot be
/// displaced below the reserve. One address can use its allowance plus the
/// budget above the reserve at once (4,000 requests), as a single shared
/// budget of the same size allowed.
const VERIFIED_REQUESTS_PER_SECOND: u64 = 2000;
const VERIFIED_REQUEST_BURST: u64 = 6000;
const VERIFIED_RESERVE: u64 = 2000;
const VERIFIED_SOURCE_PER_SECOND: u64 = 20;
const VERIFIED_SOURCE_BURST: u64 = 40;
/// Other UDP requests, which carry no nonce for the sender's address, share a
/// second budget. Each address (IPv6: each /64) is held to a small allowance
/// within it, whatever the budget holds.
const UNVERIFIED_REQUESTS_PER_SECOND: u64 = 2000;
const UNVERIFIED_REQUEST_BURST: u64 = 2000;
const UNVERIFIED_SOURCE_PER_SECOND: u64 = 5;
const UNVERIFIED_SOURCE_BURST: u64 = 20;
/// Slots in each per-source table. Sources whose hashes collide share one
/// allowance; the tables are allocated once and never grow.
const SOURCE_SLOTS: usize = 4096;
// Coalesce only already queued plain TCP peer returns. Flush within the current
// receive dispatch, never wait for a later packet or timer to fill a batch.
const TCP_RETURN_BATCH_FRAMES: usize = 16;
const TCP_RETURN_BATCH_BYTES: usize = 16_384;

struct TcpReturnBatch {
    enabled: bool,
    frames: usize,
    bytes: usize,
    payload_bytes: usize,
}

impl TcpReturnBatch {
    fn new(enabled: bool) -> Self {
        Self {
            enabled,
            frames: 0,
            bytes: 0,
            payload_bytes: 0,
        }
    }
}

struct PeerReturnDispatch {
    first_accepted: bool,
    batch_started: bool,
    lent_output: bool,
    batch: TcpReturnBatch,
}

impl PeerReturnDispatch {
    fn new() -> Self {
        Self {
            first_accepted: false,
            batch_started: false,
            lent_output: false,
            batch: TcpReturnBatch::new(false),
        }
    }
}

fn local_bridge_address(ip: IpAddr) -> bool {
    matches!(ip, IpAddr::V4(v) if v.octets()[0] == 127 && (64..=127).contains(&v.octets()[1]))
}

/// Maximum explicit local/advertised UDP port pairs accepted by one server.
pub const MAX_RELAY_PORT_MAPPINGS: usize = 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RelayPortMapping {
    pub local_port: u16,
    pub advertised_port: u16,
}

#[derive(Clone)]
pub struct Config {
    pub listen: SocketAddr,
    pub relay_ip: IpAddr,
    /// Inclusive UDP peer-relay range. None retains OS-assigned ephemeral ports.
    /// A configured range never falls back to an ephemeral port on exhaustion.
    pub relay_port_range: Option<(u16, u16)>,
    /// Explicit bounded UDP port pairs, mutually exclusive with a relay range.
    /// None retains range/ephemeral behaviour; Some must contain 1..=1024 pairs.
    /// Translation requires an explicit advertised_ip different from relay_ip.
    pub relay_port_mappings: Option<Vec<RelayPortMapping>>,
    pub advertised_ip: Option<IpAddr>,
    pub realm: String,
    pub secret: Vec<u8>,
    /// Explicit local testing opt-in, never enabled by default.
    pub allow_loopback_peers: bool,
    /// Explicit local bridge domain: 127.64.0.0/10 on the configured relay ports.
    /// The client listener is a concrete IPv4 address; the bridge owns peer transport.
    pub local_peer_bridge: bool,
    /// Authorised virtual peer aliases, changed by the embedding bridge host.
    pub bridge_peer_ips: HashSet<std::net::Ipv4Addr>,
    pub max_allocations: usize,
    pub max_per_user: usize,
    pub max_connections: usize,
    /// Maximum lease returned by Allocate or Refresh, in seconds (1..=3600).
    /// This never extends the authenticated username's own expiry.
    pub max_allocation_lifetime: u32,
    /// Aggregate bytes across both directions per allocation.
    pub bytes_per_second: u64,
    /// Relayed payload bytes per second, both directions, summed over every
    /// allocation. None leaves the total unlimited; Some must be non-zero.
    /// The per-allocation limit still applies first.
    pub aggregate_bytes_per_second: Option<u64>,
    /// Optional live admission check for issued usernames. The host must keep
    /// this callback bounded and non-blocking. Losing its state must deny.
    pub credential_authorizer: Option<CredentialAuthorizer>,
    #[cfg(feature = "tls")]
    pub tls: Option<(SocketAddr, Arc<rustls::ServerConfig>)>,
}

#[cfg(test)]
mod policy_tests;

impl Config {
    pub fn local(secret: Vec<u8>) -> Self {
        Self {
            listen: "127.0.0.1:3478".parse().expect("literal"),
            relay_ip: "127.0.0.1".parse().expect("literal"),
            relay_port_range: None,
            relay_port_mappings: None,
            advertised_ip: None,
            realm: "spry-turn".into(),
            secret,
            allow_loopback_peers: false,
            local_peer_bridge: false,
            bridge_peer_ips: HashSet::new(),
            max_allocations: 1024,
            max_per_user: 8,
            max_connections: 256,
            max_allocation_lifetime: 3600,
            bytes_per_second: 64 * 1024 * 1024,
            aggregate_bytes_per_second: None,
            credential_authorizer: None,
            #[cfg(feature = "tls")]
            tls: None,
        }
    }
}

#[derive(Clone, Copy, Debug, Hash, Eq, PartialEq)]
enum Client {
    Datagram(SocketAddr),
    Stream(Token),
}

/// Aggregate relay accounting only. No client address, username or peer is
/// retained here. Stream payload accepted into a bounded output queue is
/// counted as forwarded; it is not proof of delivery to a remote application.
#[derive(Clone, Copy, Debug, Default)]
pub struct RelayMetrics {
    pub udp_allocations: usize,
    pub stream_allocations: usize,
    pub stream_connections: usize,
    pub udp_forwarded_bytes: u64,
    pub stream_forwarded_bytes: u64,
    pub forwarded_packets: u64,
    pub dropped_packets: u64,
    pub stream_errors: u64,
    pub refused_streams: u64,
    pub allocation_quota_refusals: u64,
    pub user_quota_refusals: u64,
    pub relay_bind_failures: u64,
    /// Requests refused by the budget for UDP sources without a nonce, or by
    /// a source's allowance within it.
    pub unverified_request_refusals: u64,
    /// Requests refused by the budget for TCP/TLS, loopback and nonce-bearing
    /// UDP sources, or by a source's allowance within it.
    pub verified_request_refusals: u64,
}

#[derive(Default)]
struct TransportCounters {
    udp_bytes: u64,
    stream_bytes: u64,
    stream_errors: u64,
    refused_streams: u64,
    allocation_quota_refusals: u64,
    user_quota_refusals: u64,
    relay_bind_failures: u64,
    unverified_request_refusals: u64,
    verified_request_refusals: u64,
}

/// Generation-tagged slots for internally assigned readiness tokens. Client
/// addresses still use a keyed map; no untrusted input is used as a slot index.
#[cfg(feature = "direct-index")]
#[derive(Default)]
struct RelaySlots {
    entries: Vec<(Token, Option<Client>)>,
    free: Vec<usize>,
}

#[cfg(feature = "direct-index")]
impl RelaySlots {
    const BITS: usize = usize::BITS as usize / 2;
    const MASK: usize = (1usize << Self::BITS) - 1;

    fn reserve(&mut self, client: Client) -> Token {
        let index = if let Some(index) = self.free.pop() {
            self.entries[index].0.0 = self.entries[index].0.0.wrapping_add(1usize << Self::BITS);
            index
        } else {
            let index = self.entries.len();
            self.entries.push((Token((index + 1) << 2), None));
            index
        };
        self.entries[index].1 = Some(client);
        self.entries[index].0
    }

    fn index(token: Token) -> Option<usize> {
        if token.0 & 1 != 0 {
            return None;
        }
        ((token.0 & Self::MASK) >> 2).checked_sub(1)
    }

    fn get(&self, token: &Token) -> Option<&Client> {
        let slot = self.entries.get(Self::index(*token)?)?;
        if slot.0 != Token(token.0 & !2) {
            return None;
        }
        slot.1.as_ref()
    }

    fn remove(&mut self, token: &Token) -> Option<Client> {
        let index = Self::index(*token)?;
        let slot = self.entries.get_mut(index)?;
        if slot.0 != Token(token.0 & !2) {
            return None;
        }
        let client = slot.1.take()?;
        self.free.push(index);
        Some(client)
    }
}

struct Permission {
    ip: IpAddr,
    expires: Instant,
}
struct Channel {
    number: u16,
    peer: SocketAddr,
    expires: Instant,
}
struct Allocation {
    socket: UdpSocket,
    #[cfg(feature = "connected-udp")]
    client_socket: Option<UdpSocket>,
    token: Token,
    bound_address: SocketAddr,
    advertised_address: SocketAddr,
    username: String,
    transaction: [u8; 12],
    expires: Instant,
    permissions: Vec<Permission>,
    channels: Vec<Channel>,
    bandwidth: Bucket,
    /// Control requests this client may make whatever other sources send.
    requests: Bucket,
}

enum StreamRead {
    Data,
    Pending,
    Closed,
    Yielded,
}

struct StreamBudget {
    reads: usize,
    bytes: usize,
    frames: usize,
}

impl StreamBudget {
    fn new() -> Self {
        Self {
            reads: STREAM_READS_PER_TURN,
            bytes: STREAM_BYTES_PER_TURN,
            frames: STREAM_FRAMES_PER_TURN,
        }
    }

    fn take_read(&mut self) -> bool {
        if self.reads == 0 || self.bytes == 0 {
            return false;
        }
        self.reads -= 1;
        true
    }
}

struct Connection {
    socket: TcpStream,
    peer: SocketAddr,
    input: Vec<u8>,
    input_offset: usize,
    output: Vec<u8>,
    written: usize,
    writable_interest: bool,
    queued: bool,
    last_active: Instant,
    created: Instant,
    #[cfg(feature = "tls")]
    tls: Option<rustls::ServerConnection>,
}

impl Connection {
    fn update_interest(
        &mut self,
        registry: &mio::Registry,
        token: Token,
        pending: bool,
    ) -> io::Result<()> {
        // Read interest stays enabled. Re-register only when backpressure
        // changes write interest, rather than making a kernel call per packet.
        if self.writable_interest != pending {
            let interest = if pending {
                Interest::READABLE | Interest::WRITABLE
            } else {
                Interest::READABLE
            };
            registry.reregister(&mut self.socket, token, interest)?;
            self.writable_interest = pending;
        }
        Ok(())
    }

    fn queue(&mut self, bytes: &[u8]) -> io::Result<()> {
        if self.output.len() - self.written + bytes.len() > MAX_QUEUE {
            return Err(io::Error::other("stream output limit"));
        }
        if self.written != 0 && self.output.len() + bytes.len() > MAX_QUEUE {
            self.output.drain(..self.written);
            self.written = 0;
        }
        self.output.extend_from_slice(bytes);
        self.last_active = Instant::now();
        Ok(())
    }

    fn read(&mut self, scratch: &mut [u8], budget: &mut StreamBudget) -> io::Result<StreamRead> {
        // Leave the consumed prefix in place on a frame-budget yield; compact
        // only when another read needs space, avoiding a copy per frame.
        if self.input_offset == self.input.len() {
            self.input.clear();
        } else if self.input_offset != 0 {
            self.input.drain(..self.input_offset);
        }
        self.input_offset = 0;
        loop {
            if !budget.take_read() {
                return Ok(StreamRead::Yielded);
            }
            let capacity = MAX_QUEUE
                .saturating_sub(self.input.len())
                .min(scratch.len())
                .min(budget.bytes);
            if capacity == 0 {
                return Err(io::Error::other("stream input limit"));
            }
            let scratch = &mut scratch[..capacity];
            #[cfg(feature = "tls")]
            if let Some(tls) = &mut self.tls {
                // A prior TLS read can leave decoded records behind a yield.
                // Drain them before waiting for another socket readiness edge.
                match tls.reader().read(scratch) {
                    Ok(0) => return Ok(StreamRead::Closed),
                    Ok(n) => {
                        self.input.extend_from_slice(&scratch[..n]);
                        budget.bytes -= n;
                        self.last_active = Instant::now();
                        return Ok(StreamRead::Data);
                    }
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => (),
                    Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                    Err(e) => return Err(e),
                }
                if !budget.take_read() {
                    return Ok(StreamRead::Yielded);
                }
                // Charge encrypted/control work too. A nonzero capacity keeps
                // this bounded reader from turning an exhausted budget into EOF.
                let mut socket = (&mut self.socket).take(capacity as u64);
                match tls.read_tls(&mut socket) {
                    Ok(0) => return Ok(StreamRead::Closed),
                    Ok(n) => {
                        budget.bytes -= n;
                        tls.process_new_packets().map_err(io::Error::other)?;
                        self.last_active = Instant::now();
                    }
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                        return Ok(StreamRead::Pending);
                    }
                    Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                    Err(e) => return Err(e),
                }
                continue;
            }
            match self.socket.read(scratch) {
                Ok(0) => return Ok(StreamRead::Closed),
                Ok(n) => {
                    self.input.extend_from_slice(&scratch[..n]);
                    budget.bytes -= n;
                    self.last_active = Instant::now();
                    return Ok(StreamRead::Data);
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    return Ok(StreamRead::Pending);
                }
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e),
            }
        }
    }

    fn flush(&mut self) -> io::Result<bool> {
        #[cfg(feature = "tls")]
        if self.tls.is_some() {
            return self.flush_tls();
        }
        while self.written < self.output.len() {
            match self.socket.write(&self.output[self.written..]) {
                Ok(0) => break,
                Ok(n) => self.written += n,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e),
            }
        }
        if self.written == self.output.len() {
            self.output.clear();
            self.written = 0;
        }
        Ok(!self.output.is_empty())
    }

    #[cfg(feature = "tls")]
    fn flush_tls(&mut self) -> io::Result<bool> {
        let tls = self.tls.as_mut().expect("TLS checked by flush");
        loop {
            while self.written < self.output.len() {
                match tls.writer().write(&self.output[self.written..]) {
                    Ok(0) => break,
                    Ok(n) => self.written += n,
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                    Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                    Err(e) => return Err(e),
                }
            }
            if self.written == self.output.len() {
                self.output.clear();
                self.written = 0;
            }
            let mut ciphertext_progress = false;
            while tls.wants_write() {
                match tls.write_tls(&mut self.socket) {
                    Ok(0) => return Ok(true),
                    Ok(_) => ciphertext_progress = true,
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => return Ok(true),
                    Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                    Err(e) => return Err(e),
                }
            }
            if self.output.is_empty() || !ciphertext_progress || tls.is_handshaking() {
                return Ok(!self.output.is_empty());
            }
            // Draining TLS records freed its writer's bounded capacity. Retry
            // the existing application queue before waiting for another edge.
            // No new application bytes enter this call; blocked/no-progress or
            // pre-handshake states above always return to the event loop.
        }
    }
}

/// Embed this server and drive `poll_once`, or use the standalone executable.
/// No room IDs, participant list, discovery, media keys or hosted defaults.
pub struct Server {
    config: Config,
    poll: Poll,
    events: Events,
    listener: UdpSocket,
    tcp: TcpListener,
    #[cfg(feature = "tls")]
    tls_listener: Option<TcpListener>,
    allocations: HashMap<Client, Allocation>,
    #[cfg(not(feature = "direct-index"))]
    relays: HashMap<Token, Client>,
    #[cfg(feature = "direct-index")]
    relays: RelaySlots,
    relay_ports: HashSet<u16>,
    advertised_relay_ports: HashSet<u16>,
    /// Live allocations' advertised relay port to local relay port, and back.
    own_public_to_local: HashMap<u16, u16>,
    own_local_to_public: HashMap<u16, u16>,
    next_relay_mapping: usize,
    next_relay_port: u16,
    connections: HashMap<Token, Connection>,
    // Empty storage lent to one plain TCP peer receive dispatch at a time.
    tcp_return_output: Vec<u8>,
    pending_streams: VecDeque<Token>,
    next_token: usize,
    nonces: auth::Nonces,
    /// Budget for address-verified sources; see `admit_request`.
    requests: Bucket,
    /// Budget for UDP sources that have not shown a nonce.
    unverified: Bucket,
    verified_sources: SourceTable,
    unverified_sources: SourceTable,
    /// Seeds the hash that chooses a source's table slot.
    sources: RandomState,
    /// Origin of the nanosecond clock the per-source tables run on.
    epoch: Instant,
    sweep_at: Instant,
    policy_at: Instant,
    input: Vec<u8>,
    stats: Stats,
    transport: TransportCounters,
    /// One bucket shared by every allocation, when configured.
    aggregate: Option<Bucket>,
    /// Unix seconds of the newest allocation made from a non-local address.
    last_remote_allocation: Option<u64>,
}

/// Most connections without an allocation that one source may hold: half of
/// `max_connections`, rounded down, and at least one.
fn unauthenticated_cap(max_connections: usize) -> usize {
    (max_connections / 2).max(1)
}

/// The key under which connections and requests from one source share a cap
/// or allowance. IPv4-mapped IPv6 addresses count as IPv4, and other IPv6
/// addresses are grouped by /64, matching how the service groups callers for
/// its own rate limits.
fn connection_source(ip: IpAddr) -> IpAddr {
    match ip.to_canonical() {
        IpAddr::V6(ip) => {
            let [a, b, c, d, ..] = ip.segments();
            IpAddr::V6(std::net::Ipv6Addr::new(a, b, c, d, 0, 0, 0, 0))
        }
        ip => ip,
    }
}

/// Whether an allocation's client address counts as someone else's device:
/// not loopback, unspecified, private, link-local or unique-local, and not
/// this relay's own bind or advertised address (a host reaching its own relay
/// through the router shows up as one of those).
pub fn remote_client(ip: IpAddr, config: &Config) -> bool {
    let ip = ip.to_canonical();
    if ip == config.relay_ip.to_canonical()
        || config
            .advertised_ip
            .is_some_and(|own| own.to_canonical() == ip)
    {
        return false;
    }
    match ip {
        IpAddr::V4(ip) => {
            !(ip.is_unspecified()
                || ip.is_loopback()
                || ip.is_private()
                || ip.is_link_local()
                || ip.is_multicast()
                || ip.is_broadcast())
        }
        IpAddr::V6(ip) => {
            !(ip.is_unspecified()
                || ip.is_loopback()
                || ip.is_multicast()
                || ip.segments()[0] & 0xfe00 == 0xfc00
                || ip.segments()[0] & 0xffc0 == 0xfe80)
        }
    }
}

pub fn unix_time() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn credential_lifetime(username: &str, requested: u32, now: SystemTime) -> Duration {
    let remaining = auth::expires(username)
        .and_then(|expiry| UNIX_EPOCH.checked_add(Duration::from_secs(expiry)))
        .and_then(|deadline| deadline.duration_since(now).ok())
        .unwrap_or_default();
    Duration::from_secs(u64::from(requested)).min(remaining)
}

impl Server {
    fn bind_listener(address: SocketAddr) -> io::Result<UdpSocket> {
        #[cfg(all(feature = "connected-udp", unix))]
        {
            let socket = socket2::Socket::new(
                socket2::Domain::for_address(address),
                socket2::Type::DGRAM,
                Some(socket2::Protocol::UDP),
            )?;
            socket.set_reuse_port(true)?;
            socket.set_nonblocking(true)?;
            socket.bind(&address.into())?;
            Ok(UdpSocket::from_std(socket.into()))
        }
        #[cfg(not(all(feature = "connected-udp", unix)))]
        {
            UdpSocket::bind(address)
        }
    }

    /// Binds the UDP listener and a TCP listener on the same port.
    ///
    /// With port 0 the system offers a port for one protocol and the same
    /// number can be held by an unrelated socket for the other, or reserved,
    /// which Windows reports as a permission error. Windows also offers ports
    /// in sequence and reserves them in blocks, so asking the same protocol
    /// again can be refused many times running. Attempts therefore alternate
    /// which protocol takes the offer. A configured port is tried once: a
    /// clash there is the operator's to resolve.
    fn bind_listeners(address: SocketAddr) -> io::Result<(UdpSocket, TcpListener)> {
        let attempts = if address.port() == 0 { 8 } else { 1 };
        let mut attempt = 1;
        loop {
            let bound = if attempt % 2 == 1 {
                Self::bind_listener(address).and_then(|listener| {
                    let tcp = TcpListener::bind(listener.local_addr()?)?;
                    Ok((listener, tcp))
                })
            } else {
                TcpListener::bind(address)
                    .and_then(|tcp| Ok((Self::bind_listener(tcp.local_addr()?)?, tcp)))
            };
            match bound {
                Ok(pair) => return Ok(pair),
                Err(error)
                    if attempt < attempts
                        && matches!(
                            error.kind(),
                            io::ErrorKind::AddrInUse | io::ErrorKind::PermissionDenied
                        ) =>
                {
                    attempt += 1;
                }
                Err(error) => return Err(error),
            }
        }
    }

    #[cfg(feature = "connected-udp")]
    fn connected_client(&self, client: Client, token: Token) -> Option<UdpSocket> {
        #[cfg(unix)]
        {
            let Client::Datagram(peer) = client else {
                return None;
            };
            let address = self.listener.local_addr().ok()?;
            // A concrete IPv4 bind preserves the exact client-facing 5-tuple.
            // Wildcard and IPv6 listeners retain the standard portable path.
            if !address.is_ipv4() || address.ip().is_unspecified() || !peer.is_ipv4() {
                return None;
            }
            let socket = socket2::Socket::new(
                socket2::Domain::IPV4,
                socket2::Type::DGRAM,
                Some(socket2::Protocol::UDP),
            )
            .ok()?;
            socket.set_reuse_port(true).ok()?;
            socket.set_nonblocking(true).ok()?;
            socket.bind(&address.into()).ok()?;
            socket.connect(&peer.into()).ok()?;
            let mut socket = UdpSocket::from_std(socket.into());
            self.poll
                .registry()
                .register(&mut socket, Token(token.0 | 2), Interest::READABLE)
                .ok()?;
            Some(socket)
        }
        #[cfg(not(unix))]
        {
            let _ = (client, token);
            None
        }
    }

    #[cfg(feature = "connected-udp")]
    fn receive_client_socket(&mut self, token: Token, input: &mut [u8]) {
        let Some(client) = self.relays.get(&token).copied() else {
            return;
        };
        let Client::Datagram(peer) = client else {
            return;
        };
        loop {
            let Some(socket) = self
                .allocations
                .get_mut(&client)
                .and_then(|a| a.client_socket.as_mut())
            else {
                return;
            };
            let n = match socket.recv(input) {
                Ok(n) => n,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(_) => return,
            };
            self.receive(client, peer, &input[..n]);
        }
    }

    pub fn bind(config: Config) -> io::Result<Self> {
        if let Some(mappings) = &config.relay_port_mappings {
            let mut local = HashSet::new();
            let mut advertised = HashSet::new();
            if mappings.is_empty()
                || mappings.len() > MAX_RELAY_PORT_MAPPINGS
                || config.relay_port_range.is_some()
                || config.local_peer_bridge
                || mappings.iter().any(|mapping| {
                    mapping.local_port == 0
                        || mapping.advertised_port == 0
                        || !local.insert(mapping.local_port)
                        || !advertised.insert(mapping.advertised_port)
                        || (mapping.local_port == config.listen.port()
                            && (config.listen.ip().is_unspecified()
                                || config.listen.ip() == config.relay_ip))
                })
            {
                return Err(io::Error::other(
                    "relay port mappings require 1..=1024 unique nonzero local/public ports, no listener collision, range or peer bridge",
                ));
            }
            if mappings
                .iter()
                .any(|mapping| mapping.local_port != mapping.advertised_port)
                && config.advertised_ip.is_none_or(|ip| ip == config.relay_ip)
            {
                return Err(io::Error::other(
                    "translated relay ports require an explicit advertised IP different from the local relay IP",
                ));
            }
        }
        if config
            .relay_port_range
            .is_some_and(|(first, last)| first == 0 || first > last)
        {
            return Err(io::Error::other(
                "relay ports require 1 <= first <= last <= 65535",
            ));
        }
        #[cfg(feature = "direct-index")]
        if config.max_allocations > (RelaySlots::MASK >> 2) - 1 {
            return Err(io::Error::other(
                "allocation limit exceeds readiness slot capacity",
            ));
        }
        if config.secret.len() < 32
            || config.realm.is_empty()
            || config.realm.len() > 128
            || config.relay_ip.is_unspecified()
            || config.max_allocations == 0
            || config.max_per_user == 0
            || config.max_connections == 0
            || !(1..=3600).contains(&config.max_allocation_lifetime)
            || config.bytes_per_second == 0
            || config.aggregate_bytes_per_second == Some(0)
        {
            return Err(io::Error::other(
                "invalid configuration (secret requires at least 32 bytes)",
            ));
        }
        if config
            .advertised_ip
            .is_some_and(|ip| ip.is_ipv4() != config.relay_ip.is_ipv4() || ip.is_unspecified())
        {
            return Err(io::Error::other(
                "advertised address must match relay address family",
            ));
        }
        if config.local_peer_bridge
            && (!matches!(config.listen.ip(), IpAddr::V4(ip) if !ip.is_unspecified() && !ip.is_multicast() && !ip.is_broadcast())
                || !local_bridge_address(config.relay_ip)
                || config.relay_port_range.is_none()
                || config.allow_loopback_peers
                || config.bridge_peer_ips.len() > 8
                || config.bridge_peer_ips.iter().any(|ip| {
                    !local_bridge_address(IpAddr::V4(*ip)) || IpAddr::V4(*ip) == config.relay_ip
                })
                || config.advertised_ip.is_some_and(|ip| ip != config.relay_ip))
        {
            return Err(io::Error::other(
                "peer bridging requires a concrete IPv4 listener, a virtual relay address and bounded peer aliases/ports",
            ));
        }
        #[cfg(feature = "tls")]
        if config.local_peer_bridge
            && config
                .tls
                .as_ref()
                .is_some_and(|(address, _)| !address.ip().is_loopback())
        {
            return Err(io::Error::other(
                "local peer bridging requires loopback TLS",
            ));
        }
        let poll = Poll::new()?;
        let (mut listener, mut tcp) = Self::bind_listeners(config.listen)?;
        poll.registry()
            .register(&mut listener, UDP, Interest::READABLE)?;
        poll.registry()
            .register(&mut tcp, TCP, Interest::READABLE)?;
        #[cfg(feature = "tls")]
        let tls_listener = if let Some((address, _)) = &config.tls {
            let mut listener = TcpListener::bind(*address)?;
            poll.registry()
                .register(&mut listener, TLS, Interest::READABLE)?;
            Some(listener)
        } else {
            None
        };
        let now = Instant::now();
        let next_relay_port = config.relay_port_range.map_or(0, |(first, _)| first);
        let aggregate = config
            .aggregate_bytes_per_second
            .map(|rate| Bucket::new(rate, rate, now));
        Ok(Self {
            config,
            poll,
            events: Events::with_capacity(1024),
            listener,
            tcp,
            #[cfg(feature = "tls")]
            tls_listener,
            allocations: HashMap::new(),
            relays: Default::default(),
            relay_ports: HashSet::new(),
            advertised_relay_ports: HashSet::new(),
            own_public_to_local: HashMap::new(),
            own_local_to_public: HashMap::new(),
            next_relay_mapping: 0,
            next_relay_port,
            connections: HashMap::new(),
            tcp_return_output: Vec::new(),
            pending_streams: VecDeque::new(),
            next_token: 3,
            nonces: auth::Nonces::new()
                .map_err(|_| io::Error::other("OS randomness unavailable"))?,
            requests: Bucket::new(VERIFIED_REQUESTS_PER_SECOND, VERIFIED_REQUEST_BURST, now),
            unverified: Bucket::new(
                UNVERIFIED_REQUESTS_PER_SECOND,
                UNVERIFIED_REQUEST_BURST,
                now,
            ),
            verified_sources: SourceTable::new(
                SOURCE_SLOTS,
                VERIFIED_SOURCE_PER_SECOND,
                VERIFIED_SOURCE_BURST,
            ),
            unverified_sources: SourceTable::new(
                SOURCE_SLOTS,
                UNVERIFIED_SOURCE_PER_SECOND,
                UNVERIFIED_SOURCE_BURST,
            ),
            sources: RandomState::new(),
            epoch: now,
            sweep_at: now + SWEEP_INTERVAL,
            policy_at: now,
            input: vec![0; MAX_PACKET + HEADROOM],
            stats: Stats::default(),
            transport: TransportCounters::default(),
            aggregate,
            last_remote_allocation: None,
        })
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.listener.local_addr()
    }
    pub fn stats(&self) -> Stats {
        self.stats
    }
    pub fn allocation_count(&self) -> usize {
        self.allocations.len()
    }
    pub fn relay_metrics(&self) -> RelayMetrics {
        let udp_allocations = self
            .allocations
            .keys()
            .filter(|client| matches!(client, Client::Datagram(_)))
            .count();
        RelayMetrics {
            udp_allocations,
            stream_allocations: self.allocations.len() - udp_allocations,
            stream_connections: self.connections.len(),
            udp_forwarded_bytes: self.transport.udp_bytes,
            stream_forwarded_bytes: self.transport.stream_bytes,
            forwarded_packets: self.stats.forwarded_packets,
            dropped_packets: self.stats.dropped_packets,
            stream_errors: self.transport.stream_errors,
            refused_streams: self.transport.refused_streams,
            allocation_quota_refusals: self.transport.allocation_quota_refusals,
            user_quota_refusals: self.transport.user_quota_refusals,
            relay_bind_failures: self.transport.relay_bind_failures,
            unverified_request_refusals: self.transport.unverified_request_refusals,
            verified_request_refusals: self.transport.verified_request_refusals,
        }
    }
    fn forwarded(&mut self, client: Client, bytes: usize) {
        self.forwarded_batch(client, 1, bytes);
    }
    fn forwarded_batch(&mut self, client: Client, frames: usize, bytes: usize) {
        self.stats.forwarded_packets += frames as u64;
        self.stats.forwarded_bytes += bytes as u64;
        let counter = match client {
            Client::Datagram(_) => &mut self.transport.udp_bytes,
            Client::Stream(_) => &mut self.transport.stream_bytes,
        };
        *counter = counter.saturating_add(bytes as u64);
    }
    fn fail_stream(&mut self, token: Token) {
        self.transport.stream_errors = self.transport.stream_errors.saturating_add(1);
        self.close(token);
    }
    /// Unix seconds of the newest allocation whose client was not a local
    /// address (see [`remote_client`]), or None if there has been none.
    /// Only the time is kept, never the address.
    pub fn last_remote_allocation(&self) -> Option<u64> {
        self.last_remote_allocation
    }

    /// Admit a relayed payload against the allocation's own bucket and then
    /// the shared aggregate bucket. A packet the aggregate refuses gives the
    /// allocation's tokens back, so the total cap cannot also exhaust one
    /// allocation's own allowance.
    fn within_budget(
        allocation: &mut Bucket,
        aggregate: &mut Option<Bucket>,
        amount: usize,
        now: Instant,
    ) -> bool {
        if !allocation.take(amount, now) {
            return false;
        }
        if aggregate
            .as_mut()
            .is_some_and(|total| !total.take(amount, now))
        {
            allocation.give_back(amount);
            return false;
        }
        true
    }

    /// Update only the explicitly configured bridge's authorised peer aliases.
    pub fn set_bridge_peer_ips(&mut self, peers: HashSet<std::net::Ipv4Addr>) -> io::Result<()> {
        if !self.config.local_peer_bridge
            || peers.len() > 8
            || peers.iter().any(|ip| {
                !local_bridge_address(IpAddr::V4(*ip)) || IpAddr::V4(*ip) == self.config.relay_ip
            })
        {
            return Err(io::Error::other("invalid bridge peer aliases"));
        }
        self.config.bridge_peer_ips = peers;
        // Previously installed permissions cannot outlive an alias withdrawal.
        for allocation in self.allocations.values_mut() {
            allocation.permissions.retain(|permission| {
                self.config.bridge_peer_ips.contains(&match permission.ip {
                    IpAddr::V4(ip) => ip,
                    _ => return false,
                }) || permission.ip == self.config.relay_ip
            });
            allocation.channels.retain(|channel| {
                self.config
                    .bridge_peer_ips
                    .contains(&match channel.peer.ip() {
                        IpAddr::V4(ip) => ip,
                        _ => return false,
                    })
                    || channel.peer.ip() == self.config.relay_ip
            });
        }
        Ok(())
    }

    /// Active relay ports for an embedding adapter's destination checks.
    pub fn allocated_relay_ports(&self) -> impl Iterator<Item = u16> + '_ {
        self.relay_ports.iter().copied()
    }

    fn token(&mut self) -> Token {
        #[cfg(not(feature = "direct-index"))]
        let token = Token(self.next_token);
        #[cfg(feature = "direct-index")]
        let token = Token((self.next_token << 2) | 3);
        self.next_token += 1;
        token
    }

    fn is_relay(&self, token: Token) -> bool {
        #[cfg(feature = "direct-index")]
        {
            token.0 & 3 == 0
        }
        #[cfg(not(feature = "direct-index"))]
        {
            self.relays.contains_key(&token)
        }
    }

    pub fn poll_once(&mut self, timeout: Duration) -> io::Result<()> {
        self.revoke_unauthorised();
        let timeout = if self.config.credential_authorizer.is_some() {
            timeout.min(Duration::from_millis(50))
        } else {
            timeout
        };
        let mut events = std::mem::replace(&mut self.events, Events::with_capacity(0));
        let wait = if self.pending_streams.is_empty() {
            timeout.min(self.sweep_at.saturating_duration_since(Instant::now()))
        } else {
            Duration::ZERO
        };
        if let Err(e) = self.poll.poll(&mut events, Some(wait)) {
            self.events = events;
            return if e.kind() == io::ErrorKind::Interrupted {
                Ok(())
            } else {
                Err(e)
            };
        }
        let mut input = std::mem::take(&mut self.input);
        for event in &events {
            let token = event.token();
            if token == UDP {
                loop {
                    match self.listener.recv_from(&mut input) {
                        Ok((n, peer)) => self.receive(Client::Datagram(peer), peer, &input[..n]),
                        Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                        Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                        Err(_) => break,
                    }
                }
            } else if token == TCP || token == TLS {
                self.accept(token);
            } else if self.is_relay(token) {
                self.receive_peer(token, &mut input);
            } else if cfg!(feature = "connected-udp") && token.0 & 3 == 2 {
                #[cfg(feature = "connected-udp")]
                self.receive_client_socket(token, &mut input);
            } else {
                self.queue_stream(token);
            }
        }
        // A yielded stream waits until the next poll, so each ready client and
        // expiry sweep gets a turn even when one stream stays continuously hot.
        let ready_streams = self.pending_streams.len();
        for _ in 0..ready_streams {
            let Some(token) = self.pending_streams.pop_front() else {
                break;
            };
            if let Some(conn) = self.connections.get_mut(&token) {
                conn.queued = false;
            }
            self.stream(token, &mut input);
        }
        self.input = input;
        self.events = events;
        if Instant::now() >= self.sweep_at {
            self.sweep();
        }
        Ok(())
    }

    fn send_client(&mut self, client: Client, bytes: &[u8]) {
        // Check the externally observable teardown boundary in unit tests,
        // before any success bytes can reach a concurrently running client.
        #[cfg(test)]
        if Message::parse(bytes).is_some_and(|response| {
            response.method == REFRESH
                && response.class == 2
                && response.number(LIFETIME) == Some(0)
        }) {
            assert!(
                !self.allocations.contains_key(&client),
                "zero-lifetime success must follow allocation/socket teardown"
            );
        }
        self.send_client_packet(client, bytes, false);
    }

    /// Returns whether the whole packet was accepted. UDP relay overload drops
    /// the new packet; it must not truncate queued stream frames or allocations.
    fn send_client_packet(&mut self, client: Client, bytes: &[u8], relay_payload: bool) -> bool {
        self.send_client_packet_inner(client, bytes, relay_payload, false, false)
    }

    fn send_client_packet_inner(
        &mut self,
        client: Client,
        bytes: &[u8],
        relay_payload: bool,
        defer_tcp_return: bool,
        reuse_large_empty_output: bool,
    ) -> bool {
        match client {
            Client::Datagram(peer) => {
                #[cfg(feature = "connected-udp")]
                let result = if let Some(socket) = self
                    .allocations
                    .get(&client)
                    .and_then(|a| a.client_socket.as_ref())
                {
                    socket.send(bytes)
                } else {
                    self.listener.send_to(bytes, peer)
                };
                #[cfg(not(feature = "connected-udp"))]
                let result = self.listener.send_to(bytes, peer);
                if result.is_err() {
                    self.stats.dropped_packets += 1;
                    false
                } else {
                    true
                }
            }
            Client::Stream(token) => {
                let Some(conn) = self.connections.get_mut(&token) else {
                    if relay_payload {
                        self.stats.dropped_packets += 1;
                    }
                    return false;
                };
                let pending = conn.output.len() - conn.written;
                if relay_payload
                    && bytes.len() > (MAX_QUEUE - STREAM_CONTROL_RESERVE).saturating_sub(pending)
                {
                    // The socket may have recovered since its last WouldBlock,
                    // before this poll services its deferred writable event.
                    // Retry existing output once before dropping the new frame.
                    if conn
                        .flush()
                        .and_then(|pending| {
                            conn.update_interest(self.poll.registry(), token, pending)
                        })
                        .is_err()
                    {
                        self.fail_stream(token);
                        self.stats.dropped_packets += 1;
                        return false;
                    }
                }
                let pending = conn.output.len() - conn.written;
                if relay_payload
                    && bytes.len() > (MAX_QUEUE - STREAM_CONTROL_RESERVE).saturating_sub(pending)
                {
                    self.stats.dropped_packets += 1;
                    return false;
                }
                // Singleton returns normally fit the connection's existing
                // buffer. Only borrow for a large first frame that would
                // otherwise leave growth retained on an idle connection.
                let lent_output = relay_payload
                    && reuse_large_empty_output
                    && bytes.len() > conn.output.capacity()
                    && conn.output.is_empty()
                    && conn.written == 0
                    && {
                        #[cfg(feature = "tls")]
                        {
                            conn.tls.is_none()
                        }
                        #[cfg(not(feature = "tls"))]
                        {
                            true
                        }
                    };
                if lent_output {
                    debug_assert!(self.tcp_return_output.is_empty());
                    std::mem::swap(&mut conn.output, &mut self.tcp_return_output);
                }
                let result = conn.queue(bytes).and_then(|()| {
                    if defer_tcp_return {
                        Ok(false)
                    } else {
                        conn.flush()
                    }
                });
                let accepted = match result {
                    // The dispatch boundary flushes and updates readiness. Do
                    // not disable existing write interest for a deferred frame.
                    Ok(_) if defer_tcp_return => true,
                    Ok(pending) => {
                        if conn
                            .update_interest(self.poll.registry(), token, pending)
                            .is_err()
                        {
                            self.fail_stream(token);
                            false
                        } else {
                            true
                        }
                    }
                    Err(_) => {
                        self.fail_stream(token);
                        false
                    }
                };
                if !accepted && relay_payload {
                    self.stats.dropped_packets += 1;
                }
                if lent_output {
                    // A partial write retains the borrowed buffer and cursor;
                    // a fatal close has already released its owned storage.
                    self.swap_empty_peer_output(client);
                }
                accepted
            }
        }
    }

    /// Whether `ip`'s source already holds its share of connections that have
    /// no allocation. The share is half of `max_connections` (at least one),
    /// so one source cannot hold more than half the table unauthenticated.
    /// A connection stops counting when it gains an allocation and counts
    /// again if that allocation ends while the stream stays open. The count
    /// is derived from the live connection table, so there is no separate
    /// counter to leak. Runs on accept only, never per packet.
    fn source_at_unauthenticated_cap(&self, ip: IpAddr) -> bool {
        let cap = unauthenticated_cap(self.config.max_connections);
        if self.connections.len() < cap {
            return false;
        }
        let source = connection_source(ip);
        self.connections
            .iter()
            .filter(|(token, conn)| {
                connection_source(conn.peer.ip()) == source
                    && !self.allocations.contains_key(&Client::Stream(**token))
            })
            .count()
            >= cap
    }

    fn accept(&mut self, listener: Token) {
        loop {
            let accepted = if listener == TCP {
                self.tcp.accept()
            } else {
                #[cfg(feature = "tls")]
                {
                    let Some(tls) = &self.tls_listener else {
                        return;
                    };
                    tls.accept()
                }
                #[cfg(not(feature = "tls"))]
                {
                    return;
                }
            };
            let (mut socket, peer) = match accepted {
                Ok(value) => value,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(_) => break,
            };
            if self.connections.len() >= self.config.max_connections {
                self.transport.refused_streams = self.transport.refused_streams.saturating_add(1);
                continue;
            }
            if self.source_at_unauthenticated_cap(peer.ip()) {
                self.transport.refused_streams = self.transport.refused_streams.saturating_add(1);
                continue;
            }
            let token = self.token();
            if socket.set_nodelay(true).is_err()
                || self
                    .poll
                    .registry()
                    .register(&mut socket, token, Interest::READABLE)
                    .is_err()
            {
                self.transport.stream_errors = self.transport.stream_errors.saturating_add(1);
                continue;
            }
            let now = Instant::now();
            #[cfg(feature = "tls")]
            let tls = if listener == TLS {
                let Some((_, config)) = &self.config.tls else {
                    continue;
                };
                match rustls::ServerConnection::new(config.clone()) {
                    Ok(mut conn) => {
                        conn.set_buffer_limit(Some(MAX_QUEUE));
                        Some(conn)
                    }
                    Err(_) => {
                        self.transport.stream_errors =
                            self.transport.stream_errors.saturating_add(1);
                        continue;
                    }
                }
            } else {
                None
            };
            self.connections.insert(
                token,
                Connection {
                    socket,
                    peer,
                    input: Vec::with_capacity(4096),
                    input_offset: 0,
                    output: Vec::with_capacity(4096),
                    written: 0,
                    writable_interest: false,
                    queued: false,
                    last_active: now,
                    created: now,
                    #[cfg(feature = "tls")]
                    tls,
                },
            );
        }
    }

    fn queue_stream(&mut self, token: Token) {
        let Some(conn) = self.connections.get_mut(&token) else {
            return;
        };
        if !conn.queued {
            conn.queued = true;
            self.pending_streams.push_back(token);
        }
    }

    fn stream(&mut self, token: Token, scratch: &mut [u8]) {
        let mut budget = StreamBudget::new();
        let mut yielded = false;
        loop {
            let Some(conn) = self.connections.get_mut(&token) else {
                return;
            };
            let peer = conn.peer;
            let bytes = std::mem::take(&mut conn.input);
            let mut used = conn.input_offset;
            let mut invalid = false;
            while budget.frames != 0 {
                let Some(len) = wire::frame_len(&bytes[used..]) else {
                    break;
                };
                if len == 0 || len > MAX_PACKET {
                    invalid = true;
                    break;
                }
                if bytes.len() - used < len {
                    break;
                }
                self.receive(Client::Stream(token), peer, &bytes[used..used + len]);
                used += len;
                budget.frames -= 1;
                if !self.connections.contains_key(&token) {
                    return;
                }
            }
            if invalid {
                self.fail_stream(token);
                return;
            }
            if let Some(conn) = self.connections.get_mut(&token) {
                conn.input = bytes;
                conn.input_offset = used;
                if budget.frames == 0 {
                    yielded = true;
                    break;
                }
                match conn.read(scratch, &mut budget) {
                    Ok(StreamRead::Data) => (),
                    Ok(StreamRead::Pending) => break,
                    Ok(StreamRead::Yielded) => {
                        yielded = true;
                        break;
                    }
                    Ok(StreamRead::Closed) => {
                        self.close(token);
                        return;
                    }
                    Err(_) => {
                        self.fail_stream(token);
                        return;
                    }
                }
            }
        }
        if let Some(conn) = self.connections.get_mut(&token) {
            match conn.flush() {
                Ok(pending) => {
                    if conn
                        .update_interest(self.poll.registry(), token, pending)
                        .is_err()
                    {
                        self.fail_stream(token);
                    }
                }
                Err(_) => self.fail_stream(token),
            }
        }
        if yielded {
            self.queue_stream(token);
        }
    }

    fn close(&mut self, token: Token) {
        if let Some(mut conn) = self.connections.remove(&token) {
            if conn.queued {
                self.pending_streams.retain(|queued| *queued != token);
            }
            let _ = self.poll.registry().deregister(&mut conn.socket);
        }
        self.remove_allocation(Client::Stream(token));
    }

    fn remove_allocation(&mut self, client: Client) {
        if let Some(mut allocation) = self.allocations.remove(&client) {
            #[cfg(feature = "connected-udp")]
            if let Some(socket) = &mut allocation.client_socket {
                let _ = self.poll.registry().deregister(socket);
            }
            self.relay_ports.remove(&allocation.bound_address.port());
            self.advertised_relay_ports
                .remove(&allocation.advertised_address.port());
            self.own_public_to_local
                .remove(&allocation.advertised_address.port());
            self.own_local_to_public
                .remove(&allocation.bound_address.port());
            let _ = self.poll.registry().deregister(&mut allocation.socket);
            self.relays.remove(&allocation.token);
        }
    }

    /// Drop allocations whose live grant ended, without rotating a shared
    /// secret or interrupting other rooms. Every payload path also checks the
    /// policy, so a continuously readable socket cannot postpone revocation.
    fn revoke_unauthorised(&mut self) {
        self.policy_at = Instant::now() + Duration::from_millis(50);
        let Some(authorizer) = &self.config.credential_authorizer else {
            return;
        };
        let revoked: Vec<_> = self
            .allocations
            .iter()
            .filter_map(|(client, allocation)| {
                (!authorizer(&allocation.username)).then_some(*client)
            })
            .collect();
        for client in revoked {
            match client {
                Client::Stream(token) => self.close(token),
                Client::Datagram(_) => self.remove_allocation(client),
            }
        }
    }

    fn expire_allocations(&mut self, now: Instant) {
        let expired: Vec<_> = self
            .allocations
            .iter()
            .filter_map(|(c, a)| (a.expires <= now).then_some(*c))
            .collect();
        for client in expired {
            self.remove_allocation(client);
        }
    }

    fn sweep(&mut self) {
        let now = Instant::now();
        self.expire_allocations(now);
        for a in self.allocations.values_mut() {
            a.permissions.retain(|p| p.expires > now);
            a.channels.retain(|c| c.expires > now);
        }
        let expired: Vec<_> = self
            .connections
            .iter()
            .filter_map(|(t, c)| {
                let active = self.allocations.contains_key(&Client::Stream(*t));
                ((!active && now.duration_since(c.created) > Duration::from_secs(15))
                    || now.duration_since(c.last_active) > Duration::from_secs(600))
                .then_some(*t)
            })
            .collect();
        for token in expired {
            self.close(token);
        }
        self.sweep_at = now + SWEEP_INTERVAL;
    }
}

impl Server {
    fn error(
        &mut self,
        client: Client,
        peer: SocketAddr,
        message: &Message<'_>,
        code: u16,
        key: Option<&[u8]>,
    ) {
        let mut b = Builder::new(message.method, 3, message.transaction);
        let text = match code {
            400 => "Bad Request",
            401 => "Unauthorised",
            403 => "Forbidden",
            420 => "Unknown Attribute",
            437 => "Allocation Mismatch",
            438 => "Stale Nonce",
            440 => "Address Family Not Supported",
            441 => "Wrong Credentials",
            442 => "Unsupported Transport",
            443 => "Peer Address Family Mismatch",
            486 => "Allocation Quota Reached",
            _ => "Insufficient Capacity",
        };
        let mut value = vec![0, 0, (code / 100) as u8, (code % 100) as u8];
        value.extend_from_slice(text.as_bytes());
        b.attr(ERROR, &value);
        if code == 401 || code == 438 {
            b.attr(REALM, self.config.realm.as_bytes());
            b.attr(
                NONCE,
                self.nonces
                    .issue(unix_time(), peer.ip(), &self.config.realm)
                    .as_bytes(),
            );
        }
        self.send_client(client, &b.finish(key));
    }

    fn authenticate(
        &mut self,
        client: Client,
        peer: SocketAddr,
        m: &Message<'_>,
    ) -> Option<(String, [u8; 16])> {
        let Some(username) = m.attr(USERNAME).and_then(|b| std::str::from_utf8(b).ok()) else {
            self.error(client, peer, m, 401, None);
            return None;
        };
        if m.attr(REALM) != Some(self.config.realm.as_bytes())
            || auth::expires(username).is_none_or(|expiry| expiry <= unix_time())
            || self
                .config
                .credential_authorizer
                .as_ref()
                .is_some_and(|allow| !allow(username))
        {
            self.error(client, peer, m, 401, None);
            return None;
        }
        let password = auth::credential(&self.config.secret, username);
        let key = auth::key(username, &self.config.realm, &password);
        if !m.verify(&key) {
            self.error(client, peer, m, 401, None);
            return None;
        }
        if !m.attr(NONCE).is_some_and(|nonce| {
            self.nonces
                .valid(nonce, unix_time(), peer.ip(), &self.config.realm)
        }) {
            self.error(client, peer, m, 438, Some(&key));
            return None;
        }
        if self
            .allocations
            .get(&client)
            .is_some_and(|a| a.username != username)
        {
            self.error(client, peer, m, 441, Some(&key));
            return None;
        }
        Some((username.to_owned(), key))
    }

    /// The slot a source's allowance lives in, in both per-source tables.
    fn source_slot(&self, ip: IpAddr) -> usize {
        self.verified_sources
            .slot(self.sources.hash_one(connection_source(ip)))
    }

    /// Draws on the request budgets, which bound the integrity checks that
    /// requests without credentials can cause. Nothing here computes an HMAC.
    ///
    /// 1. A client that already holds an allocation first draws on its own
    ///    small budget, so it can refresh and add permissions whatever other
    ///    sources send. This is the only draw such a request makes while it
    ///    has tokens.
    /// 2. Otherwise the source is address-verified if it is a stream (the
    ///    handshake confirmed the address), is on loopback, or sent a UDP
    ///    request whose nonce passes the cheap keyed check for that address.
    ///    Verified sources draw on the shared verified budget. A source within
    ///    its own allowance may use all of it, including the reserve; one over
    ///    its allowance may use only what is left above the reserve. The
    ///    allowance is soft: it decides priority when the budget runs low, not
    ///    a limit.
    /// 3. Every other UDP request draws on the unverified budget, and on its
    ///    source's hard allowance within it.
    ///
    /// A source's allowance is restored when the shared budget then refuses,
    /// so a refusal never costs the source twice. `unix` is only read when a
    /// nonce has to be checked.
    fn admit_request(
        &mut self,
        client: Client,
        peer: SocketAddr,
        m: &Message<'_>,
        now: Instant,
        unix: impl FnOnce() -> u64,
    ) -> bool {
        if self
            .allocations
            .get_mut(&client)
            .is_some_and(|a| a.requests.take(1, now))
        {
            return true;
        }
        let verified = match client {
            Client::Stream(_) => true,
            Client::Datagram(_) => {
                peer.ip().to_canonical().is_loopback()
                    || m.attr(NONCE).is_some_and(|nonce| {
                        self.nonces
                            .check(nonce, unix(), peer.ip(), &self.config.realm)
                    })
            }
        };
        let slot = self.source_slot(peer.ip());
        let at =
            u64::try_from(now.saturating_duration_since(self.epoch).as_nanos()).unwrap_or(u64::MAX);
        if verified {
            let admitted = match self.verified_sources.take(slot, at) {
                Some(previous) => {
                    let admitted = self.requests.take(1, now);
                    if !admitted {
                        self.verified_sources.restore(slot, previous);
                    }
                    admitted
                }
                None => self.requests.take_above(1, VERIFIED_RESERVE, now),
            };
            if !admitted {
                self.transport.verified_request_refusals =
                    self.transport.verified_request_refusals.saturating_add(1);
            }
            admitted
        } else {
            let admitted = match self.unverified_sources.take(slot, at) {
                Some(previous) => {
                    let admitted = self.unverified.take(1, now);
                    if !admitted {
                        self.unverified_sources.restore(slot, previous);
                    }
                    admitted
                }
                None => false,
            };
            if !admitted {
                self.transport.unverified_request_refusals =
                    self.transport.unverified_request_refusals.saturating_add(1);
            }
            admitted
        }
    }

    fn receive(&mut self, client: Client, peer: SocketAddr, bytes: &[u8]) {
        if self.config.credential_authorizer.is_some() && Instant::now() >= self.policy_at {
            self.revoke_unauthorised();
        }
        if bytes.first().is_some_and(|b| b >> 6 == 1) {
            let Some((number, data)) = wire::channel(bytes) else {
                return;
            };
            let now = Instant::now();
            let Some(a) = self.allocations.get_mut(&client).filter(|a| {
                a.expires > now
                    && self
                        .config
                        .credential_authorizer
                        .as_ref()
                        .is_none_or(|allow| allow(&a.username))
            }) else {
                return;
            };
            let Some(channel) = a
                .channels
                .iter()
                .find(|c| c.number == number && c.expires > now)
            else {
                return;
            };
            if !Self::allowed_peer(
                &self.config,
                &self.relay_ports,
                &self.advertised_relay_ports,
                channel.peer,
            ) {
                self.stats.dropped_packets += 1;
                return;
            }
            if !a
                .permissions
                .iter()
                .any(|p| p.ip == channel.peer.ip() && p.expires > now)
                || !Self::within_budget(&mut a.bandwidth, &mut self.aggregate, data.len(), now)
            {
                self.stats.dropped_packets += 1;
                return;
            }
            let target =
                Self::own_local_target(&self.config, &self.own_public_to_local, channel.peer);
            if a.socket.send_to(data, target).is_ok() {
                self.forwarded(client, data.len());
            } else {
                self.stats.dropped_packets += 1;
            }
            return;
        }
        let Some(m) = Message::parse(bytes) else {
            return;
        };
        if m.class == 1 && m.method == SEND {
            self.send_indication(client, &m);
            return;
        }
        if m.class != 0 {
            return;
        }
        if !self.admit_request(client, peer, &m, Instant::now(), unix_time) {
            return;
        }
        if m.method == BINDING {
            let mut b = Builder::new(BINDING, 2, m.transaction);
            b.address(MAPPED, peer);
            self.send_client(client, &b.finish(None));
            return;
        }
        let Some((username, key)) = self.authenticate(client, peer, &m) else {
            return;
        };
        let mut unknown: Vec<u16> = Vec::new();
        for (typ, _) in m.attributes() {
            if typ < 0x8000
                && !matches!(
                    typ,
                    USERNAME
                        | REALM
                        | NONCE
                        | CHANNEL
                        | LIFETIME
                        | PEER
                        | DATA
                        | FAMILY
                        | TRANSPORT
                )
                && !unknown.contains(&typ)
            {
                unknown.push(typ);
            }
        }
        if !unknown.is_empty() {
            let mut b = Builder::new(m.method, 3, m.transaction);
            let mut error = vec![0, 0, 4, 20];
            error.extend_from_slice(b"Unknown Attribute");
            let unknown: Vec<u8> = unknown.iter().flat_map(|t| t.to_be_bytes()).collect();
            b.attr(ERROR, &error).attr(UNKNOWN, &unknown);
            self.send_client(client, &b.finish(Some(&key)));
            return;
        }
        match m.method {
            ALLOCATE => self.allocate(client, peer, &m, username, key),
            REFRESH | PERMISSION | CHANNEL_BIND => {
                if self
                    .allocations
                    .get(&client)
                    .is_none_or(|a| a.expires <= Instant::now())
                {
                    self.remove_allocation(client);
                    self.error(client, peer, &m, 437, Some(&key));
                    return;
                }
                match m.method {
                    REFRESH => self.refresh(client, peer, &m, key),
                    PERMISSION => self.permission(client, peer, &m, key),
                    _ => self.channel_bind(client, peer, &m, key),
                }
            }
            _ => self.error(client, peer, &m, 400, Some(&key)),
        }
    }

    fn allocate(
        &mut self,
        client: Client,
        peer: SocketAddr,
        m: &Message<'_>,
        username: String,
        key: [u8; 16],
    ) {
        if self
            .allocations
            .get(&client)
            .is_some_and(|a| a.expires <= Instant::now())
        {
            self.remove_allocation(client);
        }
        if let Some(a) = self.allocations.get(&client) {
            if a.transaction == m.transaction {
                self.allocated(client, peer, m, &key);
            } else {
                self.error(client, peer, m, 437, Some(&key));
            }
            return;
        }
        match m.attr(TRANSPORT) {
            Some([17, _, _, _]) => (),
            Some([_, _, _, _]) => {
                self.error(client, peer, m, 442, Some(&key));
                return;
            }
            _ => {
                self.error(client, peer, m, 400, Some(&key));
                return;
            }
        }
        let family = match m.attr(FAMILY) {
            None => 1,
            Some([family @ (1 | 2), _, _, _]) => *family,
            _ => {
                self.error(client, peer, m, 400, Some(&key));
                return;
            }
        };
        if (family == 1) != self.config.relay_ip.is_ipv4() {
            self.error(client, peer, m, 440, Some(&key));
            return;
        }
        // Timer sweeps are periodic. An authenticated replacement must not
        // lose quota or a bounded relay port to a lease that already ended.
        self.expire_allocations(Instant::now());
        if self.allocations.len() >= self.config.max_allocations {
            self.transport.allocation_quota_refusals =
                self.transport.allocation_quota_refusals.saturating_add(1);
            self.error(client, peer, m, 486, Some(&key));
            return;
        }
        if self
            .allocations
            .values()
            .filter(|a| a.username == username)
            .count()
            >= self.config.max_per_user
        {
            self.transport.user_quota_refusals =
                self.transport.user_quota_refusals.saturating_add(1);
            self.error(client, peer, m, 486, Some(&key));
            return;
        }
        let socket = self.bind_relay_socket();
        let Ok(mut socket) = socket else {
            self.transport.relay_bind_failures =
                self.transport.relay_bind_failures.saturating_add(1);
            self.error(client, peer, m, 508, Some(&key));
            return;
        };
        #[cfg(not(feature = "direct-index"))]
        let token = self.token();
        #[cfg(feature = "direct-index")]
        let token = self.relays.reserve(client);
        let address = socket.local_addr().and_then(|address| {
            self.poll
                .registry()
                .register(&mut socket, token, Interest::READABLE)?;
            Ok(address)
        });
        let Ok(bound_address) = address else {
            #[cfg(feature = "direct-index")]
            self.relays.remove(&token);
            self.error(client, peer, m, 508, Some(&key));
            return;
        };
        let mut advertised_address = bound_address;
        if let Some(ip) = self.config.advertised_ip {
            advertised_address.set_ip(ip);
        }
        if let Some(mappings) = &self.config.relay_port_mappings {
            // bind_relay_socket selects only validated entries from this map.
            let mapping = mappings
                .iter()
                .find(|mapping| mapping.local_port == bound_address.port())
                .expect("bound mapped port");
            advertised_address.set_port(mapping.advertised_port);
        }
        let now = Instant::now();
        let lifetime = credential_lifetime(
            &username,
            m.number(LIFETIME)
                .unwrap_or(600)
                .clamp(600, 3600)
                .min(self.config.max_allocation_lifetime),
            SystemTime::now(),
        );
        #[cfg(feature = "connected-udp")]
        let client_socket = self.connected_client(client, token);
        self.allocations.insert(
            client,
            Allocation {
                socket,
                #[cfg(feature = "connected-udp")]
                client_socket,
                token,
                bound_address,
                advertised_address,
                username,
                transaction: m.transaction,
                expires: now + lifetime,
                permissions: Vec::new(),
                channels: Vec::new(),
                bandwidth: Bucket::new(
                    self.config.bytes_per_second,
                    self.config.bytes_per_second,
                    now,
                ),
                requests: Bucket::new(
                    ALLOCATION_REQUESTS_PER_SECOND,
                    ALLOCATION_REQUEST_BURST,
                    now,
                ),
            },
        );
        self.relay_ports.insert(bound_address.port());
        self.advertised_relay_ports
            .insert(advertised_address.port());
        self.own_public_to_local
            .insert(advertised_address.port(), bound_address.port());
        self.own_local_to_public
            .insert(bound_address.port(), advertised_address.port());
        if remote_client(peer.ip(), &self.config) {
            self.last_remote_allocation = Some(unix_time());
        }
        #[cfg(not(feature = "direct-index"))]
        self.relays.insert(token, client);
        self.allocated(client, peer, m, &key);
    }

    fn bind_relay_socket(&mut self) -> io::Result<UdpSocket> {
        if let Some(mappings) = &self.config.relay_port_mappings {
            for _ in 0..mappings.len() {
                let mapping = mappings[self.next_relay_mapping];
                self.next_relay_mapping = (self.next_relay_mapping + 1) % mappings.len();
                if self.relay_ports.contains(&mapping.local_port) {
                    continue;
                }
                match UdpSocket::bind(SocketAddr::new(self.config.relay_ip, mapping.local_port)) {
                    Ok(socket) => return Ok(socket),
                    Err(error) if error.kind() == io::ErrorKind::AddrInUse => continue,
                    Err(error) => return Err(error),
                }
            }
            return Err(io::Error::new(
                io::ErrorKind::AddrInUse,
                "relay port mappings exhausted",
            ));
        }
        let Some((first, last)) = self.config.relay_port_range else {
            return UdpSocket::bind(SocketAddr::new(self.config.relay_ip, 0));
        };
        // Rotate through the bounded range once. Occupied host ports are skipped,
        // but neither capacity exhaustion nor a bind error widens the range.
        for _ in u32::from(first)..=u32::from(last) {
            let port = self.next_relay_port;
            self.next_relay_port = if port == last { first } else { port + 1 };
            if self.relay_ports.contains(&port) {
                continue;
            }
            match UdpSocket::bind(SocketAddr::new(self.config.relay_ip, port)) {
                Ok(socket) => return Ok(socket),
                Err(error) if error.kind() == io::ErrorKind::AddrInUse => continue,
                Err(error) => return Err(error),
            }
        }
        Err(io::Error::new(
            io::ErrorKind::AddrInUse,
            "relay port range exhausted",
        ))
    }

    fn allocated(&mut self, client: Client, peer: SocketAddr, m: &Message<'_>, key: &[u8]) {
        let Some(a) = self.allocations.get(&client) else {
            return;
        };
        let lifetime = a
            .expires
            .saturating_duration_since(Instant::now())
            .as_secs()
            .saturating_add(1)
            .min(3600) as u32;
        let mut b = Builder::new(ALLOCATE, 2, m.transaction);
        b.address(RELAYED, a.advertised_address)
            .address(MAPPED, peer)
            .number(LIFETIME, lifetime)
            .attr(SOFTWARE, b"spry-turn");
        self.send_client(client, &b.finish(Some(key)));
    }

    fn refresh(&mut self, client: Client, peer: SocketAddr, m: &Message<'_>, key: [u8; 16]) {
        let a = self
            .allocations
            .get_mut(&client)
            .expect("checked allocation");
        if let Some(family) = m.attr(FAMILY) {
            if family.len() != 4 {
                self.error(client, peer, m, 400, Some(&key));
                return;
            }
            if (family[0] == 1) != a.advertised_address.is_ipv4() {
                self.error(client, peer, m, 443, Some(&key));
                return;
            }
        }
        if m.attr(LIFETIME).is_some() && m.number(LIFETIME).is_none() {
            self.error(client, peer, m, 400, Some(&key));
            return;
        }
        let duration = credential_lifetime(
            &a.username,
            m.number(LIFETIME)
                .unwrap_or(600)
                .min(self.config.max_allocation_lifetime),
            SystemTime::now(),
        );
        a.expires = Instant::now() + duration;
        let lifetime = duration
            .as_secs()
            .saturating_add(u64::from(duration.subsec_nanos() != 0)) as u32;
        let mut b = Builder::new(REFRESH, 2, m.transaction);
        b.number(LIFETIME, lifetime);
        if lifetime == 0 {
            // A client can send its next request as soon as it sees success.
            // Close the connected UDP socket first, so that request reaches
            // the listener instead of being queued on a socket we then drop.
            // Stream connections remain open; the listener keeps the same
            // concrete client-facing endpoint as the removed UDP socket.
            self.remove_allocation(client);
        }
        self.send_client(client, &b.finish(Some(&key)));
    }

    fn peer_allowed(&self, address: SocketAddr) -> bool {
        Self::allowed_peer(
            &self.config,
            &self.relay_ports,
            &self.advertised_relay_ports,
            address,
        )
    }

    /// Where to send a packet addressed to `peer`. A router without NAT
    /// loopback drops what the host sends to its own public address, so a
    /// packet for another live allocation's advertised address goes straight
    /// to that allocation's local socket instead. Policy and permissions are
    /// still checked against the advertised address.
    fn own_local_target(
        config: &Config,
        public_to_local: &HashMap<u16, u16>,
        peer: SocketAddr,
    ) -> SocketAddr {
        match config.advertised_ip {
            Some(public) if public != config.relay_ip && peer.ip() == public => public_to_local
                .get(&peer.port())
                .map_or(peer, |&local| SocketAddr::new(config.relay_ip, local)),
            _ => peer,
        }
    }

    /// How a packet from `source` is shown to the receiving allocation. One
    /// sent by another live allocation arrives from its local socket; when
    /// the receiver has a permission for the advertised IP, the packet is
    /// shown as coming from that allocation's advertised address, which is
    /// the only one its client ever learnt.
    fn own_public_source(
        config: &Config,
        local_to_public: &HashMap<u16, u16>,
        permissions: &[Permission],
        now: Instant,
        source: SocketAddr,
    ) -> SocketAddr {
        match config.advertised_ip {
            Some(public) if public != config.relay_ip && source.ip() == config.relay_ip => {
                match local_to_public.get(&source.port()) {
                    Some(&port)
                        if permissions
                            .iter()
                            .any(|p| p.ip == public && p.expires > now) =>
                    {
                        SocketAddr::new(public, port)
                    }
                    _ => source,
                }
            }
            _ => source,
        }
    }

    fn allowed_peer(
        config: &Config,
        ports: &HashSet<u16>,
        advertised_ports: &HashSet<u16>,
        address: SocketAddr,
    ) -> bool {
        if address.port() == 0 {
            return false;
        }
        let ip = address.ip();
        if config.local_peer_bridge {
            if !local_bridge_address(ip) {
                return false;
            }
            if ip == config.relay_ip {
                return ports.contains(&address.port());
            }
            if !matches!(ip, IpAddr::V4(peer) if config.bridge_peer_ips.contains(&peer)) {
                return false;
            }
            return config
                .relay_port_range
                .is_some_and(|(first, last)| (first..=last).contains(&address.port()));
        }
        if ip.is_unspecified() || ip.is_multicast() {
            return false;
        }
        if ip.is_loopback() && !config.allow_loopback_peers {
            return false;
        }
        // Mapped mode must not let the local-test loopback opt-in bypass
        // exact ownership checks on the configured local/public relay IPs.
        if config.relay_port_mappings.is_some()
            && (ip == config.relay_ip || Some(ip) == config.advertised_ip)
        {
            return (ip == config.relay_ip && ports.contains(&address.port()))
                || (ip == config.advertised_ip.unwrap_or(config.relay_ip)
                    && advertised_ports.contains(&address.port()));
        }
        if ip.is_loopback() {
            return config.allow_loopback_peers;
        }
        if ip == config.relay_ip || Some(ip) == config.advertised_ip {
            return (ip == config.relay_ip && ports.contains(&address.port()))
                || (ip == config.advertised_ip.unwrap_or(config.relay_ip)
                    && advertised_ports.contains(&address.port()));
        }
        match ip {
            IpAddr::V4(v) => {
                let [a, b, c, _] = v.octets();
                !(v.is_private()
                    || v.is_link_local()
                    || v.is_broadcast()
                    || v.is_documentation()
                    || a == 0
                    || a >= 224
                    || (a == 100 && (64..=127).contains(&b))
                    || (a == 198 && (b == 18 || b == 19))
                    || (a == 192 && b == 0 && c == 0))
            }
            IpAddr::V6(v) => {
                // Only global unicast, 2000::/3. That alone refuses the
                // ranges a translator can turn into an IPv4 destination the
                // rules above would refuse: IPv4-mapped and IPv4-compatible
                // addresses and NAT64 64:ff9b::/96 and 64:ff9b:1::/48. It
                // also refuses unique-local, link-local, site-local and the
                // discard prefix. Inside 2000::/3, refuse the IETF special
                // block 2001::/23 (Teredo and others), the documentation
                // ranges 2001:db8::/32 and 3fff::/20, and 6to4 2002::/16,
                // which embeds IPv4.
                let [first, second, ..] = v.segments();
                first & 0xe000 == 0x2000
                    && !(first == 0x2001 && second < 0x0200)
                    && !(first == 0x2001 && second == 0x0db8)
                    && first != 0x2002
                    && first & 0xfff0 != 0x3ff0
            }
        }
    }

    fn permission(&mut self, client: Client, peer: SocketAddr, m: &Message<'_>, key: [u8; 16]) {
        let mut peers = Vec::new();
        for (typ, value) in m.attributes().filter(|(t, _)| *t == PEER) {
            let _ = typ;
            let Some(address) = decode_address(value, &m.transaction) else {
                self.error(client, peer, m, 400, Some(&key));
                return;
            };
            if address.is_ipv4() != self.config.relay_ip.is_ipv4() {
                self.error(client, peer, m, 443, Some(&key));
                return;
            }
            if !self.peer_allowed(address) {
                self.error(client, peer, m, 403, Some(&key));
                return;
            }
            if !peers.contains(&address.ip()) {
                peers.push(address.ip());
            }
        }
        if peers.is_empty() {
            self.error(client, peer, m, 400, Some(&key));
            return;
        }
        let now = Instant::now();
        let a = self
            .allocations
            .get_mut(&client)
            .expect("checked allocation");
        a.permissions.retain(|p| p.expires > now);
        let new = peers
            .iter()
            .filter(|ip| !a.permissions.iter().any(|p| p.ip == **ip))
            .count();
        if a.permissions.len() + new > MAX_PEERS {
            self.error(client, peer, m, 508, Some(&key));
            return;
        }
        for ip in peers {
            Self::permit(a, ip, now);
        }
        self.send_client(
            client,
            &Builder::new(PERMISSION, 2, m.transaction).finish(Some(&key)),
        );
    }

    fn permit(a: &mut Allocation, ip: IpAddr, now: Instant) {
        if let Some(p) = a.permissions.iter_mut().find(|p| p.ip == ip) {
            p.expires = now + Duration::from_secs(300);
        } else {
            a.permissions.push(Permission {
                ip,
                expires: now + Duration::from_secs(300),
            });
        }
    }

    fn channel_bind(&mut self, client: Client, peer: SocketAddr, m: &Message<'_>, key: [u8; 16]) {
        let Some(value) = m.attr(CHANNEL).filter(|v| v.len() == 4) else {
            self.error(client, peer, m, 400, Some(&key));
            return;
        };
        let number = u16::from_be_bytes([value[0], value[1]]);
        let Some(address) = m.address(PEER) else {
            self.error(client, peer, m, 400, Some(&key));
            return;
        };
        if !(0x4000..=0x4fff).contains(&number) {
            self.error(client, peer, m, 400, Some(&key));
            return;
        }
        if address.is_ipv4() != self.config.relay_ip.is_ipv4() {
            self.error(client, peer, m, 443, Some(&key));
            return;
        }
        if !self.peer_allowed(address) {
            self.error(client, peer, m, 403, Some(&key));
            return;
        }
        let now = Instant::now();
        let a = self
            .allocations
            .get_mut(&client)
            .expect("checked allocation");
        a.permissions.retain(|p| p.expires > now);
        a.channels.retain(|c| c.expires > now);
        if a.channels.iter().any(|c| {
            (c.number == number || c.peer == address) && (c.number != number || c.peer != address)
        }) {
            self.error(client, peer, m, 400, Some(&key));
            return;
        }
        if (!a.channels.iter().any(|c| c.number == number) && a.channels.len() >= MAX_PEERS)
            || (!a.permissions.iter().any(|p| p.ip == address.ip())
                && a.permissions.len() >= MAX_PEERS)
        {
            self.error(client, peer, m, 508, Some(&key));
            return;
        }
        if let Some(c) = a.channels.iter_mut().find(|c| c.number == number) {
            c.expires = now + Duration::from_secs(600);
        } else {
            a.channels.push(Channel {
                number,
                peer: address,
                expires: now + Duration::from_secs(600),
            });
        }
        Self::permit(a, address.ip(), now);
        self.send_client(
            client,
            &Builder::new(CHANNEL_BIND, 2, m.transaction).finish(Some(&key)),
        );
    }

    fn send_indication(&mut self, client: Client, m: &Message<'_>) {
        let (Some(peer), Some(data)) = (m.address(PEER), m.attr(DATA)) else {
            return;
        };
        // Permissions are IP-scoped; apply port-sensitive policy to every send.
        if !self.peer_allowed(peer) {
            self.stats.dropped_packets += 1;
            return;
        }
        let now = Instant::now();
        let Some(a) = self.allocations.get_mut(&client).filter(|a| {
            a.expires > now
                && self
                    .config
                    .credential_authorizer
                    .as_ref()
                    .is_none_or(|allow| allow(&a.username))
        }) else {
            return;
        };
        if !a
            .permissions
            .iter()
            .any(|p| p.ip == peer.ip() && p.expires > now)
            || !Self::within_budget(&mut a.bandwidth, &mut self.aggregate, data.len(), now)
        {
            self.stats.dropped_packets += 1;
            return;
        }
        let target = Self::own_local_target(&self.config, &self.own_public_to_local, peer);
        if a.socket.send_to(data, target).is_ok() {
            self.forwarded(client, data.len());
        } else {
            self.stats.dropped_packets += 1;
        }
    }

    fn flush_peer_batch(&mut self, client: Client, batch: &mut TcpReturnBatch) -> bool {
        if batch.frames == 0 {
            return true;
        }
        let frames = std::mem::take(&mut batch.frames);
        let payload_bytes = std::mem::take(&mut batch.payload_bytes);
        batch.bytes = 0;
        let Client::Stream(token) = client else {
            unreachable!("only plain TCP returns are batched");
        };
        let accepted = if let Some(conn) = self.connections.get_mut(&token) {
            if conn
                .flush()
                .and_then(|pending| conn.update_interest(self.poll.registry(), token, pending))
                .is_ok()
            {
                true
            } else {
                self.fail_stream(token);
                false
            }
        } else {
            false
        };
        // Preserve accepted/queued semantics: WouldBlock succeeds, a fatal
        // first flush rejects this batch. Previously accepted pending output
        // has already been counted and must not be counted again here.
        if accepted {
            self.forwarded_batch(client, frames, payload_bytes);
        } else {
            self.stats.dropped_packets += frames as u64;
        }
        accepted
    }

    fn send_peer_packet(
        &mut self,
        client: Client,
        bytes: &[u8],
        payload_bytes: usize,
        batch: &mut TcpReturnBatch,
    ) -> bool {
        if !batch.enabled || bytes.len() > TCP_RETURN_BATCH_BYTES {
            self.flush_peer_batch(client, batch);
            let accepted = self.send_client_packet(client, bytes, true);
            if accepted {
                self.forwarded(client, payload_bytes);
            }
            return accepted;
        }
        // Settle the current batch before the queue-cap retry can flush it.
        // Otherwise a successful retry followed by a later fatal flush could
        // reclassify already accepted packets as dropped.
        let needs_queue_retry = match client {
            Client::Stream(token) => self.connections.get(&token).is_some_and(|conn| {
                bytes.len()
                    > (MAX_QUEUE - STREAM_CONTROL_RESERVE)
                        .saturating_sub(conn.output.len() - conn.written)
            }),
            Client::Datagram(_) => false,
        };
        if bytes.len() > TCP_RETURN_BATCH_BYTES.saturating_sub(batch.bytes) || needs_queue_retry {
            self.flush_peer_batch(client, batch);
        }
        let accepted = self.send_client_packet_inner(client, bytes, true, true, false);
        if accepted {
            batch.frames += 1;
            batch.bytes += bytes.len();
            batch.payload_bytes += payload_bytes;
            if batch.frames >= TCP_RETURN_BATCH_FRAMES || batch.bytes >= TCP_RETURN_BATCH_BYTES {
                return self.flush_peer_batch(client, batch);
            }
        }
        accepted
    }

    fn peer_return_batch(&self, client: Client) -> TcpReturnBatch {
        let enabled = match client {
            Client::Stream(token) => self.connections.get(&token).is_some_and(|conn| {
                #[cfg(feature = "tls")]
                if conn.tls.is_some() {
                    return false;
                }
                let _ = conn;
                true
            }),
            Client::Datagram(_) => false,
        };
        TcpReturnBatch::new(enabled)
    }

    // Swap only empty storage: blocked writes and their cursor always remain
    // owned by the connection. Closing a borrower releases its owned buffer.
    fn swap_empty_peer_output(&mut self, client: Client) -> bool {
        let Client::Stream(token) = client else {
            return false;
        };
        let Some(conn) = self.connections.get_mut(&token) else {
            return false;
        };
        if !conn.output.is_empty() || conn.written != 0 {
            return false;
        }
        debug_assert!(self.tcp_return_output.is_empty());
        std::mem::swap(&mut conn.output, &mut self.tcp_return_output);
        true
    }

    fn receive_peer(&mut self, token: Token, input: &mut [u8]) {
        let Some(client) = self.relays.get(&token).copied() else {
            return;
        };
        let mut dispatch = PeerReturnDispatch::new();
        self.receive_peer_packets(client, input, &mut dispatch);
        // Includes WouldBlock, expiry/revocation and errors. No pending batch
        // relies on another readiness edge, timer, or datagram to be flushed.
        self.flush_peer_batch(client, &mut dispatch.batch);
        if dispatch.lent_output {
            self.swap_empty_peer_output(client);
        }
    }

    fn send_peer_return(
        &mut self,
        client: Client,
        bytes: &[u8],
        payload_bytes: usize,
        dispatch: &mut PeerReturnDispatch,
    ) -> bool {
        if !dispatch.first_accepted {
            // No look-ahead syscall or batching state for the first eligible
            // return. A singleton uses the immediate forwarding path.
            let accepted = self.send_client_packet_inner(client, bytes, true, false, true);
            if accepted {
                dispatch.first_accepted = true;
                self.forwarded(client, payload_bytes);
            }
            return accepted;
        }
        if !dispatch.batch_started {
            // Only a second authorised return in this dispatch pays for batch
            // classification and the empty-buffer loan. TLS and UDP stay
            // immediate; pending stream output always keeps its own storage.
            dispatch.batch_started = true;
            dispatch.batch = self.peer_return_batch(client);
            dispatch.lent_output = dispatch.batch.enabled && self.swap_empty_peer_output(client);
        }
        self.send_peer_packet(client, bytes, payload_bytes, &mut dispatch.batch)
    }

    fn receive_peer_packets(
        &mut self,
        client: Client,
        input: &mut [u8],
        dispatch: &mut PeerReturnDispatch,
    ) {
        loop {
            let now = Instant::now();
            let Some(a) = self.allocations.get_mut(&client).filter(|a| {
                a.expires > now
                    && self
                        .config
                        .credential_authorizer
                        .as_ref()
                        .is_none_or(|allow| allow(&a.username))
            }) else {
                return;
            };
            // Receive directly after room for the largest TURN header. Return
            // packets prepend their framing without copying the media payload.
            let (n, peer) = match a.socket.recv_from(&mut input[HEADROOM..]) {
                Ok(value) => value,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {
                    self.flush_peer_batch(client, &mut dispatch.batch);
                    continue;
                }
                Err(_) => return,
            };
            let peer = Self::own_public_source(
                &self.config,
                &self.own_local_to_public,
                &a.permissions,
                now,
                peer,
            );
            if !a
                .permissions
                .iter()
                .any(|p| p.ip == peer.ip() && p.expires > now)
                || !Self::within_budget(&mut a.bandwidth, &mut self.aggregate, n, now)
            {
                self.stats.dropped_packets += 1;
                self.flush_peer_batch(client, &mut dispatch.batch);
                continue;
            }
            if let Some(c) = a
                .channels
                .iter()
                .find(|c| c.peer == peer && c.expires > now)
            {
                let begin = HEADROOM - 4;
                input[begin..begin + 2].copy_from_slice(&c.number.to_be_bytes());
                input[begin + 2..HEADROOM].copy_from_slice(&(n as u16).to_be_bytes());
                let end = if matches!(client, Client::Stream(_)) {
                    (HEADROOM + n + 3) & !3
                } else {
                    HEADROOM + n
                };
                input[HEADROOM + n..end].fill(0);
                if !self.send_peer_return(client, &input[begin..end], n, dispatch) {
                    self.flush_peer_batch(client, &mut dispatch.batch);
                    continue;
                }
            } else {
                // Data indications also use the reserved prefix of this buffer.
                if n > 65_440 {
                    self.stats.dropped_packets += 1;
                    self.flush_peer_batch(client, &mut dispatch.batch);
                    continue;
                }
                let mut transaction = [0; 12];
                if getrandom::fill(&mut transaction).is_err() {
                    self.flush_peer_batch(client, &mut dispatch.batch);
                    continue;
                }
                let (address, address_len) = address_value(peer, &transaction);
                let data_start = 20 + 4 + address_len + 4;
                let len = (data_start + n + 3) & !3;
                let begin = HEADROOM - data_start;
                let output = &mut input[begin..begin + len];
                output[..2].copy_from_slice(&message_type(DATA_METHOD, 1).to_be_bytes());
                output[2..4].copy_from_slice(&((len - 20) as u16).to_be_bytes());
                output[4..8].copy_from_slice(&COOKIE.to_be_bytes());
                output[8..20].copy_from_slice(&transaction);
                output[20..22].copy_from_slice(&PEER.to_be_bytes());
                output[22..24].copy_from_slice(&(address_len as u16).to_be_bytes());
                output[24..24 + address_len].copy_from_slice(&address[..address_len]);
                output[data_start - 4..data_start - 2].copy_from_slice(&DATA.to_be_bytes());
                output[data_start - 2..data_start].copy_from_slice(&(n as u16).to_be_bytes());
                output[data_start + n..len].fill(0);
                if !self.send_peer_return(client, &output[..len], n, dispatch) {
                    self.flush_peer_batch(client, &mut dispatch.batch);
                    continue;
                }
            }
        }
    }
}
