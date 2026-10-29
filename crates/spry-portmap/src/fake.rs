//! In-process fake gateways on loopback, for tests only (feature `testing`).
//!
//! [`FakeNatGateway`] answers PCP and NAT-PMP on one UDP port, as a real
//! gateway does on 5351. [`FakeUpnpGateway`] answers SSDP searches and serves
//! a device description and SOAP control over HTTP. Both are written from the
//! RFCs and the UPnP IGD specifications in this repository; no third-party
//! router software is involved. Each runs on its own threads and stops when
//! dropped.

use crate::Protocol;
use std::io::{ErrorKind, Read, Write};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpListener, TcpStream, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

/// A documentation address (RFC 5737) used as the fake external address.
pub const EXTERNAL: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 7);

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// How the fake answers PCP (version 2) requests.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PcpMode {
    Grant,
    Silent,
    /// Answer with this PCP result code.
    Refuse(u8),
    /// Answer as a NAT-PMP-only gateway: version 0, "unsupported version".
    NatPmpOnly,
    /// Answer with a different nonce only.
    WrongNonce,
    /// Answer with a different nonce, then correctly.
    WrongNonceThenGrant,
    /// Answer with the first 40 bytes only.
    Truncated,
    /// Answer correctly, but from another UDP port.
    FromOtherPort,
}

/// How the fake answers NAT-PMP (version 0) requests.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NatPmpMode {
    Grant,
    Silent,
    /// Answer with this NAT-PMP result code.
    Refuse(u16),
    /// Answer with a datagram of the wrong length.
    Malformed,
}

#[derive(Clone, Debug)]
pub struct NatBehaviour {
    pub pcp: PcpMode,
    pub natpmp: NatPmpMode,
    pub external: Ipv4Addr,
    /// Grant external ports 10000 above the suggested ones.
    pub translate: bool,
    /// Longest lifetime granted, in seconds.
    pub max_lifetime: u32,
}

impl Default for NatBehaviour {
    fn default() -> Self {
        Self {
            pcp: PcpMode::Grant,
            natpmp: NatPmpMode::Grant,
            external: EXTERNAL,
            translate: false,
            max_lifetime: 7200,
        }
    }
}

/// A mapping held by the fake NAT gateway.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NatMapping {
    /// 2 for PCP, 0 for NAT-PMP.
    pub version: u8,
    pub protocol: Protocol,
    pub internal_port: u16,
    pub external_port: u16,
    pub lifetime: u32,
    pub nonce: Option<[u8; 12]>,
}

/// A request the fake NAT gateway received: version, opcode and lifetime.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NatRequest {
    pub version: u8,
    pub opcode: u8,
    pub lifetime: u32,
}

struct NatState {
    behaviour: NatBehaviour,
    epoch_base: Instant,
    epoch_offset: u32,
    mappings: Vec<NatMapping>,
    requests: Vec<NatRequest>,
}

impl NatState {
    fn epoch(&self) -> u32 {
        let elapsed = u32::try_from(self.epoch_base.elapsed().as_secs()).unwrap_or(u32::MAX);
        self.epoch_offset.saturating_add(elapsed)
    }
    fn external_port(&self, suggested: u16, internal: u16) -> u16 {
        let base = if suggested == 0 { internal } else { suggested };
        if self.behaviour.translate {
            base.wrapping_add(10000).max(1024)
        } else {
            base
        }
    }
}

/// A fake PCP and NAT-PMP gateway on one loopback UDP port.
pub struct FakeNatGateway {
    address: SocketAddrV4,
    state: Arc<Mutex<NatState>>,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

fn protocol_from_number(number: u8) -> Option<Protocol> {
    match number {
        17 => Some(Protocol::Udp),
        6 => Some(Protocol::Tcp),
        _ => None,
    }
}

fn pcp_reply(
    request: &[u8],
    result: u8,
    lifetime: u32,
    epoch: u32,
    external: SocketAddrV4,
) -> Vec<u8> {
    let mut out = vec![0u8; 60];
    out[0] = 2;
    out[1] = 0x81;
    out[3] = result;
    out[4..8].copy_from_slice(&lifetime.to_be_bytes());
    out[8..12].copy_from_slice(&epoch.to_be_bytes());
    out[24..44].copy_from_slice(&request[24..44]);
    out[42..44].copy_from_slice(&external.port().to_be_bytes());
    out[44..60].copy_from_slice(&external.ip().to_ipv6_mapped().octets());
    out
}

/// Replies to one datagram: bytes, and whether to send from another port.
fn handle_nat(state: &mut NatState, request: &[u8], from: SocketAddrV4) -> Vec<(Vec<u8>, bool)> {
    if request.len() < 2 {
        return Vec::new();
    }
    let version = request[0];
    let opcode = request[1];
    let lifetime = request
        .get(4..8)
        .map_or(0, |b| u32::from_be_bytes([b[0], b[1], b[2], b[3]]));
    let lifetime = if version == 0 {
        request
            .get(8..12)
            .map_or(0, |b| u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    } else {
        lifetime
    };
    state.requests.push(NatRequest {
        version,
        opcode,
        lifetime,
    });
    let epoch = state.epoch();
    match version {
        2 => handle_pcp(state, request, from, epoch),
        0 => handle_natpmp(state, request, epoch),
        _ => Vec::new(),
    }
}

fn handle_pcp(
    state: &mut NatState,
    request: &[u8],
    from: SocketAddrV4,
    epoch: u32,
) -> Vec<(Vec<u8>, bool)> {
    let mode = state.behaviour.pcp;
    match mode {
        PcpMode::Silent => return Vec::new(),
        PcpMode::NatPmpOnly => {
            let mut out = vec![0, 0x80 | request[1], 0, 1];
            out.extend_from_slice(&epoch.to_be_bytes());
            return vec![(out, false)];
        }
        _ => {}
    }
    if request.len() != 60 || request[1] != 1 {
        return Vec::new();
    }
    let lifetime = u32::from_be_bytes([request[4], request[5], request[6], request[7]]);
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&request[24..36]);
    let Some(protocol) = protocol_from_number(request[36]) else {
        return vec![(
            pcp_reply(
                request,
                9,
                0,
                epoch,
                SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0),
            ),
            false,
        )];
    };
    let internal_port = u16::from_be_bytes([request[40], request[41]]);
    let suggested = u16::from_be_bytes([request[42], request[43]]);
    let none = SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0);
    if request[8..24] != from.ip().to_ipv6_mapped().octets() {
        return vec![(pcp_reply(request, 12, 0, epoch, none), false)];
    }
    if let PcpMode::Refuse(code) = mode {
        return vec![(pcp_reply(request, code, 0, epoch, none), false)];
    }
    let existing = state
        .mappings
        .iter()
        .position(|m| m.version == 2 && m.protocol == protocol && m.internal_port == internal_port);
    if existing.is_some_and(|at| state.mappings[at].nonce != Some(nonce)) {
        return vec![(pcp_reply(request, 2, 0, epoch, none), false)];
    }
    let external = state.behaviour.external;
    let reply = if lifetime == 0 {
        let port = existing.map_or(0, |at| state.mappings.remove(at).external_port);
        pcp_reply(request, 0, 0, epoch, SocketAddrV4::new(external, port))
    } else {
        let granted = lifetime.min(state.behaviour.max_lifetime);
        let port = match existing {
            Some(at) => {
                state.mappings[at].lifetime = granted;
                state.mappings[at].external_port
            }
            None => {
                let port = state.external_port(suggested, internal_port);
                state.mappings.push(NatMapping {
                    version: 2,
                    protocol,
                    internal_port,
                    external_port: port,
                    lifetime: granted,
                    nonce: Some(nonce),
                });
                port
            }
        };
        pcp_reply(
            request,
            0,
            granted,
            epoch,
            SocketAddrV4::new(external, port),
        )
    };
    let mut forged = reply.clone();
    forged[24] ^= 0xff;
    match mode {
        PcpMode::WrongNonce => vec![(forged, false)],
        PcpMode::WrongNonceThenGrant => vec![(forged, false), (reply, false)],
        PcpMode::Truncated => vec![(reply[..40].to_vec(), false)],
        PcpMode::FromOtherPort => vec![(reply, true)],
        _ => vec![(reply, false)],
    }
}

fn handle_natpmp(state: &mut NatState, request: &[u8], epoch: u32) -> Vec<(Vec<u8>, bool)> {
    let opcode = request[1];
    let mut out = vec![0, 0x80 | opcode];
    match state.behaviour.natpmp {
        NatPmpMode::Silent => return Vec::new(),
        NatPmpMode::Malformed => return vec![(vec![0, 0x80 | opcode, 0, 0, 1], false)],
        NatPmpMode::Refuse(code) => {
            out.extend_from_slice(&code.to_be_bytes());
            out.extend_from_slice(&epoch.to_be_bytes());
            return vec![(out, false)];
        }
        NatPmpMode::Grant => {}
    }
    out.extend_from_slice(&[0, 0]);
    out.extend_from_slice(&epoch.to_be_bytes());
    match (opcode, request.len()) {
        (0, 2) => out.extend_from_slice(&state.behaviour.external.octets()),
        (1 | 2, 12) => {
            let protocol = if opcode == 1 {
                Protocol::Udp
            } else {
                Protocol::Tcp
            };
            let internal_port = u16::from_be_bytes([request[4], request[5]]);
            let suggested = u16::from_be_bytes([request[6], request[7]]);
            let lifetime = u32::from_be_bytes([request[8], request[9], request[10], request[11]]);
            let existing = state.mappings.iter().position(|m| {
                m.version == 0 && m.protocol == protocol && m.internal_port == internal_port
            });
            let (port, granted) = if lifetime == 0 {
                if let Some(at) = existing {
                    state.mappings.remove(at);
                }
                (0, 0)
            } else {
                let granted = lifetime.min(state.behaviour.max_lifetime);
                let port = match existing {
                    Some(at) => {
                        state.mappings[at].lifetime = granted;
                        state.mappings[at].external_port
                    }
                    None => {
                        let port = state.external_port(suggested, internal_port);
                        state.mappings.push(NatMapping {
                            version: 0,
                            protocol,
                            internal_port,
                            external_port: port,
                            lifetime: granted,
                            nonce: None,
                        });
                        port
                    }
                };
                (port, granted)
            };
            out.extend_from_slice(&internal_port.to_be_bytes());
            out.extend_from_slice(&port.to_be_bytes());
            out.extend_from_slice(&granted.to_be_bytes());
        }
        _ => {
            // Unsupported opcode.
            out[2..4].copy_from_slice(&5u16.to_be_bytes());
        }
    }
    vec![(out, false)]
}

impl FakeNatGateway {
    pub fn start(behaviour: NatBehaviour) -> Self {
        let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind fake gateway");
        let other = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind fake gateway");
        socket
            .set_read_timeout(Some(Duration::from_millis(20)))
            .expect("socket timeout");
        let SocketAddr::V4(address) = socket.local_addr().expect("local address") else {
            unreachable!("bound to IPv4");
        };
        let state = Arc::new(Mutex::new(NatState {
            behaviour,
            epoch_base: Instant::now(),
            epoch_offset: 1000,
            mappings: Vec::new(),
            requests: Vec::new(),
        }));
        let stop = Arc::new(AtomicBool::new(false));
        let thread = {
            let state = state.clone();
            let stop = stop.clone();
            std::thread::spawn(move || {
                let mut buffer = [0u8; 1500];
                while !stop.load(Ordering::Relaxed) {
                    let Ok((size, SocketAddr::V4(from))) = socket.recv_from(&mut buffer) else {
                        continue;
                    };
                    let replies = handle_nat(&mut lock(&state), &buffer[..size], from);
                    for (reply, from_other) in replies {
                        let sender = if from_other { &other } else { &socket };
                        let _ = sender.send_to(&reply, from);
                    }
                }
            })
        };
        Self {
            address,
            state,
            stop,
            thread: Some(thread),
        }
    }

    pub fn address(&self) -> SocketAddrV4 {
        self.address
    }
    pub fn set(&self, behaviour: NatBehaviour) {
        lock(&self.state).behaviour = behaviour;
    }
    pub fn behaviour(&self) -> NatBehaviour {
        lock(&self.state).behaviour.clone()
    }
    pub fn mappings(&self) -> Vec<NatMapping> {
        lock(&self.state).mappings.clone()
    }
    pub fn requests(&self) -> Vec<NatRequest> {
        lock(&self.state).requests.clone()
    }
    /// Simulate a reboot: the epoch starts again from zero and every mapping
    /// is lost.
    pub fn restart(&self) {
        let mut state = lock(&self.state);
        state.epoch_base = Instant::now();
        state.epoch_offset = 0;
        state.mappings.clear();
    }
}

impl Drop for FakeNatGateway {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

/// How the fake UPnP gateway behaves.
#[derive(Clone, Debug)]
pub struct UpnpBehaviour {
    /// 1 or 2 (IGDv2 offers `AddAnyPortMapping`).
    pub version: u8,
    /// Offer WANPPPConnection instead of WANIPConnection.
    pub ppp: bool,
    /// Refuse finite leases with error 725.
    pub permanent_only: bool,
    /// Refuse every add with this error code.
    pub refuse: Option<u16>,
    /// External address reported; unspecified reports an empty address.
    pub external: Ipv4Addr,
    /// Advertise the description at this host instead of loopback.
    pub location_host: Option<Ipv4Addr>,
    /// Advertise this control URL instead of `/ctl/IPConn`.
    pub control_url: Option<String>,
    /// Ignore SSDP searches.
    pub silent: bool,
    /// Send SOAP replies with chunked transfer encoding.
    pub chunked: bool,
    /// Serve this text as the device description.
    pub description: Option<String>,
    /// Answer SOAP calls with something that is not XML.
    pub garbage: bool,
    /// Report this client and tag in `GetSpecificPortMappingEntry`.
    pub entry_override: Option<(SocketAddrV4, String)>,
}

impl Default for UpnpBehaviour {
    fn default() -> Self {
        Self {
            version: 1,
            ppp: false,
            permanent_only: false,
            refuse: None,
            external: EXTERNAL,
            location_host: None,
            control_url: None,
            silent: false,
            chunked: false,
            description: None,
            garbage: false,
            entry_override: None,
        }
    }
}

/// A mapping held by the fake UPnP gateway.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UpnpMapping {
    pub protocol: Protocol,
    pub external_port: u16,
    pub internal: SocketAddrV4,
    pub description: String,
    pub lease: u32,
}

struct UpnpState {
    behaviour: UpnpBehaviour,
    mappings: Vec<UpnpMapping>,
    actions: Vec<String>,
    searches: usize,
}

/// A fake UPnP IGD: an SSDP responder and an HTTP description and SOAP
/// control server, both on loopback.
pub struct FakeUpnpGateway {
    ssdp: SocketAddrV4,
    http: SocketAddrV4,
    state: Arc<Mutex<UpnpState>>,
    stop: Arc<AtomicBool>,
    threads: Vec<JoinHandle<()>>,
}

fn service_urn(behaviour: &UpnpBehaviour) -> String {
    let kind = if behaviour.ppp {
        "WANPPPConnection"
    } else {
        "WANIPConnection"
    };
    let version = if behaviour.ppp { 1 } else { behaviour.version };
    format!("urn:schemas-upnp-org:service:{kind}:{version}")
}

fn description(behaviour: &UpnpBehaviour) -> String {
    if let Some(text) = &behaviour.description {
        return text.clone();
    }
    let version = behaviour.version;
    let control = behaviour.control_url.as_deref().unwrap_or("/ctl/IPConn");
    format!(
        "<?xml version=\"1.0\"?>\r\n<root xmlns=\"urn:schemas-upnp-org:device-1-0\">\
         <specVersion><major>1</major><minor>{minor}</minor></specVersion>\
         <device><deviceType>urn:schemas-upnp-org:device:InternetGatewayDevice:{version}</deviceType>\
         <friendlyName>Fake gateway</friendlyName>\
         <serviceList><service><serviceType>urn:schemas-upnp-org:service:Layer3Forwarding:1</serviceType>\
         <controlURL>/ctl/L3F</controlURL></service></serviceList>\
         <deviceList><device><deviceType>urn:schemas-upnp-org:device:WANDevice:{version}</deviceType>\
         <deviceList><device><deviceType>urn:schemas-upnp-org:device:WANConnectionDevice:{version}</deviceType>\
         <serviceList><service><serviceType>{urn}</serviceType><serviceId>urn:upnp-org:serviceId:WANConn1</serviceId>\
         <controlURL>{control}</controlURL><eventSubURL>/evt/IPConn</eventSubURL><SCPDURL>/scpd.xml</SCPDURL>\
         </service></serviceList></device></deviceList></device></deviceList></device></root>\r\n",
        minor = version - 1,
        urn = service_urn(behaviour),
    )
}

/// Text of `<name>...</name>` in a SOAP request, found without the crate's
/// own XML reader so the fake does not share its bugs.
fn soap_argument(body: &str, name: &str) -> Option<String> {
    let open = format!("<{name}>");
    let close = format!("</{name}>");
    let start = body.find(&open)? + open.len();
    let end = body[start..].find(&close)? + start;
    Some(body[start..end].to_owned())
}

fn soap_ok(urn: &str, action: &str, args: &[(&str, String)]) -> (u16, String) {
    let mut out = format!(
        "<?xml version=\"1.0\"?>\r\n<s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" \
         s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\"><s:Body><u:{action}Response xmlns:u=\"{urn}\">"
    );
    for (name, value) in args {
        out.push_str(&format!("<{name}>{value}</{name}>"));
    }
    out.push_str(&format!("</u:{action}Response></s:Body></s:Envelope>\r\n"));
    (200, out)
}

fn soap_fault(code: u16) -> (u16, String) {
    (
        500,
        format!(
            "<?xml version=\"1.0\"?>\r\n<s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" \
             s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\"><s:Body><s:Fault>\
             <faultcode>s:Client</faultcode><faultstring>UPnPError</faultstring><detail>\
             <UPnPError xmlns=\"urn:schemas-upnp-org:control-1-0\"><errorCode>{code}</errorCode>\
             <errorDescription>Fake</errorDescription></UPnPError></detail></s:Fault></s:Body></s:Envelope>\r\n"
        ),
    )
}

fn handle_soap(state: &mut UpnpState, action: &str, body: &str) -> (u16, String) {
    state.actions.push(action.to_owned());
    let behaviour = state.behaviour.clone();
    let urn = service_urn(&behaviour);
    if behaviour.garbage {
        return (200, "<html>not soap".to_owned());
    }
    let protocol = soap_argument(body, "NewProtocol").and_then(|p| Protocol::parse(&p));
    let external_port: Option<u16> =
        soap_argument(body, "NewExternalPort").and_then(|p| p.parse().ok());
    match action {
        "GetExternalIPAddress" => {
            // An unspecified address stands for a router whose WAN is down,
            // which answers with an empty address.
            let address = if behaviour.external.is_unspecified() {
                String::new()
            } else {
                behaviour.external.to_string()
            };
            soap_ok(&urn, action, &[("NewExternalIPAddress", address)])
        }
        "AddPortMapping" | "AddAnyPortMapping" => {
            if action == "AddAnyPortMapping" && behaviour.version < 2 {
                return soap_fault(401);
            }
            if let Some(code) = behaviour.refuse {
                return soap_fault(code);
            }
            let (Some(protocol), Some(external_port)) = (protocol, external_port) else {
                return soap_fault(402);
            };
            let internal_port: Option<u16> =
                soap_argument(body, "NewInternalPort").and_then(|p| p.parse().ok());
            let client: Option<Ipv4Addr> =
                soap_argument(body, "NewInternalClient").and_then(|c| c.parse().ok());
            let lease: Option<u32> =
                soap_argument(body, "NewLeaseDuration").and_then(|l| l.parse().ok());
            let description = soap_argument(body, "NewPortMappingDescription").unwrap_or_default();
            let (Some(internal_port), Some(client), Some(lease)) = (internal_port, client, lease)
            else {
                return soap_fault(402);
            };
            if behaviour.permanent_only && lease != 0 {
                return soap_fault(725);
            }
            let internal = SocketAddrV4::new(client, internal_port);
            let taken = |port: u16| {
                state.mappings.iter().any(|m| {
                    m.protocol == protocol && m.external_port == port && m.internal != internal
                })
            };
            let mut port = external_port;
            if action == "AddAnyPortMapping" {
                while taken(port) {
                    port = port.wrapping_add(1).max(1024);
                }
            } else if taken(port) {
                return soap_fault(718);
            }
            state
                .mappings
                .retain(|m| !(m.protocol == protocol && m.external_port == port));
            state.mappings.push(UpnpMapping {
                protocol,
                external_port: port,
                internal,
                description,
                lease,
            });
            if action == "AddAnyPortMapping" {
                soap_ok(&urn, action, &[("NewReservedPort", port.to_string())])
            } else {
                soap_ok(&urn, action, &[])
            }
        }
        "GetSpecificPortMappingEntry" => {
            let found = state
                .mappings
                .iter()
                .find(|m| Some(m.protocol) == protocol && Some(m.external_port) == external_port);
            let Some(found) = found else {
                return soap_fault(714);
            };
            let (internal, description) = behaviour
                .entry_override
                .clone()
                .unwrap_or((found.internal, found.description.clone()));
            soap_ok(
                &urn,
                action,
                &[
                    ("NewInternalPort", internal.port().to_string()),
                    ("NewInternalClient", internal.ip().to_string()),
                    ("NewEnabled", "1".to_owned()),
                    ("NewPortMappingDescription", description),
                    ("NewLeaseDuration", found.lease.to_string()),
                ],
            )
        }
        "DeletePortMapping" => {
            let before = state.mappings.len();
            state.mappings.retain(|m| {
                !(Some(m.protocol) == protocol && Some(m.external_port) == external_port)
            });
            if state.mappings.len() == before {
                soap_fault(714)
            } else {
                soap_ok(&urn, action, &[])
            }
        }
        _ => soap_fault(401),
    }
}

fn read_http_request(stream: &mut TcpStream) -> Option<(String, String, String, String)> {
    stream.set_read_timeout(Some(Duration::from_secs(2))).ok()?;
    let mut buffer = Vec::new();
    let mut chunk = [0u8; 4096];
    let (head_end, length) = loop {
        let read = stream.read(&mut chunk).ok()?;
        if read == 0 {
            return None;
        }
        buffer.extend_from_slice(&chunk[..read]);
        if buffer.len() > 128 * 1024 {
            return None;
        }
        if let Some(end) = buffer.windows(4).position(|w| w == b"\r\n\r\n") {
            let head = String::from_utf8_lossy(&buffer[..end]).to_string();
            let length = head
                .lines()
                .find_map(|line| {
                    let (name, value) = line.split_once(':')?;
                    name.eq_ignore_ascii_case("content-length")
                        .then(|| value.trim().parse::<usize>().ok())?
                })
                .unwrap_or(0);
            break (end + 4, length);
        }
    };
    while buffer.len() < head_end + length {
        let read = stream.read(&mut chunk).ok()?;
        if read == 0 {
            return None;
        }
        buffer.extend_from_slice(&chunk[..read]);
    }
    let head = String::from_utf8_lossy(&buffer[..head_end]).to_string();
    let body = String::from_utf8_lossy(&buffer[head_end..head_end + length]).to_string();
    let mut request_line = head.lines().next()?.split(' ');
    let method = request_line.next()?.to_owned();
    let path = request_line.next()?.to_owned();
    let action = head
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("soapaction")
                .then(|| value.trim().trim_matches('"').to_owned())
        })
        .and_then(|value| value.rsplit_once('#').map(|(_, action)| action.to_owned()))
        .unwrap_or_default();
    Some((method, path, action, body))
}

fn serve_http(stream: &mut TcpStream, state: &Mutex<UpnpState>) {
    let Some((method, path, action, body)) = read_http_request(stream) else {
        return;
    };
    let chunked = lock(state).behaviour.chunked;
    let (status, text) = match (method.as_str(), path.as_str()) {
        ("GET", "/rootDesc.xml") => (200, description(&lock(state).behaviour)),
        ("POST", "/ctl/IPConn") => handle_soap(&mut lock(state), &action, &body),
        _ => (404, String::new()),
    };
    let reason = match status {
        200 => "OK",
        500 => "Internal Server Error",
        _ => "Not Found",
    };
    let mut response = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: text/xml; charset=\"utf-8\"\r\nConnection: close\r\n"
    );
    if chunked {
        let (first, second) = text.split_at(text.len() / 2);
        response.push_str("Transfer-Encoding: chunked\r\n\r\n");
        for part in [first, second] {
            if !part.is_empty() {
                response.push_str(&format!("{:x}\r\n{part}\r\n", part.len()));
            }
        }
        response.push_str("0\r\n\r\n");
    } else {
        response.push_str(&format!("Content-Length: {}\r\n\r\n{text}", text.len()));
    }
    let _ = stream.write_all(response.as_bytes());
}

impl FakeUpnpGateway {
    pub fn start(behaviour: UpnpBehaviour) -> Self {
        let ssdp_socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind fake SSDP");
        ssdp_socket
            .set_read_timeout(Some(Duration::from_millis(20)))
            .expect("socket timeout");
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind fake HTTP");
        listener
            .set_nonblocking(true)
            .expect("nonblocking listener");
        let (SocketAddr::V4(ssdp), SocketAddr::V4(http)) = (
            ssdp_socket.local_addr().expect("address"),
            listener.local_addr().expect("address"),
        ) else {
            unreachable!("bound to IPv4");
        };
        let state = Arc::new(Mutex::new(UpnpState {
            behaviour,
            mappings: Vec::new(),
            actions: Vec::new(),
            searches: 0,
        }));
        let stop = Arc::new(AtomicBool::new(false));
        let ssdp_thread = {
            let state = state.clone();
            let stop = stop.clone();
            std::thread::spawn(move || {
                let mut buffer = [0u8; 2048];
                while !stop.load(Ordering::Relaxed) {
                    let Ok((size, from)) = ssdp_socket.recv_from(&mut buffer) else {
                        continue;
                    };
                    let message = String::from_utf8_lossy(&buffer[..size]).to_string();
                    let mut state = lock(&state);
                    if state.behaviour.silent
                        || !message.starts_with("M-SEARCH * HTTP/1.1\r\n")
                        || !message.contains("ssdp:discover")
                    {
                        continue;
                    }
                    let Some(target) = message
                        .lines()
                        .find_map(|line| line.strip_prefix("ST: "))
                        .filter(|target| target.contains("InternetGatewayDevice"))
                        .map(str::to_owned)
                    else {
                        continue;
                    };
                    state.searches += 1;
                    let host = state.behaviour.location_host.unwrap_or(Ipv4Addr::LOCALHOST);
                    let reply = format!(
                        "HTTP/1.1 200 OK\r\nCACHE-CONTROL: max-age=120\r\nEXT:\r\nST: {target}\r\n\
                         USN: uuid:00000000-0000-0000-0000-000000000001::{target}\r\n\
                         LOCATION: http://{host}:{}/rootDesc.xml\r\nSERVER: Fake/1 UPnP/1.1 Fake/1\r\n\r\n",
                        http.port()
                    );
                    drop(state);
                    let _ = ssdp_socket.send_to(reply.as_bytes(), from);
                }
            })
        };
        let http_thread = {
            let state = state.clone();
            let stop = stop.clone();
            std::thread::spawn(move || {
                while !stop.load(Ordering::Relaxed) {
                    match listener.accept() {
                        Ok((mut stream, _)) => {
                            let _ = stream.set_nonblocking(false);
                            serve_http(&mut stream, &state);
                        }
                        Err(error) if error.kind() == ErrorKind::WouldBlock => {
                            std::thread::sleep(Duration::from_millis(5));
                        }
                        Err(_) => std::thread::sleep(Duration::from_millis(5)),
                    }
                }
            })
        };
        Self {
            ssdp,
            http,
            state,
            stop,
            threads: vec![ssdp_thread, http_thread],
        }
    }

    /// Where to send SSDP searches.
    pub fn ssdp(&self) -> SocketAddrV4 {
        self.ssdp
    }
    pub fn http(&self) -> SocketAddrV4 {
        self.http
    }
    pub fn set(&self, behaviour: UpnpBehaviour) {
        lock(&self.state).behaviour = behaviour;
    }
    pub fn behaviour(&self) -> UpnpBehaviour {
        lock(&self.state).behaviour.clone()
    }
    pub fn mappings(&self) -> Vec<UpnpMapping> {
        lock(&self.state).mappings.clone()
    }
    /// SOAP actions received, in order.
    pub fn actions(&self) -> Vec<String> {
        lock(&self.state).actions.clone()
    }
    pub fn searches(&self) -> usize {
        lock(&self.state).searches
    }
    /// Place a mapping as if an earlier run or another host had made it.
    pub fn insert(&self, mapping: UpnpMapping) {
        lock(&self.state).mappings.push(mapping);
    }
    /// Simulate a reboot that loses every mapping.
    pub fn clear(&self) {
        lock(&self.state).mappings.clear();
    }
}

impl Drop for FakeUpnpGateway {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        for thread in self.threads.drain(..) {
            let _ = thread.join();
        }
    }
}
