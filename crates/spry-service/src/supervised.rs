//! Supervised standard mode: `spry-node supervised`.
//!
//! A host application (KithMoot desktop, later Android) runs the node as a
//! child process for its own rooms while the app is open. The mode has no
//! HTTP listener, no owner UI, no claim codes, no public mode, no advert and
//! no private mesh. Its only authority surface is the encrypted `spry:`
//! control channel, and on it only the room-grant paths. The supervising
//! app's signing key is trusted as the node's one pairing at start-up, every
//! room grant is sealed (`SPRY_ROOM_SEAL=required`), and every network value
//! is supplied explicitly: nothing is discovered or guessed.
use crate::{
    node::{ServiceState, relay_options},
    now,
    public::SetupError,
    public_v4,
    signalling::{ControlHandler, SignallingRuntime},
    standard::{MAX_ALLOCATIONS, MAX_BYTES_PER_SECOND, MAX_CONNECTIONS, MAX_PER_USER, bounded},
};
use mapping::{Plan, Update, Values};
use serde_json::{Value, json};
use spry_access::{Authority, Config, Refused, Seal};
use spry_link::{
    control::{AcceptedRequest, ControlEndpoint, RelayPolicy},
    identity::{Event, Identity},
    standard::StandardCard,
};
use spry_portmap::Options as PortmapOptions;
use spry_turn::turn::{self, RelayPortMapping, Server};
use std::{
    env,
    io::{self, Write},
    net::{Ipv4Addr, SocketAddr, SocketAddrV4},
    path::PathBuf,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    thread,
    time::Duration,
};

pub mod embedded;
mod mapping;

/// Home defaults from the owner decisions of 28 October 2026. Each may be
/// raised by the supervisor up to the standard profile's maximum.
pub(crate) const HOME_ALLOCATIONS: u32 = 8;
pub(crate) const HOME_PER_USER: u32 = 2;
pub(crate) const HOME_CONNECTIONS: u32 = 16;
pub(crate) const HOME_BYTES_PER_SECOND: u64 = 125_000;
/// Relayed payload bytes per second, both directions, across every
/// allocation together: 5 Mbit/s. Eight allocations at the per-allocation
/// default could otherwise ask for 1,000,000, more than many home uplinks
/// carry. The owner decisions of 28 October 2026 fix no value; this is
/// two thirds of that sum, and the supervisor may raise or lower it.
pub(crate) const HOME_AGGREGATE_BYTES_PER_SECOND: u64 = 625_000;
/// Seconds between status lines when the counts have changed.
const STATUS_SECONDS: u64 = 5;
/// Mapped allocation ports accepted from the supervisor. Twice the largest
/// allocation cap; every mapping is a router entry.
pub(crate) const MAX_MAPPINGS: usize = 64;
/// Room-grant paths, the only control paths this mode answers.
const PATHS: [&str; 4] = [
    "/v1/grants",
    "/v1/grants/devices",
    "/v1/grants/vouch",
    "/v1/credentials",
];
/// `Config` needs an HTTPS origin for HTTP request proofs, which this mode
/// never accepts. `.invalid` never resolves, and every answer advertises the
/// `spry:` endpoint instead.
const UNUSED_ORIGIN: &str = "https://supervised.spry.invalid";

const PAIRING_KEY: SetupError =
    SetupError("--pairing-key must be the supervising app's 64-character lowercase public key");
const STATE_FILE: SetupError = SetupError("--state-file must name the node's private state file");
const CONTROL_RELAYS: SetupError =
    SetupError("--control-relay must be given one to four times, each a distinct wss:// relay URL");
const BIND: SetupError =
    SetupError("--bind must be the concrete local IPv4 address of the hosting interface");
const PUBLIC_IP: SetupError = SetupError("--public-ip must be a public unicast IPv4 address");
const LISTEN_PORT: SetupError = SetupError("--listen-port must be an integer from 1024 to 65535");
const PUBLIC_UDP_PORT: SetupError =
    SetupError("--public-udp-port must be an integer from 1024 to 65535");
const PUBLIC_TCP_PORT: SetupError =
    SetupError("--public-tcp-port must be an integer from 1024 to 65535");
const PORT_MAP: SetupError = SetupError(
    "--relay-port-map must be given one to 64 times as LOCAL:PUBLIC, ports 1024 to 65535, each local and public port once, apart from the listener ports",
);
const SAME_ADDRESS: SetupError = SetupError(
    "when --bind equals --public-ip, every port must map to itself and both public listener ports must equal --listen-port",
);
const MAP_EXCLUSIVE: SetupError = SetupError(
    "--map-ports takes the public address and ports from the router: do not give --public-ip, --public-udp-port, --public-tcp-port or --relay-port-map",
);
const MAP_ONLY: SetupError =
    SetupError("--gateway, --gateway-port and --ssdp are used only with --map-ports");
const GATEWAY: SetupError =
    SetupError("--gateway must be the router's IPv4 address on the hosting network");
const FIXTURE_ONLY: SetupError = SetupError(
    "--gateway-port and --ssdp are for generated fixtures and need SPRY_LOCAL_TEST=true",
);
const GATEWAY_PORT: SetupError = SetupError("--gateway-port must be an integer from 1 to 65535");
const SSDP: SetupError =
    SetupError("--ssdp must be an IPv4 address and port, such as 127.0.0.1:1900");
const MAPPING_START: SetupError = SetupError("the port-mapping thread could not start");
const ALLOCATIONS: SetupError =
    SetupError("--max-allocations must be a decimal integer from 1 to 32");
const PER_USER: SetupError = SetupError(
    "--max-per-user must be a decimal integer from 1 to 8 and not exceed --max-allocations",
);
const CONNECTIONS: SetupError =
    SetupError("--max-tcp-connections must be a decimal integer from 1 to 32");
const BANDWIDTH: SetupError =
    SetupError("--bytes-per-second must be a decimal integer from 1 to 67108864");
const AGGREGATE: SetupError =
    SetupError("--aggregate-bytes-per-second must be a decimal integer from 1 to 67108864");
const STDIN: SetupError = SetupError(
    "--exit-on-stdin-close is required: a supervised node lives only while its supervisor holds its stdin",
);
const ARGUMENT: SetupError = SetupError(
    "supervised mode takes only its documented options, each once except --control-relay and --relay-port-map",
);
const SECRET: SetupError = SetupError("SPRY_TURN_SECRET must contain at least 32 bytes");
const SEAL: SetupError = SetupError("SPRY_ROOM_SEAL must be unset or required in supervised mode");
const LOCAL_TEST: SetupError = SetupError("SPRY_LOCAL_TEST must be unset or true");
const FOREIGN_SETTING: SetupError = SetupError(
    "supervised mode reads only SPRY_TURN_SECRET, SPRY_ROOM_SEAL, SPRY_LOCAL_TEST, SPRY_SOCKS_PROXY and SPRY_CONTROL_CA_FILE; unset every other SPRY_ setting",
);
const RELAY_START: SetupError = SetupError("the relay could not open its listener");
const RELAY_STOPPED: SetupError = SetupError("the embedded relay stopped");
const IDENTITY: SetupError = SetupError("the node identity could not be prepared");
const STATE: SetupError = SetupError("the state file could not be read or saved");
const STDIN_READ: SetupError = SetupError("the supervisor's pipe could not be read");
const EMBEDDED_STDIN: SetupError = SetupError(
    "--exit-on-stdin-close does not apply to a node inside its host's process: the host stops it",
);

/// Automatic port opening gave no relay that guests can reach. The node
/// exits with code 3 so a supervisor can tell this from a crash and does not
/// restart it blindly: the `portmap` line names why.
#[derive(Debug)]
pub(crate) struct CannotHost;
impl std::fmt::Display for CannotHost {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("automatic port opening did not succeed")
    }
}
impl std::error::Error for CannotHost {}
/// Exit code for [`CannotHost`].
pub(crate) const EXIT_CANNOT_HOST: i32 = 3;

/// How the router is reached under `--map-ports`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct MapSettings {
    gateway: Option<Ipv4Addr>,
    gateway_port: Option<u16>,
    ssdp: Option<SocketAddrV4>,
}

/// The `SPRY_` environment this mode reads. Every other `SPRY_` name refuses
/// startup, so a setting meant for another profile cannot appear to apply.
#[derive(Default)]
pub(crate) struct Environment {
    secret: Option<Vec<u8>>,
    seal: Option<String>,
    local_test: Option<String>,
    socks_proxy: Option<String>,
    control_ca_file: Option<String>,
    foreign: bool,
}
impl Environment {
    /// The same five settings handed over by a host as name and value
    /// pairs, for a node in the host's own process. The process environment
    /// is never read, so nothing the host inherited can appear to apply.
    /// Any other name, `SPRY_` or not, and any name given twice refuse.
    pub(crate) fn from_pairs(pairs: &[(String, String)]) -> Self {
        let mut found = Self::default();
        let mut seen = std::collections::HashSet::new();
        for (name, value) in pairs {
            if !seen.insert(name.as_str()) {
                found.foreign = true;
                continue;
            }
            let value = Some(value.clone());
            match name.as_str() {
                "SPRY_TURN_SECRET" => found.secret = value.map(String::into_bytes),
                "SPRY_ROOM_SEAL" => found.seal = value,
                "SPRY_LOCAL_TEST" => found.local_test = value,
                "SPRY_SOCKS_PROXY" => found.socks_proxy = value,
                "SPRY_CONTROL_CA_FILE" => found.control_ca_file = value,
                _ => found.foreign = true,
            }
        }
        found
    }
    fn read() -> Result<Self, SetupError> {
        let mut found = Self::default();
        for (name, value) in env::vars_os() {
            let Some(name) = name.to_str() else {
                if name.as_encoded_bytes().starts_with(b"SPRY_") {
                    found.foreign = true;
                }
                continue;
            };
            let text = |error| value.to_str().map(str::to_owned).ok_or(error);
            match name {
                "SPRY_TURN_SECRET" => found.secret = Some(text(SECRET)?.into_bytes()),
                "SPRY_ROOM_SEAL" => found.seal = Some(text(SEAL)?),
                "SPRY_LOCAL_TEST" => found.local_test = Some(text(LOCAL_TEST)?),
                // Outbound control options, for the shared relay rules. A
                // value that is not Unicode is ignored, as those rules do.
                "SPRY_SOCKS_PROXY" => found.socks_proxy = value.to_str().map(str::to_owned),
                "SPRY_CONTROL_CA_FILE" => {
                    found.control_ca_file = value.to_str().map(str::to_owned);
                }
                name if name.starts_with("SPRY_") => found.foreign = true,
                _ => {}
            }
        }
        Ok(found)
    }
}

#[derive(PartialEq, Eq)]
pub(crate) struct Settings {
    secret: Vec<u8>,
    local_test: bool,
    pairing_key: String,
    state_file: PathBuf,
    relays: Vec<String>,
    bind: Ipv4Addr,
    public_ip: Ipv4Addr,
    listen_port: u16,
    public_udp_port: u16,
    public_tcp_port: u16,
    mappings: Vec<(u16, u16)>,
    /// `Some` when the router supplies the public address and ports.
    map: Option<MapSettings>,
    allocations: u32,
    per_user: u32,
    connections: u32,
    bytes_per_second: u64,
    aggregate_bytes_per_second: u64,
}

/// Never prints the secret.
impl std::fmt::Debug for Settings {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("Settings { .. }")
    }
}

fn decimal(value: &str) -> bool {
    !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit())
}
/// A port from 1024 to 65535: the client rule for `spry:` TURN URLs.
fn high_port(value: &str) -> Option<u16> {
    decimal(value)
        .then(|| value.parse::<u16>().ok())
        .flatten()
        .filter(|port| *port >= 1024)
}
fn lowercase_key(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

impl Settings {
    /// Settings for `spry-node supervised`, a child process whose stdin is
    /// its lifetime: `--exit-on-stdin-close` is required.
    #[cfg(test)]
    pub(crate) fn parse(args: &[String], environment: &Environment) -> Result<Self, SetupError> {
        Self::parse_for(args, environment, Host::Process)
    }
    /// The same options for either host. Inside the host's own process there
    /// is no stdin to watch, so `--exit-on-stdin-close` is refused there.
    pub(crate) fn parse_for(
        args: &[String],
        environment: &Environment,
        host: Host,
    ) -> Result<Self, SetupError> {
        if environment.foreign {
            return Err(FOREIGN_SETTING);
        }
        let secret = environment
            .secret
            .clone()
            .filter(|secret| secret.len() >= 32)
            .ok_or(SECRET)?;
        if environment
            .seal
            .as_deref()
            .is_some_and(|seal| seal != "required")
        {
            return Err(SEAL);
        }
        let local_test = match environment.local_test.as_deref() {
            None => false,
            Some("true") => true,
            Some(_) => return Err(LOCAL_TEST),
        };
        let mut single: std::collections::HashMap<&str, &str> = std::collections::HashMap::new();
        let mut relays = Vec::new();
        let mut maps = Vec::new();
        let mut stdin = false;
        let mut map_ports = false;
        let mut iter = args.iter();
        while let Some(option) = iter.next() {
            let option = option.as_str();
            if option == "--exit-on-stdin-close" {
                if host == Host::Embedded {
                    return Err(EMBEDDED_STDIN);
                }
                if stdin {
                    return Err(ARGUMENT);
                }
                stdin = true;
                continue;
            }
            if option == "--map-ports" {
                if map_ports {
                    return Err(ARGUMENT);
                }
                map_ports = true;
                continue;
            }
            if !matches!(
                option,
                "--pairing-key"
                    | "--state-file"
                    | "--control-relay"
                    | "--bind"
                    | "--public-ip"
                    | "--listen-port"
                    | "--public-udp-port"
                    | "--public-tcp-port"
                    | "--relay-port-map"
                    | "--gateway"
                    | "--gateway-port"
                    | "--ssdp"
                    | "--max-allocations"
                    | "--max-per-user"
                    | "--max-tcp-connections"
                    | "--bytes-per-second"
                    | "--aggregate-bytes-per-second"
            ) {
                return Err(ARGUMENT);
            }
            let value = iter.next().ok_or(ARGUMENT)?.as_str();
            match option {
                "--control-relay" => relays.push(value.to_owned()),
                "--relay-port-map" => maps.push(value),
                _ => {
                    if single.insert(option, value).is_some() {
                        return Err(ARGUMENT);
                    }
                }
            }
        }
        if !stdin && host == Host::Process {
            return Err(STDIN);
        }
        let required = |name: &str, error| single.get(name).copied().ok_or(error);
        let pairing_key = required("--pairing-key", PAIRING_KEY)?;
        if !lowercase_key(pairing_key) {
            return Err(PAIRING_KEY);
        }
        let state_file = required("--state-file", STATE_FILE)?;
        if state_file.is_empty() || state_file.len() > 4096 {
            return Err(STATE_FILE);
        }
        let policy = if local_test {
            RelayPolicy::LocalFixture
        } else {
            RelayPolicy::Public
        };
        if relays.is_empty() {
            return Err(CONTROL_RELAYS);
        }
        // Checked against a fixed valid key: the node key is not known yet,
        // and the relay rules do not depend on it.
        let checked = ControlEndpoint::new(
            "1b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f".into(),
            relays.clone(),
            policy,
        )
        .map_err(|_| CONTROL_RELAYS)?;
        if checked.relays.len() != relays.len() {
            return Err(CONTROL_RELAYS);
        }
        let bind: Ipv4Addr = required("--bind", BIND)?.parse().map_err(|_| BIND)?;
        if bind.is_unspecified()
            || bind.is_multicast()
            || bind.is_broadcast()
            || bind.is_link_local()
            || (bind.is_loopback() && !local_test)
        {
            return Err(BIND);
        }
        let (public_ip, listen_port, public_udp_port, public_tcp_port, mappings, map) = if map_ports
        {
            if ["--public-ip", "--public-udp-port", "--public-tcp-port"]
                .iter()
                .any(|name| single.contains_key(name))
                || !maps.is_empty()
            {
                return Err(MAP_EXCLUSIVE);
            }
            let listen_port =
                high_port(required("--listen-port", LISTEN_PORT)?).ok_or(LISTEN_PORT)?;
            let gateway = single
                .get("--gateway")
                .map(|value| {
                    let gateway: Ipv4Addr = value.parse().map_err(|_| GATEWAY)?;
                    if gateway.is_unspecified()
                        || gateway.is_multicast()
                        || gateway.is_broadcast()
                        || gateway.is_link_local()
                        || (gateway.is_loopback() && !local_test)
                    {
                        return Err(GATEWAY);
                    }
                    Ok(gateway)
                })
                .transpose()?;
            if !local_test
                && (single.contains_key("--gateway-port") || single.contains_key("--ssdp"))
            {
                return Err(FIXTURE_ONLY);
            }
            let gateway_port = single
                .get("--gateway-port")
                .map(|value| {
                    value
                        .parse::<u16>()
                        .ok()
                        .filter(|port| *port != 0)
                        .ok_or(GATEWAY_PORT)
                })
                .transpose()?;
            let ssdp = single
                .get("--ssdp")
                .map(|value| value.parse::<SocketAddrV4>().map_err(|_| SSDP))
                .transpose()?;
            (
                Ipv4Addr::UNSPECIFIED,
                listen_port,
                0,
                0,
                Vec::new(),
                Some(MapSettings {
                    gateway,
                    gateway_port,
                    ssdp,
                }),
            )
        } else {
            if ["--gateway", "--gateway-port", "--ssdp"]
                .iter()
                .any(|name| single.contains_key(name))
            {
                return Err(MAP_ONLY);
            }
            let public_ip: Ipv4Addr = required("--public-ip", PUBLIC_IP)?
                .parse()
                .map_err(|_| PUBLIC_IP)?;
            let fixture_public =
                local_test && !public_ip.is_unspecified() && !public_ip.is_multicast();
            if !public_v4(public_ip) && !fixture_public {
                return Err(PUBLIC_IP);
            }
            let listen_port =
                high_port(required("--listen-port", LISTEN_PORT)?).ok_or(LISTEN_PORT)?;
            let public_udp_port = high_port(required("--public-udp-port", PUBLIC_UDP_PORT)?)
                .ok_or(PUBLIC_UDP_PORT)?;
            let public_tcp_port = high_port(required("--public-tcp-port", PUBLIC_TCP_PORT)?)
                .ok_or(PUBLIC_TCP_PORT)?;
            if maps.is_empty() || maps.len() > MAX_MAPPINGS {
                return Err(PORT_MAP);
            }
            let mut mappings = Vec::with_capacity(maps.len());
            let mut locals = std::collections::HashSet::new();
            let mut publics = std::collections::HashSet::new();
            for map in maps {
                let (local, public) = map.split_once(':').ok_or(PORT_MAP)?;
                let local = high_port(local).ok_or(PORT_MAP)?;
                let public = high_port(public).ok_or(PORT_MAP)?;
                // UDP allocation ports share the interface with the UDP and TCP
                // listener locally and with the UDP listener on the router.
                if local == listen_port
                    || public == public_udp_port
                    || !locals.insert(local)
                    || !publics.insert(public)
                {
                    return Err(PORT_MAP);
                }
                mappings.push((local, public));
            }
            if bind == public_ip
                && (mappings.iter().any(|(local, public)| local != public)
                    || public_udp_port != listen_port
                    || public_tcp_port != listen_port)
            {
                return Err(SAME_ADDRESS);
            }
            (
                public_ip,
                listen_port,
                public_udp_port,
                public_tcp_port,
                mappings,
                None,
            )
        };
        let allocations = single
            .get("--max-allocations")
            .map_or(Some(HOME_ALLOCATIONS), |value| {
                bounded(value, MAX_ALLOCATIONS)
            })
            .ok_or(ALLOCATIONS)?;
        let per_user = match single.get("--max-per-user") {
            Some(value) => bounded(value, MAX_PER_USER)
                .filter(|value| *value <= allocations)
                .ok_or(PER_USER)?,
            None => HOME_PER_USER.min(allocations),
        };
        let connections = single
            .get("--max-tcp-connections")
            .map_or(Some(HOME_CONNECTIONS), |value| {
                bounded(value, MAX_CONNECTIONS)
            })
            .ok_or(CONNECTIONS)?;
        let bytes_per_second = match single.get("--bytes-per-second") {
            Some(value) => decimal(value)
                .then(|| value.parse::<u64>().ok())
                .flatten()
                .filter(|value| (1..=MAX_BYTES_PER_SECOND).contains(value))
                .ok_or(BANDWIDTH)?,
            None => HOME_BYTES_PER_SECOND,
        };
        let aggregate_bytes_per_second = match single.get("--aggregate-bytes-per-second") {
            Some(value) => decimal(value)
                .then(|| value.parse::<u64>().ok())
                .flatten()
                .filter(|value| (1..=MAX_BYTES_PER_SECOND).contains(value))
                .ok_or(AGGREGATE)?,
            None => HOME_AGGREGATE_BYTES_PER_SECOND,
        };
        Ok(Self {
            secret,
            local_test,
            pairing_key: pairing_key.to_owned(),
            state_file: PathBuf::from(state_file),
            relays: checked.relays,
            bind,
            public_ip,
            listen_port,
            public_udp_port,
            public_tcp_port,
            mappings,
            map,
            allocations,
            per_user,
            connections,
            bytes_per_second,
            aggregate_bytes_per_second,
        })
    }

    /// Exactly two TURN URLs on the public IPv4 literal and the listener's
    /// external ports. No `turns:`: there is no certificate in this mode.
    pub(crate) fn urls(&self) -> Vec<String> {
        vec![
            format!(
                "turn:{}:{}?transport=udp",
                self.public_ip, self.public_udp_port
            ),
            format!(
                "turn:{}:{}?transport=tcp",
                self.public_ip, self.public_tcp_port
            ),
        ]
    }

    /// Take the router's grant as the public address, listener ports and
    /// allocation map. The same rules as the explicit options apply.
    pub(crate) fn apply(&mut self, values: &Values) -> Result<(), SetupError> {
        let fixture_public = self.local_test
            && !values.public_ip.is_unspecified()
            && !values.public_ip.is_multicast();
        if !public_v4(values.public_ip) && !fixture_public {
            return Err(PUBLIC_IP);
        }
        if values.udp_port < 1024 || values.tcp_port < 1024 {
            return Err(PORT_MAP);
        }
        let mut locals = std::collections::HashSet::new();
        let mut publics = std::collections::HashSet::new();
        let valid = !values.map.is_empty()
            && values.map.len() <= MAX_MAPPINGS
            && values.map.iter().all(|(local, public)| {
                *local >= 1024
                    && *public >= 1024
                    && *local != self.listen_port
                    && *public != values.udp_port
                    && locals.insert(*local)
                    && publics.insert(*public)
            });
        if !valid {
            return Err(PORT_MAP);
        }
        self.public_ip = values.public_ip;
        self.public_udp_port = values.udp_port;
        self.public_tcp_port = values.tcp_port;
        self.mappings = values.map.clone();
        Ok(())
    }

    /// What the mapping thread is asked to do, when `--map-ports` is set.
    fn map_plan(&self) -> Option<Plan> {
        let map = self.map.as_ref()?;
        let mut options = PortmapOptions {
            gateway: map.gateway,
            ..PortmapOptions::default()
        };
        if let Some(port) = map.gateway_port {
            options.gateway_port = port;
        }
        if let Some(ssdp) = map.ssdp {
            options.ssdp = ssdp;
        }
        let wanted = self.allocations as usize;
        let mut record = self.state_file.clone().into_os_string();
        record.push(".mappings");
        Some(Plan {
            options,
            bind: self.bind,
            listen_port: self.listen_port,
            wanted,
            minimum: wanted.min(mapping::MINIMUM_PORTS),
            record: PathBuf::from(record),
            ports: mapping::DYNAMIC_PORTS,
            local_test: self.local_test,
        })
    }

    pub(crate) fn relay_config(&self) -> turn::Config {
        let mut config = turn::Config::local(self.secret.clone());
        config.listen = SocketAddr::from((self.bind, self.listen_port));
        config.relay_ip = self.bind.into();
        config.advertised_ip = Some(self.public_ip.into());
        config.relay_port_range = None;
        config.relay_port_mappings = Some(
            self.mappings
                .iter()
                .map(|(local, public)| RelayPortMapping {
                    local_port: *local,
                    advertised_port: *public,
                })
                .collect(),
        );
        // A mapped relay cannot hold more allocations than the router gave
        // ports for.
        let allocations = if self.map.is_some() {
            self.allocations.min(self.mappings.len() as u32)
        } else {
            self.allocations
        };
        config.max_allocations = allocations as usize;
        config.max_per_user = self.per_user.min(allocations) as usize;
        config.max_connections = self.connections as usize;
        config.bytes_per_second = self.bytes_per_second;
        config.aggregate_bytes_per_second = Some(self.aggregate_bytes_per_second);
        config.allow_loopback_peers = self.local_test && self.bind.is_loopback();
        config
    }
}

/// What the status line reports, published by the forwarding thread after
/// each poll and read by the monitor. Three numbers and nothing else: the
/// relay never hands the monitor an address, a login or a key.
#[derive(Default)]
struct Counts {
    allocations: AtomicU64,
    bytes_relayed: AtomicU64,
    /// Unix seconds of the newest allocation from a non-local address; 0 for
    /// none (no real allocation is made at the epoch).
    last_allocation: AtomicU64,
    /// What an earlier relay in this run already counted, so a restart
    /// after a router change does not make the numbers go backwards.
    carried_bytes: u64,
    carried_last: u64,
}
impl Counts {
    fn publish(&self, server: &Server) {
        self.allocations
            .store(server.allocation_count() as u64, Ordering::Relaxed);
        self.bytes_relayed.store(
            self.carried_bytes
                .saturating_add(server.stats().forwarded_bytes),
            Ordering::Relaxed,
        );
        self.last_allocation.store(
            server
                .last_remote_allocation()
                .unwrap_or(0)
                .max(self.carried_last),
            Ordering::Relaxed,
        );
    }
    fn snapshot(&self) -> (u64, u64, Option<u64>) {
        let last = self.last_allocation.load(Ordering::Relaxed);
        (
            self.allocations.load(Ordering::Relaxed),
            self.bytes_relayed.load(Ordering::Relaxed),
            (last != 0).then_some(last),
        )
    }
}

/// The one status line shape: counts only, fixed keys, so its size is
/// bounded and a supervisor can show it as it stands.
fn status_line((allocations, bytes_relayed, last): (u64, u64, Option<u64>)) -> Value {
    json!({
        "v":1,
        "event":"status",
        "allocations":allocations,
        "bytesRelayed":bytes_relayed,
        "lastAllocation":last,
    })
}

/// The TURN relay, in this process, so one stdin guard ends both.
struct EmbeddedRelay {
    stop: Arc<AtomicBool>,
    counts: Arc<Counts>,
    thread: Option<thread::JoinHandle<()>>,
}
impl EmbeddedRelay {
    fn start(config: turn::Config, carried: (u64, Option<u64>)) -> io::Result<Self> {
        let mut server = Server::bind(config)?;
        let stop = Arc::new(AtomicBool::new(false));
        let running = stop.clone();
        let counts = Arc::new(Counts {
            carried_bytes: carried.0,
            carried_last: carried.1.unwrap_or(0),
            ..Counts::default()
        });
        let published = counts.clone();
        let thread = thread::Builder::new()
            .name("spry-forwarding".into())
            .spawn(move || {
                while !running.load(Ordering::Acquire) {
                    if server.poll_once(Duration::from_millis(50)).is_err() {
                        break;
                    }
                    published.publish(&server);
                }
            })?;
        Ok(Self {
            stop,
            counts,
            thread: Some(thread),
        })
    }
    fn running(&self) -> bool {
        self.thread
            .as_ref()
            .is_some_and(|thread| !thread.is_finished())
    }
    fn counts(&self) -> (u64, u64, Option<u64>) {
        self.counts.snapshot()
    }
    fn halt(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
    /// Stop forwarding, free the ports and bind the new configuration. The
    /// allocations on the old one end; clients renew through ICE. The
    /// counts carry over.
    fn restart(&mut self, config: &turn::Config) -> io::Result<()> {
        let (_, bytes, last) = self.counts();
        self.halt();
        let mut failure = io::Error::from(io::ErrorKind::AddrInUse);
        // The old sockets close with the thread; a TCP listener may need a
        // moment to be free again.
        for _ in 0..10 {
            match Self::start(config.clone(), (bytes, last)) {
                Ok(relay) => {
                    *self = relay;
                    return Ok(());
                }
                Err(error) => failure = error,
            }
            thread::sleep(Duration::from_millis(100));
        }
        Err(failure)
    }
}
impl Drop for EmbeddedRelay {
    fn drop(&mut self) {
        self.halt();
    }
}

/// Answers the room-grant control paths and nothing else, and adds the
/// signed `spry-standard-v1` card to grant and credential answers.
pub(crate) struct Handler {
    state: Arc<ServiceState>,
    identity: Arc<Identity>,
    card: Mutex<Option<(u64, Event)>>,
}
impl Handler {
    pub(crate) fn new(state: Arc<ServiceState>, identity: Arc<Identity>) -> Self {
        Self {
            state,
            identity,
            card: Mutex::new(None),
        }
    }
    /// Re-signed every four minutes, so repeated answers carry a stable card.
    fn card(&self, now: u64) -> Option<Event> {
        let mut cached = self.card.lock().ok()?;
        if cached
            .as_ref()
            .is_none_or(|(time, _)| now.saturating_sub(*time) >= 240 || *time > now)
        {
            *cached = Some((now, StandardCard::sign(&self.identity, now).ok()?.event));
        }
        cached.as_ref().map(|(_, event)| event.clone())
    }
}
impl ControlHandler for Handler {
    fn handle(&self, request: &AcceptedRequest, now: u64) -> (u16, Value) {
        if !PATHS.contains(&request.path.as_str()) {
            return (404, json!({"error":"Not found."}));
        }
        match self
            .state
            .api(&request.key, &request.path, &request.body, now)
        {
            Ok(mut body) => {
                if matches!(request.path.as_str(), "/v1/grants" | "/v1/credentials") {
                    let Some(card) = self
                        .card(now)
                        .and_then(|card| serde_json::to_value(card).ok())
                    else {
                        return (503, json!({"error":"Spry is temporarily unavailable."}));
                    };
                    body["node"] = card;
                }
                (200, body)
            }
            Err(Refused(status, message)) => (status, json!({"error":message})),
        }
    }
}

/// Prepare the authority: sealed, with the supervising app's pairing trusted
/// and every answer advertising the `spry:` endpoint.
pub(crate) fn authority(
    settings: &Settings,
    endpoint: &str,
    now: u64,
) -> Result<(Authority, String), SetupError> {
    let mut config = Config::new(
        UNUSED_ORIGIN,
        &format!("{UNUSED_ORIGIN}/"),
        &settings.pairing_key,
        &settings.secret,
        Some(settings.state_file.clone()),
    )
    .map_err(|_| PAIRING_KEY)?;
    config.seal = Seal::Required;
    config.urls = settings.urls();
    config.readiness = "Spry is starting.";
    let mut authority = Authority::new(config);
    authority.restore().map_err(|_| STATE)?;
    authority.config.transport_endpoint = Some(endpoint.to_owned());
    let pairing = authority
        .trust_pairing(&settings.pairing_key, now)
        .map_err(|Refused(status, _)| if status == 400 { PAIRING_KEY } else { STATE })?;
    Ok((authority, pairing))
}

/// Which host the node lives in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Host {
    /// `spry-node supervised`: a child process. Lines go to stdout, stdin is
    /// the lifetime, SIGINT and SIGTERM stop it, and it ends the process.
    Process,
    /// Inside the host's own process (`embedded`): lines go to the host's
    /// sink, the host's stop request is the lifetime, no signal handler is
    /// installed and the process is never ended.
    Embedded,
}

/// Where the node's single-line JSON objects go.
#[derive(Clone)]
pub(crate) struct Output(Arc<dyn Fn(&str) + Send + Sync>);
impl Output {
    fn stdout() -> Self {
        Self(Arc::new(|text: &str| {
            let mut out = io::stdout().lock();
            let _ = writeln!(out, "{text}");
            let _ = out.flush();
        }))
    }
    pub(crate) fn line(&self, value: Value) {
        (self.0)(&value.to_string());
    }
}

/// How the supervisor's pipe ended, or that the host asked the node to stop.
#[derive(Default)]
pub(crate) struct Lifetime {
    closed: tokio::sync::Notify,
    failed: AtomicBool,
}
impl Lifetime {
    /// Ask the node for an orderly stop: the relay's ports are freed and its
    /// router mappings removed before it ends.
    pub(crate) fn close(&self) {
        self.failed.store(false, Ordering::Release);
        self.closed.notify_one();
    }
}
/// Seconds a node that was asked to stop has to finish removing its router
/// mappings before it exits regardless.
pub(crate) const STOP_SECONDS: u64 = 5;

/// The supervisor's stdin pipe is the node's lifetime. EOF ends the whole
/// process, including the forwarding thread; the OS closes every socket.
/// With `--map-ports` the node first tells the main loop, which removes its
/// router mappings within a bounded time, and exits by itself after
/// [`STOP_SECONDS`] if that does not finish.
fn watch_stdin(graceful: Option<Arc<Lifetime>>) -> io::Result<()> {
    thread::Builder::new()
        .name("spry-parent-lifetime".into())
        .spawn(move || {
            use std::io::Read;
            let mut input = io::stdin().lock();
            let mut bytes = [0; 4096];
            let failed = loop {
                match input.read(&mut bytes) {
                    Ok(0) => break false,
                    Ok(_) => (),
                    Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                    Err(_) => break true,
                }
            };
            if let Some(lifetime) = graceful {
                lifetime.failed.store(failed, Ordering::Release);
                lifetime.closed.notify_one();
                thread::sleep(Duration::from_secs(STOP_SECONDS));
            }
            std::process::exit(i32::from(failed));
        })
        .map(|_| ())
}

/// SIGINT and SIGTERM for a child process. A node in its host's process
/// installs no handler: the signals belong to the host.
struct Signals {
    enabled: bool,
    #[cfg(unix)]
    terminate: Option<tokio::signal::unix::Signal>,
}
impl Signals {
    fn new(host: Host) -> io::Result<Self> {
        let enabled = host == Host::Process;
        Ok(Self {
            enabled,
            #[cfg(unix)]
            terminate: if enabled {
                Some(tokio::signal::unix::signal(
                    tokio::signal::unix::SignalKind::terminate(),
                )?)
            } else {
                None
            },
        })
    }
    /// Completes when the process is asked to stop; never for a node in its
    /// host's process.
    async fn recv(&mut self) {
        if !self.enabled {
            return std::future::pending().await;
        }
        #[cfg(unix)]
        if let Some(terminate) = self.terminate.as_mut() {
            tokio::select! {
                _ = tokio::signal::ctrl_c() => {}
                _ = terminate.recv() => {}
            }
            return;
        }
        let _ = tokio::signal::ctrl_c().await;
    }
}

fn set_credentials(state: &ServiceState, urls: Option<Vec<String>>, ready: bool) {
    if let Ok(mut authority) = state.lock() {
        if let Some(urls) = urls {
            authority.config.urls = urls;
        }
        authority.config.ready = ready;
    }
}

pub(crate) async fn run(
    args: &[String],
    environment: Environment,
    host: Host,
    out: &Output,
    lifetime: Arc<Lifetime>,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut settings = Settings::parse_for(args, &environment, host)?;
    if host == Host::Process {
        watch_stdin(settings.map.is_some().then(|| lifetime.clone()))?;
    }
    let options = relay_options(
        settings.local_test,
        environment.socks_proxy.clone(),
        environment.control_ca_file.clone(),
    )?;
    let identity = Arc::new(Identity::derive(&settings.secret).map_err(|_| IDENTITY)?);
    let endpoint = ControlEndpoint::new(
        identity.public_key(),
        settings.relays.clone(),
        options.policy,
    )
    .map_err(|_| CONTROL_RELAYS)?;
    let uri = endpoint.uri().map_err(|_| CONTROL_RELAYS)?;
    // Ask the router first, when told to: the public address and ports are
    // what it grants. The thread keeps renewing them and removes them when
    // this function returns.
    let mut signals = Signals::new(host)?;
    let (updates_in, mut updates) = tokio::sync::mpsc::unbounded_channel::<Update>();
    let mut task = None;
    if let Some(plan) = settings.map_plan() {
        task = Some(mapping::Task::spawn(plan, updates_in.clone()).map_err(|_| MAPPING_START)?);
        loop {
            tokio::select! {
                _ = signals.recv() => {
                    release(task.take(), &mut updates, out);
                    return Ok(());
                }
                _ = lifetime.closed.notified() => {
                    release(task.take(), &mut updates, out);
                    return Ok(());
                }
                update = updates.recv() => {
                    let Some(update) = update else { return Err(CannotHost.into()) };
                    if let Some(event) = update.event() {
                        out.line(event);
                    }
                    match update {
                        Update::Mapped { values, .. } => {
                            settings.apply(&values)?;
                            break;
                        }
                        Update::Failed(_) => return Err(CannotHost.into()),
                        _ => {}
                    }
                }
            }
        }
    }
    // Bind before touching state, so a port in use changes nothing on disk.
    let mut relay =
        EmbeddedRelay::start(settings.relay_config(), (0, None)).map_err(|_| RELAY_START)?;
    let (mut authority, pairing) = authority(&settings, &uri, now())?;
    authority.config.ready = true;
    let state = Arc::new(ServiceState::new(authority));
    let runtime = SignallingRuntime::start(
        identity.clone(),
        Arc::new(Handler::new(state.clone(), identity)),
        options,
    );
    runtime.control.configure(endpoint);
    out.line(json!({
        "v":1,
        "event":"ready",
        "endpoint":uri,
        "pairing":pairing,
        "urls":settings.urls(),
        "relayPortMap":settings.mappings,
    }));
    let mut reported = relay.counts();
    out.line(status_line(reported));
    let mut monitor = tokio::time::interval(Duration::from_secs(1));
    let mut connected = 0;
    let mut seconds = 0_u64;
    let result = loop {
        tokio::select! {
            _ = signals.recv() => break Ok(()),
            _ = lifetime.closed.notified() => {
                break if lifetime.failed.load(Ordering::Acquire) {
                    Err(STDIN_READ.into())
                } else {
                    Ok(())
                };
            }
            update = updates.recv() => {
                let Some(update) = update else { continue };
                if let Some(event) = update.event() {
                    out.line(event);
                }
                match update {
                    Update::Changed { values, .. } => {
                        // The router moved something the relay hands out.
                        // Guests asking now wait; then the relay and the
                        // credential answers both carry the new values.
                        set_credentials(&state, None, false);
                        if settings.apply(&values).is_err() {
                            break Err(CannotHost.into());
                        }
                        if relay.restart(&settings.relay_config()).is_err() {
                            break Err(RELAY_START.into());
                        }
                        set_credentials(&state, Some(settings.urls()), true);
                        out.line(json!({
                            "v":1,
                            "event":"urls",
                            "urls":settings.urls(),
                            "relayPortMap":settings.mappings,
                        }));
                    }
                    Update::Lost(_) => break Err(CannotHost.into()),
                    _ => {}
                }
            }
            _ = monitor.tick() => {
                if !relay.running() {
                    break Err(RELAY_STOPPED.into());
                }
                let active = runtime.control.active_relays();
                if (active == 0) != (connected == 0) {
                    out.line(json!({"v":1,"event":"control","relays":active}));
                }
                connected = active;
                // Counts again only when they have moved, and no faster than
                // every few seconds, so the line is bounded and silent when idle.
                seconds += 1;
                if seconds % STATUS_SECONDS == 0 {
                    let counts = relay.counts();
                    if counts != reported {
                        out.line(status_line(counts));
                        reported = counts;
                    }
                }
            }
        }
    };
    drop(runtime);
    // Free the relay's ports first, then give the router's back.
    drop(relay);
    release(task.take(), &mut updates, out);
    result
}

/// Remove the node's router mappings, if it has any, and print what the
/// mapping thread reported while doing so (`released`).
fn release(
    task: Option<mapping::Task>,
    updates: &mut tokio::sync::mpsc::UnboundedReceiver<Update>,
    out: &Output,
) {
    if let Some(mut task) = task {
        task.stop();
        while let Ok(update) = updates.try_recv() {
            if let Some(event) = update.event() {
                out.line(event);
            }
        }
    }
}

/// The exit code for how [`run`] ended, and the refusal to show, if any.
/// Only refusals that name a setting are given; other errors may carry
/// configuration values.
pub(crate) fn exit_of(result: Result<(), Box<dyn std::error::Error>>) -> (i32, Option<String>) {
    match result {
        Ok(()) => (0, None),
        Err(error) if error.downcast_ref::<CannotHost>().is_some() => {
            (EXIT_CANNOT_HOST, Some(CannotHost.to_string()))
        }
        Err(error) => (
            1,
            error.downcast_ref::<SetupError>().map(ToString::to_string),
        ),
    }
}

/// The node's own tokio runtime: two workers, as the other profiles use.
pub(crate) fn runtime() -> io::Result<tokio::runtime::Runtime> {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .max_blocking_threads(2)
        .enable_all()
        .build()
}

/// Entry point for `spry-node supervised ...`.
pub(crate) fn main(args: Vec<std::ffi::OsString>) {
    let Some(args) = args
        .into_iter()
        .map(|arg| arg.into_string().ok())
        .collect::<Option<Vec<String>>>()
    else {
        eprintln!("Spry supervised mode stopped: {ARGUMENT}.");
        std::process::exit(1);
    };
    let Ok(runtime) = runtime() else {
        eprintln!("Spry could not start.");
        std::process::exit(1);
    };
    let result = Environment::read()
        .map_err(Into::into)
        .and_then(|environment| {
            runtime.block_on(run(
                &args,
                environment,
                Host::Process,
                &Output::stdout(),
                Arc::new(Lifetime::default()),
            ))
        });
    match exit_of(result) {
        (0, _) => {}
        (code, refusal) => {
            match refusal {
                Some(refusal) => eprintln!("Spry supervised mode stopped: {refusal}."),
                None => eprintln!("Spry supervised mode stopped. Check the supervisor's settings."),
            }
            std::process::exit(code);
        }
    }
}

#[cfg(test)]
mod tests;
