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
    node::{ServiceState, relay_options_from_environment},
    now,
    public::SetupError,
    public_v4,
    signalling::{ControlHandler, SignallingRuntime},
    standard::{MAX_ALLOCATIONS, MAX_BYTES_PER_SECOND, MAX_CONNECTIONS, MAX_PER_USER, bounded},
};
use serde_json::{Value, json};
use spry_access::{Authority, Config, Refused, Seal};
use spry_link::{
    control::{AcceptedRequest, ControlEndpoint, RelayPolicy},
    identity::{Event, Identity},
    standard::StandardCard,
};
use spry_turn::turn::{self, RelayPortMapping, Server};
use std::{
    env,
    io::{self, Write},
    net::{Ipv4Addr, SocketAddr},
    path::PathBuf,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::Duration,
};

/// Home defaults from the owner decisions of 28 October 2026. Each may be
/// raised by the supervisor up to the standard profile's maximum.
pub(crate) const HOME_ALLOCATIONS: u32 = 8;
pub(crate) const HOME_PER_USER: u32 = 2;
pub(crate) const HOME_CONNECTIONS: u32 = 16;
pub(crate) const HOME_BYTES_PER_SECOND: u64 = 125_000;
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
const ALLOCATIONS: SetupError =
    SetupError("--max-allocations must be a decimal integer from 1 to 32");
const PER_USER: SetupError = SetupError(
    "--max-per-user must be a decimal integer from 1 to 8 and not exceed --max-allocations",
);
const CONNECTIONS: SetupError =
    SetupError("--max-tcp-connections must be a decimal integer from 1 to 32");
const BANDWIDTH: SetupError =
    SetupError("--bytes-per-second must be a decimal integer from 1 to 67108864");
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

/// The `SPRY_` environment this mode reads. Every other `SPRY_` name refuses
/// startup, so a setting meant for another profile cannot appear to apply.
#[derive(Default)]
pub(crate) struct Environment {
    secret: Option<Vec<u8>>,
    seal: Option<String>,
    local_test: Option<String>,
    foreign: bool,
}
impl Environment {
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
                // Outbound control options, read by the shared relay rules.
                "SPRY_SOCKS_PROXY" | "SPRY_CONTROL_CA_FILE" => {}
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
    allocations: u32,
    per_user: u32,
    connections: u32,
    bytes_per_second: u64,
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
    pub(crate) fn parse(args: &[String], environment: &Environment) -> Result<Self, SetupError> {
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
        let mut iter = args.iter();
        while let Some(option) = iter.next() {
            let option = option.as_str();
            if option == "--exit-on-stdin-close" {
                if stdin {
                    return Err(ARGUMENT);
                }
                stdin = true;
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
                    | "--max-allocations"
                    | "--max-per-user"
                    | "--max-tcp-connections"
                    | "--bytes-per-second"
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
        if !stdin {
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
        let public_ip: Ipv4Addr = required("--public-ip", PUBLIC_IP)?
            .parse()
            .map_err(|_| PUBLIC_IP)?;
        let fixture_public = local_test && !public_ip.is_unspecified() && !public_ip.is_multicast();
        if !public_v4(public_ip) && !fixture_public {
            return Err(PUBLIC_IP);
        }
        let listen_port = high_port(required("--listen-port", LISTEN_PORT)?).ok_or(LISTEN_PORT)?;
        let public_udp_port =
            high_port(required("--public-udp-port", PUBLIC_UDP_PORT)?).ok_or(PUBLIC_UDP_PORT)?;
        let public_tcp_port =
            high_port(required("--public-tcp-port", PUBLIC_TCP_PORT)?).ok_or(PUBLIC_TCP_PORT)?;
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
            allocations,
            per_user,
            connections,
            bytes_per_second,
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
        config.max_allocations = self.allocations as usize;
        config.max_per_user = self.per_user as usize;
        config.max_connections = self.connections as usize;
        config.bytes_per_second = self.bytes_per_second;
        config.allow_loopback_peers = self.local_test && self.bind.is_loopback();
        config
    }
}

/// The TURN relay, in this process, so one stdin guard ends both.
struct EmbeddedRelay {
    stop: Arc<AtomicBool>,
    thread: Option<thread::JoinHandle<()>>,
}
impl EmbeddedRelay {
    fn start(config: turn::Config) -> io::Result<Self> {
        let mut server = Server::bind(config)?;
        let stop = Arc::new(AtomicBool::new(false));
        let running = stop.clone();
        let thread = thread::Builder::new()
            .name("spry-forwarding".into())
            .spawn(move || {
                while !running.load(Ordering::Acquire) {
                    if server.poll_once(Duration::from_millis(50)).is_err() {
                        break;
                    }
                }
            })?;
        Ok(Self {
            stop,
            thread: Some(thread),
        })
    }
    fn running(&self) -> bool {
        self.thread
            .as_ref()
            .is_some_and(|thread| !thread.is_finished())
    }
}
impl Drop for EmbeddedRelay {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
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

fn line(value: Value) {
    let mut out = io::stdout().lock();
    let _ = writeln!(out, "{value}");
    let _ = out.flush();
}

/// The supervisor's stdin pipe is the node's lifetime. EOF ends the whole
/// process, including the forwarding thread; the OS closes every socket.
fn watch_stdin() -> io::Result<()> {
    thread::Builder::new()
        .name("spry-parent-lifetime".into())
        .spawn(|| {
            use std::io::Read;
            let mut input = io::stdin().lock();
            let mut bytes = [0; 4096];
            loop {
                match input.read(&mut bytes) {
                    Ok(0) => std::process::exit(0),
                    Ok(_) => (),
                    Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                    Err(_) => std::process::exit(1),
                }
            }
        })
        .map(|_| ())
}

async fn run(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let settings = Settings::parse(args, &Environment::read()?)?;
    watch_stdin()?;
    let options = relay_options_from_environment()?;
    let identity = Arc::new(Identity::derive(&settings.secret).map_err(|_| IDENTITY)?);
    let endpoint = ControlEndpoint::new(
        identity.public_key(),
        settings.relays.clone(),
        options.policy,
    )
    .map_err(|_| CONTROL_RELAYS)?;
    let uri = endpoint.uri().map_err(|_| CONTROL_RELAYS)?;
    // Bind before touching state, so a port in use changes nothing on disk.
    let relay = EmbeddedRelay::start(settings.relay_config()).map_err(|_| RELAY_START)?;
    let (mut authority, pairing) = authority(&settings, &uri, now())?;
    authority.config.ready = true;
    let state = Arc::new(ServiceState::new(authority));
    let runtime = SignallingRuntime::start(
        identity.clone(),
        Arc::new(Handler::new(state, identity)),
        options,
    );
    runtime.control.configure(endpoint);
    line(json!({
        "v":1,
        "event":"ready",
        "endpoint":uri,
        "pairing":pairing,
        "urls":settings.urls(),
        "relayPortMap":settings.mappings,
    }));
    let mut monitor = tokio::time::interval(Duration::from_secs(1));
    let mut connected = 0;
    #[cfg(unix)]
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    let result = loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => break Ok(()),
            _ = async { #[cfg(unix)] { terminate.recv().await; } #[cfg(not(unix))] { std::future::pending::<()>().await; } } => break Ok(()),
            _ = monitor.tick() => {
                if !relay.running() {
                    break Err(RELAY_STOPPED.into());
                }
                let active = runtime.control.active_relays();
                if (active == 0) != (connected == 0) {
                    line(json!({"v":1,"event":"control","relays":active}));
                }
                connected = active;
            }
        }
    };
    drop(runtime);
    drop(relay);
    result
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
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .max_blocking_threads(2)
        .enable_all()
        .build();
    let Ok(runtime) = runtime else {
        eprintln!("Spry could not start.");
        std::process::exit(1);
    };
    if let Err(error) = runtime.block_on(run(&args)) {
        // Only refusals that name a setting are printed; other errors may
        // carry configuration values.
        match error.downcast_ref::<SetupError>() {
            Some(refusal) => eprintln!("Spry supervised mode stopped: {refusal}."),
            None => eprintln!("Spry supervised mode stopped. Check the supervisor's settings."),
        }
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests;
