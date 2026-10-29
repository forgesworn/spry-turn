//! Host lifecycle and authority integration for the optional peer adapter.
use crate::{
    mesh::{Mesh, MeshConfig},
    signalling::{ControlHandler, RelayControl, RelayOptions, SignallingRuntime},
};
use serde_json::{Value, json};
use spry_access::{Authority, MAX_BODY, Refused, Result, hash};
use spry_link::{
    control::{AcceptedRequest, ControlEndpoint, RelayPolicy},
    identity::{Event, Identity},
    registry::PeerRegistry,
};
use std::{
    env,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6},
    sync::{Arc, Mutex, OnceLock, RwLock},
    time::Duration,
};

pub(crate) struct ServiceState {
    authority: Mutex<Authority>,
    private: RwLock<Option<Arc<PrivateBridge>>>,
}
impl ServiceState {
    pub(crate) fn new(authority: Authority) -> Self {
        Self {
            authority: Mutex::new(authority),
            private: RwLock::new(None),
        }
    }
    pub(crate) fn lock(&self) -> std::sync::LockResult<std::sync::MutexGuard<'_, Authority>> {
        self.authority.lock()
    }
    pub(crate) fn private(&self) -> Result<Option<Arc<PrivateBridge>>> {
        Ok(self
            .private
            .read()
            .map_err(|_| Refused(503, "Spry is temporarily unavailable."))?
            .clone())
    }
    pub(crate) fn api(&self, key: &str, path: &str, body: &Value, now: u64) -> Result<Value> {
        if serde_json::to_vec(body)
            .map_err(|_| Refused(400, "Invalid request."))?
            .len()
            > MAX_BODY
        {
            return Err(Refused(413, "Request too large."));
        }
        let mut authority = self
            .lock()
            .map_err(|_| Refused(503, "Spry is temporarily unavailable."))?;
        authority.key_rate(key, now)?;
        let private = self.private()?;
        if path == "/v1/peers" {
            let private = private.ok_or(Refused(404, "Not found."))?;
            let pair = body["pairing"]
                .as_str()
                .ok_or(Refused(400, "Invalid request."))?;
            if !authority.pairing_authorises(pair, key) {
                return Err(Refused(403, "Spry is no longer paired. Pair it again."));
            }
            let scope = body["scope"]
                .as_str()
                .ok_or(Refused(400, "Invalid request."))?;
            let device = body["device"]
                .as_str()
                .ok_or(Refused(400, "Invalid request."))?;
            if !opaque(scope) || !opaque(device) {
                return Err(Refused(400, "Invalid request."));
            }
            let events: Vec<Event> = serde_json::from_value(body["peers"].clone())
                .map_err(|_| Refused(400, "Invalid peer routes."))?;
            let mut registry = private
                .registry
                .lock()
                .map_err(|_| Refused(503, "Spry is temporarily unavailable."))?;
            let mut next = registry.clone();
            let revision = body["revision"]
                .as_u64()
                .ok_or(Refused(400, "Invalid peer revision."))?;
            next.update_revision(
                &format!("{pair}:{}", hash(format!("{scope}:{device}"))),
                revision,
                &events,
                now,
            )
            .map_err(|_| Refused(403, "Peer routes were refused."))?;
            private
                .mesh
                .set_peers(next.active(now))
                .map_err(|_| Refused(503, "Your node is connecting."))?;
            *registry = next;
            return Ok(json!({"ok":true,"connectedPeers":private.mesh.connected_peers()}));
        }
        let mut value = authority.handle(path, key, body, now)?;
        if let Some(private) = private {
            if matches!(path, "/v1/pairings/remove" | "/v1/pairings/remove-self") {
                let mut registry = private
                    .registry
                    .lock()
                    .map_err(|_| Refused(503, "Spry is temporarily unavailable."))?;
                registry.retain_scopes(|scope| {
                    scope
                        .split_once(':')
                        .is_some_and(|(pair, _)| authority.has_pairing(pair))
                });
                let _ = private.mesh.set_peers(registry.active(now));
            }
            if matches!(path, "/v1/grants" | "/v1/credentials") {
                value["node"] = serde_json::to_value(
                    private
                        .mesh
                        .card()
                        .map_err(|_| Refused(503, "Your node is connecting."))?,
                )
                .map_err(|_| Refused(503, "Unavailable."))?;
            }
        }
        Ok(value)
    }
    pub(crate) fn clear_private(&self) {
        if let Ok(mut private) = self.private.write() {
            private.take();
        }
        if let Ok(mut authority) = self.lock() {
            authority.config.ready = false;
            authority.config.readiness = "Waiting for your node’s network.";
        }
    }
}
impl ControlHandler for ServiceState {
    fn handle(&self, request: &AcceptedRequest, now: u64) -> (u16, Value) {
        match self.api(&request.key, &request.path, &request.body, now) {
            Ok(body) => (200, body),
            Err(Refused(status, message)) => (status, json!({"error":message})),
        }
    }
}
fn opaque(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

pub(crate) struct PrivateBridge {
    pub(crate) mesh: Mesh,
    registry: Mutex<PeerRegistry>,
    control: OnceLock<RelayControl>,
    policy: RelayPolicy,
    preset_relays: Vec<String>,
}
impl PrivateBridge {
    pub(crate) fn control_ready(&self) -> bool {
        self.control
            .get()
            .is_some_and(|control| control.active_relays() > 0)
    }
    pub(crate) async fn prepare_pairing(
        &self,
        state: &ServiceState,
        key: &str,
        body: &Value,
    ) -> Result<()> {
        let endpoint = {
            let authority = state
                .lock()
                .map_err(|_| Refused(503, "Spry is temporarily unavailable."))?;
            if !authority.config.owners.contains(key) {
                return Err(Refused(403, "Choose one of this relay’s owner identities."));
            }
            if !authority.config.ready || !self.mesh.healthy() {
                return Err(Refused(503, "Your node is connecting."));
            }
            if let Some(endpoint) = &authority.config.transport_endpoint {
                ControlEndpoint::parse(endpoint, self.policy)
                    .map_err(|_| Refused(503, "Relay settings are unavailable."))?
            } else {
                let relays = if body.get("relays").is_some() {
                    serde_json::from_value(body["relays"].clone())
                        .map_err(|_| Refused(400, "Invalid relay settings."))?
                } else {
                    self.preset_relays.clone()
                };
                ControlEndpoint::new(self.mesh.public_key(), relays, self.policy).map_err(|_| {
                    Refused(
                        400,
                        "Your node needs a selected Nostr relay before pairing.",
                    )
                })?
            }
        };
        if endpoint.public_key != self.mesh.public_key() {
            return Err(Refused(
                503,
                "The pairing identity has changed. Check your node settings.",
            ));
        }
        let control = self
            .control
            .get()
            .ok_or(Refused(503, "Your node is connecting."))?;
        control.configure(endpoint.clone());
        tokio::time::timeout(Duration::from_secs(15), async {
            while control.active_relays() == 0 {
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await
        .map_err(|_| {
            Refused(
                503,
                "Spry could not reach your selected relays. Try again shortly.",
            )
        })?;
        state
            .lock()
            .map_err(|_| Refused(503, "Spry is temporarily unavailable."))?
            .set_transport_endpoint(
                key,
                endpoint
                    .uri()
                    .map_err(|_| Refused(400, "Invalid relay settings."))?,
            )
    }
}

pub(crate) struct PrivateSettings {
    bind: Option<SocketAddrV6>,
    interface: Option<String>,
    client_ip: Option<Ipv4Addr>,
    client_host: Option<String>,
    port: u16,
    peer_name: Option<String>,
    resolver: Option<crate::resolver::PeerResolver>,
    secret: Vec<u8>,
    options: RelayOptions,
    preset_relays: Vec<String>,
}
impl PrivateSettings {
    pub(crate) fn from_environment(
        secret: &[u8],
    ) -> std::result::Result<Option<Self>, Box<dyn std::error::Error>> {
        let bind = env::var("SPRY_PEER_BIND")
            .ok()
            .filter(|value| !value.is_empty())
            .map(|value| value.parse())
            .transpose()?;
        let interface = env::var("SPRY_PEER_INTERFACE")
            .ok()
            .filter(|value| !value.is_empty());
        if bind.is_none() && interface.is_none() {
            return Ok(None);
        }
        if interface.as_ref().is_some_and(|value| {
            value.len() > 16
                || !value
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || b"_.-".contains(&byte))
        }) {
            return Err("Invalid peer interface".into());
        }
        let peer_name = env::var("SPRY_PEER_NAME")
            .ok()
            .filter(|name| !name.is_empty());
        let resolver = env::var("SPRY_PEER_RESOLVER")
            .ok()
            .map(
                |server| -> std::result::Result<_, Box<dyn std::error::Error>> {
                    Ok(crate::resolver::PeerResolver::new(
                        server.parse()?,
                        env::var("SPRY_PEER_ZONE")?,
                    )?)
                },
            )
            .transpose()?;
        if peer_name.as_deref().is_some_and(|name| {
            !spry_link::peer::valid_name(name)
                || resolver
                    .as_ref()
                    .is_some_and(|resolver| !resolver.accepts(name))
        }) {
            return Err("Invalid private peer name".into());
        }
        let client_ip = env::var("SPRY_RELAY_IP")
            .ok()
            .map(|value| value.parse())
            .transpose()?;
        let client_host = env::var("SPRY_CLIENT_HOST")
            .ok()
            .filter(|value| !value.is_empty());
        if let Some(host) = &client_host {
            let url = url::Url::parse(&format!("http://{host}"))?;
            if host.len() > 253
                || !url.username().is_empty()
                || url.password().is_some()
                || url.port().is_some()
                || url.path() != "/"
                || url.query().is_some()
                || url.fragment().is_some()
            {
                return Err("Invalid client host".into());
            }
        }
        let port = env::var("SPRY_TURN_PORT").map_or(Ok(3478), |value| value.parse())?;
        if port < 1024 {
            return Err("Invalid client port".into());
        }
        let options = relay_options_from_environment()?;
        let preset_relays = env::var("SPRY_CONTROL_RELAYS")
            .ok()
            .filter(|value| !value.is_empty())
            .map(|value| serde_json::from_str(&value))
            .transpose()?
            .unwrap_or_default();
        Ok(Some(Self {
            bind,
            interface,
            client_ip,
            client_host,
            port,
            peer_name,
            resolver,
            secret: secret.to_vec(),
            options,
            preset_relays,
        }))
    }
    pub(crate) fn audience(&self) -> Result<String> {
        Identity::derive(&self.secret)
            .map(|identity| identity.public_key())
            .map_err(|_| Refused(503, "Invalid node identity."))
    }
    pub(crate) async fn start(
        &self,
        state: Arc<ServiceState>,
    ) -> Result<Option<SignallingRuntime>> {
        if self.resolver.is_some() && self.peer_name.is_none() {
            return Ok(None);
        }
        let address = self.bind.or_else(|| {
            self.interface
                .as_ref()
                .and_then(|interface| interface_address(interface))
                .map(|ip| SocketAddrV6::new(ip, 3745, 0, 0))
        });
        let Some(address) = address else {
            return Ok(None);
        };
        let Some(ip) = self.client_ip.or_else(client_address) else {
            return Ok(None);
        };
        let mesh = Mesh::start(MeshConfig {
            peer_name: self.peer_name.clone(),
            resolver: self.resolver.clone(),
            client_listen: SocketAddrV4::new(ip, self.port),
            peer_listen: address,
            secret: self.secret.clone(),
        })
        .await
        .map_err(|_| Refused(503, "Your node’s relay could not start."))?;
        let identity = mesh.identity();
        let registry = PeerRegistry::new(mesh.public_key())
            .map_err(|_| Refused(503, "Invalid node identity."))?;
        let private = Arc::new(PrivateBridge {
            mesh,
            registry: Mutex::new(registry),
            control: OnceLock::new(),
            policy: self.options.policy,
            preset_relays: self.preset_relays.clone(),
        });
        let endpoint = {
            let authority = state.lock().map_err(|_| Refused(503, "Unavailable."))?;
            authority
                .config
                .transport_endpoint
                .as_ref()
                .map(|endpoint| ControlEndpoint::parse(endpoint, self.options.policy))
                .transpose()
                .map_err(|_| Refused(503, "Relay settings are unavailable."))?
        };
        if endpoint
            .as_ref()
            .is_some_and(|endpoint| endpoint.public_key != identity.public_key())
        {
            return Err(Refused(503, "The pairing identity has changed."));
        }
        let runtime = SignallingRuntime::start(identity, state.clone(), self.options.clone());
        let _ = private.control.set(runtime.control.clone());
        *state
            .private
            .write()
            .map_err(|_| Refused(503, "Unavailable."))? = Some(private);
        {
            let mut authority = state.lock().map_err(|_| Refused(503, "Unavailable."))?;
            let host = self.client_host.clone().unwrap_or_else(|| ip.to_string());
            authority.config.urls = vec![
                format!("turn:{host}:{}?transport=udp", self.port),
                format!("turn:{host}:{}?transport=tcp", self.port),
            ];
            if env::var("SPRY_TLS_GATE").as_deref() == Ok("true") {
                if let Ok(url) = url::Url::parse(&authority.config.endpoint) {
                    if let Some(host) = url.host_str() {
                        authority
                            .config
                            .urls
                            .push(format!("turns:{host}:5349?transport=tcp"));
                    }
                }
            }
            authority.config.ready = true;
        }
        if let Some(endpoint) = endpoint {
            runtime.control.configure(endpoint);
        }
        Ok(Some(runtime))
    }
}
/// Outbound Nostr relay rules shared by private control and public adverts:
/// certificate validation, the optional SOCKS proxy and public-address checks.
pub(crate) fn relay_options_from_environment()
-> std::result::Result<RelayOptions, Box<dyn std::error::Error>> {
    relay_options(
        env::var("SPRY_LOCAL_TEST").as_deref() == Ok("true"),
        env::var("SPRY_SOCKS_PROXY").ok(),
        env::var("SPRY_CONTROL_CA_FILE").ok(),
    )
}
/// The same rules from values a host supplies, for a node that must not read
/// its process environment (supervised mode inside a host's own process).
pub(crate) fn relay_options(
    local_test: bool,
    socks_proxy: Option<String>,
    control_ca_file: Option<String>,
) -> std::result::Result<RelayOptions, Box<dyn std::error::Error>> {
    let policy = if local_test {
        RelayPolicy::LocalFixture
    } else {
        RelayPolicy::Public
    };
    let socks_proxy = socks_proxy
        .filter(|value| !value.is_empty())
        .map(|value| value.parse())
        .transpose()?;
    let tls = control_ca_file
        .map(
            |path| -> std::result::Result<_, Box<dyn std::error::Error>> {
                use rustls::pki_types::{CertificateDer, pem::PemObject};
                let bytes = std::fs::read(path)?;
                if bytes.len() > 262_144 {
                    return Err("Control CA file is too large".into());
                }
                let mut roots = rustls::RootCertStore::empty();
                roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
                let mut count = 0;
                for certificate in CertificateDer::pem_slice_iter(&bytes) {
                    roots.add(certificate?)?;
                    count += 1;
                    if count > 16 {
                        return Err("Too many control CA certificates".into());
                    }
                }
                if count == 0 {
                    return Err("No control CA certificate".into());
                }
                let config = rustls::ClientConfig::builder_with_provider(Arc::new(
                    rustls::crypto::ring::default_provider(),
                ))
                .with_safe_default_protocol_versions()?
                .with_root_certificates(roots)
                .with_no_client_auth();
                Ok(Arc::new(config))
            },
        )
        .transpose()?;
    Ok(RelayOptions {
        policy,
        socks_proxy,
        tls,
    })
}
fn interface_address(name: &str) -> Option<Ipv6Addr> {
    let contents = std::fs::read_to_string("/proc/net/if_inet6").ok()?;
    if contents.len() > 65_536 {
        return None;
    }
    contents
        .lines()
        .filter_map(|line| {
            let fields: Vec<_> = line.split_whitespace().collect();
            if fields.len() != 6 || fields[5] != name {
                return None;
            }
            let ip = Ipv6Addr::from(u128::from_str_radix(fields[0], 16).ok()?);
            (ip.octets()[0] & 0xfe == 0xfc).then_some(ip)
        })
        .next()
}
fn client_address() -> Option<Ipv4Addr> {
    let output = std::process::Command::new("ip")
        .args(["-j", "-4", "address", "show", "scope", "global"])
        .output()
        .ok()?;
    if !output.status.success() || output.stdout.len() > 65_536 {
        return None;
    }
    let interfaces: Value = serde_json::from_slice(&output.stdout).ok()?;
    interfaces
        .as_array()?
        .iter()
        .filter_map(|interface| interface["addr_info"].as_array())
        .flatten()
        .filter_map(|info| info["local"].as_str()?.parse::<Ipv4Addr>().ok())
        .find(|ip| {
            !IpAddr::V4(*ip).is_unspecified()
                && !ip.is_loopback()
                && !ip.is_multicast()
                && !ip.is_link_local()
        })
}
