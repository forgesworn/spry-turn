//! Fallback, lease, renewal and removal across PCP, NAT-PMP and UPnP IGD.

use crate::http::Url;
use crate::upnp::{self, Gateway, Igd, Service};
use crate::{Error, Method, Protocol, natpmp, pcp, record, route, udp};
use std::fmt;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Source of the current time, replaceable in tests.
pub type Clock = Arc<dyn Fn() -> Instant + Send + Sync>;

/// Longest lease asked of a UPnP gateway (IGDv2 allows at most a week).
const MAX_UPNP_LEASE: u32 = 604_800;

/// How a [`PortMapper`] reaches the gateway.
#[derive(Clone)]
pub struct Options {
    /// The default gateway. `None` reads it from the host's route table;
    /// Android passes the address from `LinkProperties`.
    pub gateway: Option<Ipv4Addr>,
    /// PCP and NAT-PMP port on the gateway (5351).
    pub gateway_port: u16,
    /// SSDP search address ([`upnp::SSDP`]).
    pub ssdp: SocketAddrV4,
    /// Budget for each request, retransmissions included.
    pub timeout: Duration,
    /// Protocols to try, in order.
    pub methods: Vec<Method>,
    /// Accept a UPnP gateway that grants only permanent leases (owner
    /// decision, 28 October 2026). Such a mapping must be removed on stop
    /// and again on the next launch.
    pub allow_permanent: bool,
    /// UPnP description tag; also proves ownership before a delete.
    pub description: String,
    pub clock: Clock,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            gateway: None,
            gateway_port: 5351,
            ssdp: upnp::SSDP,
            timeout: Duration::from_secs(2),
            methods: Method::ORDER.to_vec(),
            allow_permanent: true,
            description: "spry relay".to_owned(),
            clock: Arc::new(Instant::now),
        }
    }
}

impl fmt::Debug for Options {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Options")
            .field("gateway", &self.gateway)
            .field("gateway_port", &self.gateway_port)
            .field("ssdp", &self.ssdp)
            .field("timeout", &self.timeout)
            .field("methods", &self.methods)
            .field("allow_permanent", &self.allow_permanent)
            .field("description", &self.description)
            .finish_non_exhaustive()
    }
}

/// One mapping to ask for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Request {
    pub protocol: Protocol,
    pub internal_port: u16,
    /// Suggested external port; the gateway may grant another.
    pub external_port: u16,
    pub lifetime: Duration,
}

impl Request {
    /// Ask for the same external port as the internal one.
    pub fn new(protocol: Protocol, port: u16, lifetime: Duration) -> Self {
        Self {
            protocol,
            internal_port: port,
            external_port: port,
            lifetime,
        }
    }
}

/// What proves a mapping is this process's.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Owner {
    /// Only this nonce can renew or delete the mapping.
    Pcp { nonce: [u8; 12] },
    /// NAT-PMP mappings belong to the internal address and port.
    NatPmp,
    /// The control endpoint, plus the internal client, port and description
    /// tag checked before any delete.
    Upnp {
        control: Url,
        service: Service,
        description: String,
    },
}

/// A granted mapping.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Mapping {
    pub method: Method,
    pub protocol: Protocol,
    pub gateway: Ipv4Addr,
    pub internal: SocketAddrV4,
    /// External address and port. The port may differ from the internal one.
    pub external: SocketAddrV4,
    /// Granted lifetime; `None` for a permanent UPnP lease.
    pub lifetime: Option<Duration>,
    /// Lifetime asked for, reused on renewal.
    pub requested: Duration,
    pub granted_at: Instant,
    pub owner: Owner,
}

impl Mapping {
    pub fn is_permanent(&self) -> bool {
        self.lifetime.is_none()
    }
    /// Whether the gateway gave another external port than the internal one.
    pub fn translated(&self) -> bool {
        self.external.port() != self.internal.port()
    }
    /// When to renew: half the granted lifetime (design 2.2).
    pub fn renew_at(&self) -> Option<Instant> {
        self.lifetime.map(|lifetime| self.granted_at + lifetime / 2)
    }
    pub fn expires_at(&self) -> Option<Instant> {
        self.lifetime.map(|lifetime| self.granted_at + lifetime)
    }
    /// The record entry for this mapping, given the current Unix time.
    pub fn entry(&self, unix_now: u64) -> record::Entry {
        let (nonce, control, service, description) = match &self.owner {
            Owner::Pcp { nonce } => (Some(*nonce), None, None, None),
            Owner::NatPmp => (None, None, None, None),
            Owner::Upnp {
                control,
                service,
                description,
            } => (
                None,
                Some(control.to_string()),
                Some(*service),
                Some(description.clone()),
            ),
        };
        record::Entry {
            method: self.method,
            protocol: self.protocol,
            gateway: self.gateway,
            internal: self.internal,
            external_port: self.external.port(),
            expires: self
                .lifetime
                .map(|lifetime| unix_now.saturating_add(lifetime.as_secs())),
            nonce,
            control,
            service,
            description,
        }
    }
}

/// The result of a renewal.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Renewal {
    pub mapping: Mapping,
    /// The external address or port changed; whatever advertises it must be
    /// updated (for a listener, restart the relay).
    pub changed: bool,
    /// The gateway's epoch shows it lost state: every other mapping may be
    /// gone and should be requested again.
    pub gateway_restarted: bool,
}

/// One protocol that failed before another succeeded, or before all failed.
pub type Attempt = (Method, Error);

/// What happened to a recorded mapping during cleanup.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Cleanup {
    Removed,
    /// The gateway no longer has it.
    Gone,
    /// Its lease had already ended.
    Expired,
    /// NAT-PMP cannot prove ownership after a restart, so the lease is left
    /// to run out (design 2.2).
    LeftToExpire,
    /// It belongs to another gateway (another network).
    OtherNetwork,
    Failed(Error),
}

/// RFC 6887 section 8.5 epoch check: `false` when the gateway's epoch moved
/// in a way that shows it lost its mapping state.
pub fn epoch_consistent(previous: u32, current: u32, elapsed_secs: u64) -> bool {
    let (previous, current) = (u64::from(previous), u64::from(current));
    if current + 1 < previous {
        return false;
    }
    let server = current.saturating_sub(previous);
    let client = elapsed_secs;
    !(client + 2 < server - server / 16 || server + 2 < client - client / 16)
}

fn seconds(lifetime: Duration) -> Result<u32, Error> {
    let secs = u32::try_from(lifetime.as_secs()).unwrap_or(u32::MAX);
    if secs == 0 {
        return Err(Error::Invalid("lifetime must be at least one second"));
    }
    Ok(secs)
}

fn valid_description(value: &str) -> bool {
    (1..=64).contains(&value.len())
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b' ' | b'-' | b'_' | b'.'))
}

/// Port mapping on the host's default gateway.
pub struct PortMapper {
    options: Options,
    gateway: Ipv4Addr,
    local: Ipv4Addr,
    interface: Option<String>,
    method: Option<Method>,
    attempts: Vec<Attempt>,
    epoch: Option<(u32, Instant)>,
    restart_seen: bool,
    igd: Option<Igd>,
    external: Option<Ipv4Addr>,
}

impl fmt::Debug for PortMapper {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PortMapper")
            .field("gateway", &self.gateway)
            .field("method", &self.method)
            .finish_non_exhaustive()
    }
}

impl PortMapper {
    /// Find the gateway (unless given) and the local address used to reach
    /// it. Sends nothing.
    pub fn new(options: Options) -> Result<Self, Error> {
        if !valid_description(&options.description) {
            return Err(Error::Invalid("description"));
        }
        if options.methods.is_empty() || options.timeout.is_zero() {
            return Err(Error::Invalid("options"));
        }
        let (gateway, interface) = match options.gateway {
            Some(gateway) => (gateway, None),
            None => {
                let route = route::default_route()?;
                (route.gateway, route.interface)
            }
        };
        if gateway.is_unspecified() || gateway.is_multicast() || gateway.is_broadcast() {
            return Err(Error::NoGateway);
        }
        let (_, local) = udp::connect(SocketAddrV4::new(gateway, options.gateway_port))?;
        Ok(Self {
            options,
            gateway,
            local,
            interface,
            method: None,
            attempts: Vec::new(),
            epoch: None,
            restart_seen: false,
            igd: None,
            external: None,
        })
    }

    pub fn gateway(&self) -> Ipv4Addr {
        self.gateway
    }
    /// The host's address on the gateway's network.
    pub fn local(&self) -> Ipv4Addr {
        self.local
    }
    /// The default route's interface, when read from the route table.
    pub fn interface(&self) -> Option<&str> {
        self.interface.as_deref()
    }
    /// The protocol in use, once one has granted a mapping.
    pub fn method(&self) -> Option<Method> {
        self.method
    }
    /// Protocols that failed during the last fallback.
    pub fn attempts(&self) -> &[Attempt] {
        &self.attempts
    }
    /// Whether any reply since the last call showed the gateway lost state.
    pub fn take_gateway_restart(&mut self) -> bool {
        std::mem::take(&mut self.restart_seen)
    }

    fn now(&self) -> Instant {
        (self.options.clock)()
    }

    fn port(&self) -> SocketAddrV4 {
        SocketAddrV4::new(self.gateway, self.options.gateway_port)
    }

    fn observe_epoch(&mut self, epoch: u32) -> bool {
        let now = self.now();
        let restarted = self.epoch.is_some_and(|(previous, at)| {
            !epoch_consistent(previous, epoch, now.saturating_duration_since(at).as_secs())
        });
        self.epoch = Some((epoch, now));
        self.restart_seen |= restarted;
        restarted
    }

    /// Ask for a mapping. The first call tries each protocol in order and
    /// keeps the first that grants; later calls use only that protocol.
    pub fn map(&mut self, request: Request) -> Result<Mapping, Error> {
        if request.internal_port == 0 {
            return Err(Error::Invalid("internal port"));
        }
        seconds(request.lifetime)?;
        if let Some(method) = self.method {
            return self.map_with(method, request);
        }
        let mut failures = Vec::new();
        for method in self.options.methods.clone() {
            match self.map_with(method, request) {
                Ok(mapping) => {
                    self.method = Some(method);
                    self.attempts = failures;
                    return Ok(mapping);
                }
                Err(error) => failures.push((method, error)),
            }
        }
        self.attempts = failures.clone();
        Err(Error::NoMethod(failures))
    }

    fn map_with(&mut self, method: Method, request: Request) -> Result<Mapping, Error> {
        let lifetime = seconds(request.lifetime)?;
        let internal = SocketAddrV4::new(self.local, request.internal_port);
        match method {
            Method::Pcp => {
                let mut nonce = [0u8; 12];
                getrandom::fill(&mut nonce).map_err(|_| Error::Io(std::io::ErrorKind::Other))?;
                let grant = self.pcp_send(
                    nonce,
                    request.protocol,
                    request.internal_port,
                    SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, request.external_port),
                    lifetime,
                )?;
                self.observe_epoch(grant.epoch);
                self.external = Some(*grant.external.ip());
                Ok(Mapping {
                    method,
                    protocol: request.protocol,
                    gateway: self.gateway,
                    internal,
                    external: grant.external,
                    lifetime: Some(Duration::from_secs(grant.lifetime.into())),
                    requested: request.lifetime,
                    granted_at: self.now(),
                    owner: Owner::Pcp { nonce },
                })
            }
            Method::NatPmp => {
                let (address, _) = self.natpmp_external()?;
                let grant = natpmp::map(
                    self.port(),
                    request.protocol,
                    request.internal_port,
                    request.external_port,
                    lifetime,
                    self.options.timeout,
                )?;
                self.observe_epoch(grant.epoch);
                Ok(Mapping {
                    method,
                    protocol: request.protocol,
                    gateway: self.gateway,
                    internal,
                    external: SocketAddrV4::new(address, grant.external_port),
                    lifetime: Some(Duration::from_secs(grant.lifetime.into())),
                    requested: request.lifetime,
                    granted_at: self.now(),
                    owner: Owner::NatPmp,
                })
            }
            Method::Upnp => self.upnp_map(request, lifetime.min(MAX_UPNP_LEASE), internal),
        }
    }

    fn pcp_send(
        &self,
        nonce: [u8; 12],
        protocol: Protocol,
        internal_port: u16,
        suggested: SocketAddrV4,
        lifetime: u32,
    ) -> Result<pcp::Grant, Error> {
        let request = pcp::MapRequest {
            nonce,
            protocol,
            internal_port,
            suggested,
            lifetime,
            client: self.local,
        };
        pcp::send(self.port(), request, self.options.timeout)
    }

    /// The NAT-PMP external address, and whether its epoch shows a restart.
    fn natpmp_external(&mut self) -> Result<(Ipv4Addr, bool), Error> {
        let (address, epoch) = natpmp::external(self.port(), self.options.timeout)?;
        let restarted = self.observe_epoch(epoch);
        self.external = Some(address);
        Ok((address, restarted))
    }

    fn igd(&mut self) -> Result<Igd, Error> {
        if let Some(igd) = &self.igd {
            return Ok(igd.clone());
        }
        let gateway = upnp::discover(
            self.gateway,
            self.local,
            self.options.ssdp,
            self.options.timeout,
            self.options.timeout,
        )?;
        let igd = Igd {
            gateway,
            timeout: self.options.timeout,
        };
        self.igd = Some(igd.clone());
        Ok(igd)
    }

    fn igd_for(&self, control: &Url, service: Service) -> Result<Igd, Error> {
        if control.host != self.gateway {
            return Err(Error::OffLan);
        }
        Ok(Igd {
            gateway: Gateway {
                control: control.clone(),
                service,
            },
            timeout: self.options.timeout,
        })
    }

    fn upnp_map(
        &mut self,
        request: Request,
        lease: u32,
        internal: SocketAddrV4,
    ) -> Result<Mapping, Error> {
        let igd = self.igd()?;
        let description = self.options.description.clone();
        let add = |lease: u32| {
            if igd.gateway.service.is_v2() {
                igd.add_any(
                    request.protocol,
                    request.external_port,
                    internal,
                    &description,
                    lease,
                )
            } else {
                igd.add(
                    request.protocol,
                    request.external_port,
                    internal,
                    &description,
                    lease,
                )
                .map(|()| request.external_port)
            }
        };
        let (port, mut permanent) = match add(lease) {
            Ok(port) => (port, false),
            Err(Error::Refused {
                code: upnp::ONLY_PERMANENT,
                ..
            }) => {
                if !self.options.allow_permanent {
                    return Err(Error::PermanentOnly);
                }
                (add(0)?, true)
            }
            Err(error) => return Err(error),
        };
        // Read the entry back where the gateway supports it: it must show
        // this host, port and tag, and it reveals a lease silently made
        // permanent.
        match igd.entry(request.protocol, port) {
            Ok(entry) => {
                if entry.internal != internal || entry.description != description {
                    return Err(Error::NotOurs);
                }
                permanent |= entry.lease == 0;
            }
            Err(Error::Refused { .. }) | Err(Error::Malformed(_)) => {}
            Err(error) => return Err(error),
        }
        let address = igd.external_address()?;
        self.external = Some(address);
        Ok(Mapping {
            method: Method::Upnp,
            protocol: request.protocol,
            gateway: self.gateway,
            internal,
            external: SocketAddrV4::new(address, port),
            lifetime: (!permanent).then(|| Duration::from_secs(lease.into())),
            requested: request.lifetime,
            granted_at: self.now(),
            owner: Owner::Upnp {
                control: igd.gateway.control.clone(),
                service: igd.gateway.service,
                description,
            },
        })
    }

    /// Renew a mapping with the same values. A permanent UPnP mapping is
    /// re-added, which also restores it after a gateway restart.
    pub fn renew(&mut self, mapping: &Mapping) -> Result<Renewal, Error> {
        if mapping.gateway != self.gateway {
            return Err(Error::OffLan);
        }
        let lifetime = seconds(mapping.requested)?;
        let mut renewed = mapping.clone();
        let restarted = match &mapping.owner {
            Owner::Pcp { nonce } => {
                let grant = self.pcp_send(
                    *nonce,
                    mapping.protocol,
                    mapping.internal.port(),
                    mapping.external,
                    lifetime,
                )?;
                renewed.external = grant.external;
                renewed.lifetime = Some(Duration::from_secs(grant.lifetime.into()));
                self.external = Some(*grant.external.ip());
                self.observe_epoch(grant.epoch)
            }
            Owner::NatPmp => {
                let (address, restarted_before) = self.natpmp_external()?;
                let grant = natpmp::map(
                    self.port(),
                    mapping.protocol,
                    mapping.internal.port(),
                    mapping.external.port(),
                    lifetime,
                    self.options.timeout,
                )?;
                renewed.external = SocketAddrV4::new(address, grant.external_port);
                renewed.lifetime = Some(Duration::from_secs(grant.lifetime.into()));
                self.observe_epoch(grant.epoch) | restarted_before
            }
            Owner::Upnp {
                control,
                service,
                description,
            } => {
                let igd = self.igd_for(control, *service)?;
                let lease = if mapping.is_permanent() {
                    0
                } else {
                    lifetime.min(MAX_UPNP_LEASE)
                };
                igd.add(
                    mapping.protocol,
                    mapping.external.port(),
                    mapping.internal,
                    description,
                    lease,
                )?;
                let address = igd.external_address()?;
                self.external = Some(address);
                renewed.external = SocketAddrV4::new(address, mapping.external.port());
                false
            }
        };
        renewed.granted_at = self.now();
        Ok(Renewal {
            changed: renewed.external != mapping.external,
            mapping: renewed,
            gateway_restarted: restarted,
        })
    }

    /// Remove a mapping this process created.
    pub fn remove(&mut self, mapping: &Mapping) -> Result<(), Error> {
        if mapping.gateway != self.gateway {
            return Err(Error::OffLan);
        }
        match &mapping.owner {
            Owner::Pcp { nonce } => self
                .pcp_send(
                    *nonce,
                    mapping.protocol,
                    mapping.internal.port(),
                    mapping.external,
                    0,
                )
                .map(|_| ()),
            Owner::NatPmp => natpmp::map(
                self.port(),
                mapping.protocol,
                mapping.internal.port(),
                0,
                0,
                self.options.timeout,
            )
            .map(|_| ()),
            Owner::Upnp {
                control,
                service,
                description,
            } => {
                let igd = self.igd_for(control, *service)?;
                owned_delete(
                    &igd,
                    mapping.protocol,
                    mapping.external.port(),
                    mapping.internal,
                    description,
                )
                .map(|_| ())
            }
        }
    }

    /// The external address the gateway reports. PCP has no query of its
    /// own, so it returns the address from the last grant.
    pub fn external_address(&mut self) -> Result<Ipv4Addr, Error> {
        match self.method {
            Some(Method::NatPmp) => self.natpmp_external().map(|(address, _)| address),
            Some(Method::Upnp) => {
                let address = self.igd()?.external_address()?;
                self.external = Some(address);
                Ok(address)
            }
            Some(Method::Pcp) => self.external.ok_or(Error::NoAnswer),
            None => Err(Error::Invalid("no mapping yet")),
        }
    }

    /// Remove mappings a previous run recorded. Entries for another gateway
    /// are left alone; NAT-PMP entries are left to expire.
    pub fn cleanup(&mut self, entries: &[record::Entry], unix_now: u64) -> Vec<Cleanup> {
        entries
            .iter()
            .map(|entry| self.cleanup_one(entry, unix_now))
            .collect()
    }

    fn cleanup_one(&mut self, entry: &record::Entry, unix_now: u64) -> Cleanup {
        if entry.gateway != self.gateway {
            return Cleanup::OtherNetwork;
        }
        let expired = entry.expires.is_some_and(|at| at <= unix_now);
        let outcome = match entry.method {
            Method::Pcp => {
                if expired {
                    return Cleanup::Expired;
                }
                let Some(nonce) = entry.nonce else {
                    return Cleanup::Failed(Error::Record("incomplete entry"));
                };
                self.pcp_send(
                    nonce,
                    entry.protocol,
                    entry.internal.port(),
                    SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, entry.external_port),
                    0,
                )
                .map(|_| Cleanup::Removed)
            }
            Method::NatPmp => {
                return if expired {
                    Cleanup::Expired
                } else {
                    Cleanup::LeftToExpire
                };
            }
            Method::Upnp => {
                let (Some(control), Some(service), Some(description)) =
                    (&entry.control, entry.service, &entry.description)
                else {
                    return Cleanup::Failed(Error::Record("incomplete entry"));
                };
                let Ok(control) = Url::parse(control) else {
                    return Cleanup::Failed(Error::Record("bad control URL"));
                };
                if control.host != self.gateway {
                    return Cleanup::OtherNetwork;
                }
                self.igd_for(&control, service).and_then(|igd| {
                    owned_delete(
                        &igd,
                        entry.protocol,
                        entry.external_port,
                        entry.internal,
                        description,
                    )
                })
            }
        };
        outcome.unwrap_or_else(Cleanup::Failed)
    }
}

/// Delete a UPnP mapping only after the gateway shows it is ours.
fn owned_delete(
    igd: &Igd,
    protocol: Protocol,
    external_port: u16,
    internal: SocketAddrV4,
    description: &str,
) -> Result<Cleanup, Error> {
    let gone = |error: &Error| {
        matches!(
            error,
            Error::Refused {
                code: upnp::NO_SUCH_ENTRY,
                ..
            }
        )
    };
    match igd.entry(protocol, external_port) {
        Ok(entry) if entry.internal == internal && entry.description == description => {
            match igd.delete(protocol, external_port) {
                Ok(()) => Ok(Cleanup::Removed),
                Err(error) if gone(&error) => Ok(Cleanup::Gone),
                Err(error) => Err(error),
            }
        }
        Ok(_) => Err(Error::NotOurs),
        Err(error) if gone(&error) => Ok(Cleanup::Gone),
        Err(error) => Err(error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn epoch_check_follows_rfc_6887() {
        assert!(epoch_consistent(1000, 1000, 0));
        assert!(epoch_consistent(1000, 1999, 1000));
        assert!(epoch_consistent(1000, 999, 0));
        // Went backwards: the gateway restarted.
        assert!(!epoch_consistent(1000, 10, 5));
        // Server clock far behind or far ahead of ours.
        assert!(!epoch_consistent(1000, 1100, 3600));
        assert!(!epoch_consistent(1000, 9000, 60));
    }

    #[test]
    fn renewal_is_at_half_the_lease() {
        let start = Instant::now();
        let mapping = Mapping {
            method: Method::Pcp,
            protocol: Protocol::Udp,
            gateway: Ipv4Addr::LOCALHOST,
            internal: SocketAddrV4::new(Ipv4Addr::LOCALHOST, 3478),
            external: SocketAddrV4::new(Ipv4Addr::new(198, 51, 100, 7), 3478),
            lifetime: Some(Duration::from_secs(7200)),
            requested: Duration::from_secs(7200),
            granted_at: start,
            owner: Owner::Pcp { nonce: [7; 12] },
        };
        assert_eq!(mapping.renew_at(), Some(start + Duration::from_secs(3600)));
        assert_eq!(
            mapping.expires_at(),
            Some(start + Duration::from_secs(7200))
        );
        assert!(!mapping.translated());
        let entry = mapping.entry(1_000);
        assert_eq!(entry.expires, Some(8_200));
        assert_eq!(entry.nonce, Some([7; 12]));
        let permanent = Mapping {
            lifetime: None,
            ..mapping
        };
        assert_eq!(permanent.renew_at(), None);
        assert_eq!(permanent.entry(1_000).expires, None);
    }

    #[test]
    fn descriptions_are_restricted() {
        assert!(valid_description("spry relay"));
        assert!(!valid_description(""));
        assert!(!valid_description("tab\there"));
        assert!(!valid_description("<x>"));
        assert!(!valid_description(&"a".repeat(65)));
    }
}
