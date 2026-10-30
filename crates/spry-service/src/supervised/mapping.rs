//! Automatic router port opening for supervised mode (`--map-ports`).
//!
//! A [`Task`] owns one [`PortMapper`] on its own thread, because the mapper is
//! blocking. It removes whatever a crashed run recorded, asks the router for
//! the listener (UDP, then TCP) and then for the allocation ports, reports
//! the granted values, renews at half the lease, checks every minute that
//! the router still holds each mapping (some routers drop UPnP mappings long
//! before their lease ends), puts back any it lost, and reports every change
//! the relay must follow. When it is stopped it removes only the mappings it
//! made. Everything it tells the rest of the node is a count, a state or a
//! fixed reason token: no gateway address and no router detail.
use crate::now as unix_now;
use serde_json::{Value, json};
use spry_portmap::{
    AddressKind, Clock, Error, Mapping, Method, Options, PortMapper, Protocol, Request, classify,
    record::{Entry, Ledger, same_mapping},
    route::Route,
};
use std::{
    io,
    net::{Ipv4Addr, UdpSocket},
    ops::RangeInclusive,
    path::PathBuf,
    sync::{
        Arc, Condvar, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::{Duration, Instant},
};
use tokio::sync::mpsc::UnboundedSender;

/// Lease asked of PCP and NAT-PMP routers (design 2.2).
const LEASE: Duration = Duration::from_secs(7200);
/// Lease asked of UPnP routers (design 2.2). Shorter, so a crash leaves
/// less behind on the routers that honour it.
const LEASE_UPNP: Duration = Duration::from_secs(3600);
/// Mapping requests in one acquisition, listener included (design 2.2).
const MAX_REQUESTS: usize = 40;
/// Fewest allocation ports worth starting with (design 2.2), when the
/// allocation cap allows that many.
pub(crate) const MINIMUM_PORTS: usize = 4;
/// Allocation-port refusals in a row that end the search.
const MAX_REFUSALS: usize = 3;
/// How often the thread looks at its clock.
const TICK: Duration = Duration::from_millis(500);
/// A failed renewal is tried again after this long.
const RETRY: Duration = Duration::from_secs(30);
/// A permanent UPnP lease has no renewal time, so it is re-added this often.
/// That restores it after a router restart.
const PERMANENT_REFRESH: Duration = Duration::from_secs(1800);
/// Failed refreshes of a permanent lease before it counts as lost.
const PERMANENT_FAILURES: u32 = 5;
/// How often each mapping is checked between renewals. A router seen on 30
/// October 2026 dropped half its UPnP mappings within 12 minutes of a
/// 3600 s lease; this bounds such an outage to about a minute. UPnP is asked
/// (`GetSpecificPortMappingEntry`); PCP and NAT-PMP have no query, so they
/// are renewed this often instead, which puts a lost mapping back.
const CHECK: Duration = Duration::from_secs(60);
/// Removal on stop is bounded, so the node exits soon after its supervisor
/// closes the pipe. Anything unfinished stays recorded for the next launch.
pub(crate) const RELEASE_BUDGET: Duration = Duration::from_secs(2);

/// Why the router could not host. The tokens are the only text that reaches
/// the supervisor, and none carries an address.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Reason {
    NoGateway,
    Vpn,
    WrongInterface,
    NoAnswer,
    Refused,
    Failed,
    CarrierGradeNat,
    DoubleNat,
    UnusableAddress,
    TooFewPorts,
    Record,
    Expired,
    Cancelled,
}
impl Reason {
    pub(crate) const fn token(self) -> &'static str {
        match self {
            Self::NoGateway => "no-gateway",
            Self::Vpn => "vpn",
            Self::WrongInterface => "wrong-interface",
            Self::NoAnswer => "no-answer",
            Self::Refused => "refused",
            Self::Failed => "failed",
            Self::CarrierGradeNat => "carrier-grade-nat",
            Self::DoubleNat => "double-nat",
            Self::UnusableAddress => "unusable-address",
            Self::TooFewPorts => "too-few-ports",
            Self::Record => "record",
            Self::Expired => "expired",
            Self::Cancelled => "cancelled",
        }
    }
}

fn reason_of(error: &Error) -> Reason {
    match error {
        Error::NoMethod(attempts) => {
            if attempts
                .iter()
                .any(|(_, error)| matches!(reason_of(error), Reason::Refused))
            {
                Reason::Refused
            } else {
                Reason::NoAnswer
            }
        }
        Error::NoGateway => Reason::NoGateway,
        Error::Refused { .. } | Error::PermanentOnly | Error::NotOurs => Reason::Refused,
        Error::NoAnswer | Error::NoIgd => Reason::NoAnswer,
        _ => Reason::Failed,
    }
}

/// What the router granted, as the values the relay and the TURN URLs use.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Values {
    pub(crate) public_ip: Ipv4Addr,
    pub(crate) udp_port: u16,
    pub(crate) tcp_port: u16,
    /// Local and external allocation port pairs.
    pub(crate) map: Vec<(u16, u16)>,
}

/// The counts and states a supervisor may show.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Info {
    pub(crate) method: Method,
    pub(crate) allocation_ports: usize,
    pub(crate) requested: usize,
    /// Some mapping has no lease end, so it can outlive a crash until the
    /// next launch removes it.
    pub(crate) permanent: bool,
}

/// Everything the task reports, in order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Update {
    /// A previous run's mappings were dealt with.
    Cleaned { removed: usize, remaining: usize },
    /// The first grant: the relay may start.
    Mapped { values: Values, info: Info },
    /// A value the relay hands out changed: restart it with the new ones.
    Changed {
        values: Values,
        info: Info,
        reason: &'static str,
    },
    /// Acquisition failed; nothing is mapped.
    Failed(Reason),
    /// A listener mapping was lost while running; the relay cannot be
    /// reached any more.
    Lost(Reason),
    /// The router had dropped this many mappings before their lease ended;
    /// they were put back with the same values.
    Restored { count: usize },
    /// The task has removed what it could.
    Released { removed: usize, remaining: usize },
}
impl Update {
    /// The stdout line for this update, or `None` when there is nothing to
    /// say. Counts, states and reason tokens only.
    pub(crate) fn event(&self) -> Option<Value> {
        let state = |state: &str, rest: Value| {
            let mut line = json!({"v":1,"event":"portmap","state":state});
            if let (Some(line), Some(rest)) = (line.as_object_mut(), rest.as_object()) {
                line.extend(rest.clone());
            }
            line
        };
        let info = |info: &Info| {
            json!({
                "method":info.method.token(),
                "allocationPorts":info.allocation_ports,
                "requested":info.requested,
                "permanent":info.permanent,
            })
        };
        Some(match self {
            Self::Cleaned { removed, remaining } => {
                state("cleaned", json!({"removed":removed,"remaining":remaining}))
            }
            Self::Mapped { info: i, .. } => state("mapped", info(i)),
            Self::Changed {
                info: i, reason, ..
            } => {
                let mut rest = info(i);
                rest["reason"] = json!(reason);
                state("changed", rest)
            }
            Self::Failed(Reason::Cancelled) => return None,
            Self::Failed(reason) => state("failed", json!({"reason":reason.token()})),
            Self::Lost(reason) => state("lost", json!({"reason":reason.token()})),
            Self::Restored { count } => state("restored", json!({"restored":count})),
            Self::Released { removed, remaining } => {
                state("released", json!({"removed":removed,"remaining":remaining}))
            }
        })
    }
}

/// What to map and where to keep the record.
pub(crate) struct Plan {
    pub(crate) options: Options,
    pub(crate) bind: Ipv4Addr,
    pub(crate) listen_port: u16,
    /// Allocation ports to ask for: the allocation cap.
    pub(crate) wanted: usize,
    /// Fewest allocation ports worth starting with.
    pub(crate) minimum: usize,
    pub(crate) record: PathBuf,
    /// Local ports tried for allocations, at random.
    pub(crate) ports: RangeInclusive<u16>,
    /// Generated fixtures: skip the route-table, tunnel and address checks.
    pub(crate) local_test: bool,
}

/// The dynamic port range, where a home router is least likely to have a
/// mapping already.
pub(crate) const DYNAMIC_PORTS: RangeInclusive<u16> = 49152..=65535;

/// A flag the thread can wait on.
pub(crate) struct Stop {
    flag: AtomicBool,
    lock: Mutex<()>,
    signal: Condvar,
}
impl Stop {
    pub(crate) fn new() -> Arc<Self> {
        Arc::new(Self {
            flag: AtomicBool::new(false),
            lock: Mutex::new(()),
            signal: Condvar::new(),
        })
    }
    pub(crate) fn set(&self) {
        let guard = self
            .lock
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        self.flag.store(true, Ordering::Release);
        self.signal.notify_all();
        drop(guard);
    }
    pub(crate) fn is_set(&self) -> bool {
        self.flag.load(Ordering::Acquire)
    }
    /// Wait up to `duration`; true once stopped.
    pub(crate) fn wait(&self, duration: Duration) -> bool {
        let guard = self
            .lock
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let _ = self
            .signal
            .wait_timeout_while(guard, duration, |_| !self.is_set());
        self.is_set()
    }
}

struct Slot {
    mapping: Mapping,
    retry_at: Option<Instant>,
    failures: u32,
    /// When the router last showed it holds this mapping (a grant, a
    /// renewal or a check).
    checked_at: Instant,
}

/// The result of looking at the clock.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Tick {
    Idle,
    Changed(&'static str),
    Lost(Reason),
}

enum Checked {
    Held,
    Restored(Option<&'static str>),
    Lost,
}

enum Renewed {
    Kept {
        changed: Option<&'static str>,
        restarted: bool,
    },
    Retry,
    Lost,
}

/// Mappings held on the router: slot 0 is the UDP listener, slot 1 the TCP
/// listener, the rest are allocation ports.
pub(crate) struct Session {
    mapper: PortMapper,
    ledger: Ledger,
    slots: Vec<Slot>,
    clock: Clock,
    bind: Ipv4Addr,
    listen_port: u16,
    wanted: usize,
    minimum: usize,
    ports: RangeInclusive<u16>,
    local_test: bool,
    requests: usize,
    /// Mappings put back since the last [`Session::take_restored`].
    restored: usize,
}

/// Whether a failed removal leaves the record worth keeping.
fn keep_record(entry: &Entry, error: &Error) -> bool {
    if entry.expires.is_none() {
        // A permanent lease outlives everything else, so try again later
        // unless the router shows it is not ours.
        return !matches!(error, Error::NotOurs);
    }
    matches!(error, Error::NoAnswer | Error::Io(_))
}

impl Session {
    /// Remove a crashed run's mappings, then map the listener and the
    /// allocation ports. `report` is told about the clean-up as it happens.
    pub(crate) fn start(plan: &Plan, stop: &Stop, report: &dyn Fn(Update)) -> Result<Self, Reason> {
        let mut mapper =
            PortMapper::new(plan.options.clone()).map_err(|error| reason_of(&error))?;
        let mut ledger = match Ledger::load(&plan.record) {
            Ok(ledger) => ledger,
            Err(_) => {
                // A record that cannot be read would otherwise block hosting
                // for good. Set it aside and start a new one.
                let mut aside = plan.record.clone().into_os_string();
                aside.push(".rejected");
                let _ = std::fs::rename(&plan.record, aside);
                Ledger::load(&plan.record).map_err(|_| Reason::Record)?
            }
        };
        if !ledger.entries().is_empty() {
            let (removed, remaining) = clean(&mut mapper, &mut ledger);
            report(Update::Cleaned { removed, remaining });
        }
        if !plan.local_test
            && plan.options.gateway.is_none()
            && (Route {
                gateway: mapper.gateway(),
                interface: mapper.interface().map(str::to_owned),
            })
            .looks_like_tunnel()
        {
            return Err(Reason::Vpn);
        }
        if mapper.local() != plan.bind {
            return Err(Reason::WrongInterface);
        }
        let mut session = Self {
            mapper,
            ledger,
            slots: Vec::new(),
            clock: plan.options.clock.clone(),
            bind: plan.bind,
            listen_port: plan.listen_port,
            wanted: plan.wanted,
            minimum: plan.minimum,
            ports: plan.ports.clone(),
            local_test: plan.local_test,
            requests: 0,
            restored: 0,
        };
        if let Err(reason) = session.acquire(stop) {
            session.release(RELEASE_BUDGET);
            return Err(reason);
        }
        Ok(session)
    }

    fn now(&self) -> Instant {
        (self.clock)()
    }

    fn lease(&self) -> Duration {
        if self.mapper.method() == Some(Method::Upnp) {
            LEASE_UPNP
        } else {
            LEASE
        }
    }

    fn request(
        &mut self,
        protocol: Protocol,
        internal: u16,
        suggested: u16,
    ) -> Result<Mapping, Error> {
        self.requests += 1;
        let lifetime = self.lease();
        self.mapper.map(Request {
            protocol,
            internal_port: internal,
            external_port: suggested,
            lifetime,
        })
    }

    /// Keep the record in step with a grant or a renewal: one entry per
    /// protocol and local port, written before anything else relies on it.
    fn record(&mut self, mapping: &Mapping) -> Result<(), Error> {
        let entry = mapping.entry(unix_now());
        self.ledger.retain(|known| {
            !(known.protocol == entry.protocol
                && known.gateway == entry.gateway
                && known.internal == entry.internal)
        })?;
        self.ledger.record(entry)
    }

    fn adopt(&mut self, mapping: Mapping) -> Result<(), Reason> {
        let recorded = self.record(&mapping);
        let checked_at = self.now();
        self.slots.push(Slot {
            mapping,
            retry_at: None,
            failures: 0,
            checked_at,
        });
        recorded.map_err(|_| Reason::Record)
    }

    fn address_ok(&self, address: Ipv4Addr) -> Result<(), Reason> {
        if self.local_test {
            return Ok(());
        }
        match classify(address) {
            AddressKind::Public => Ok(()),
            AddressKind::CarrierGradeNat => Err(Reason::CarrierGradeNat),
            AddressKind::Private => Err(Reason::DoubleNat),
            AddressKind::Unusable => Err(Reason::UnusableAddress),
        }
    }

    fn acquire(&mut self, stop: &Stop) -> Result<(), Reason> {
        // The listener first. Nothing else is useful without it.
        for protocol in [Protocol::Udp, Protocol::Tcp] {
            if stop.is_set() {
                return Err(Reason::Cancelled);
            }
            let port = self.listen_port;
            let mapping = self
                .request(protocol, port, port)
                .map_err(|error| reason_of(&error))?;
            let address = *mapping.external.ip();
            // Held and recorded first, so a refusal below still gives it back.
            self.adopt(mapping)?;
            self.address_ok(address)?;
            if protocol == Protocol::Tcp && address != *self.slots[0].mapping.external.ip() {
                return Err(Reason::UnusableAddress);
            }
            if protocol == Protocol::Udp {
                self.shorten_upnp_lease();
            }
        }
        let mut refusals = 0;
        let mut tried = Vec::new();
        while self.slots.len() - 2 < self.wanted
            && self.requests < MAX_REQUESTS
            && refusals < MAX_REFUSALS
        {
            if stop.is_set() {
                return Err(Reason::Cancelled);
            }
            let Some(port) = self.free_port(&mut tried) else {
                break;
            };
            match self.request(Protocol::Udp, port, port) {
                Ok(mapping) => {
                    let clash = self.slots.iter().any(|slot| {
                        slot.mapping.external.port() == mapping.external.port()
                            && slot.mapping.protocol == mapping.protocol
                    });
                    if clash {
                        let _ = self.mapper.remove(&mapping);
                        refusals += 1;
                    } else {
                        self.adopt(mapping)?;
                        refusals = 0;
                    }
                }
                // A silent router will not answer the next request either.
                Err(Error::NoAnswer) => break,
                Err(_) => refusals += 1,
            }
        }
        if self.slots.len() - 2 < self.minimum {
            return Err(Reason::TooFewPorts);
        }
        Ok(())
    }

    /// The first request is made before the router's protocol is known, so
    /// it asked for the longer lease. A UPnP router gets the shorter one.
    fn shorten_upnp_lease(&mut self) {
        let Some(slot) = self.slots.first() else {
            return;
        };
        if self.mapper.method() != Some(Method::Upnp)
            || slot.mapping.is_permanent()
            || slot.mapping.requested == LEASE_UPNP
        {
            return;
        }
        let mut mapping = slot.mapping.clone();
        mapping.requested = LEASE_UPNP;
        mapping.lifetime = Some(LEASE_UPNP);
        if let Ok(renewal) = self.mapper.renew(&mapping) {
            let _ = self.record(&renewal.mapping);
            self.slots[0].mapping = renewal.mapping;
        }
    }

    /// A random high local port that nothing here is using and the host can
    /// bind, so the relay will not skip it.
    fn free_port(&self, tried: &mut Vec<u16>) -> Option<u16> {
        for _ in 0..256 {
            let mut bytes = [0u8; 2];
            getrandom::fill(&mut bytes).ok()?;
            let span = u32::from(*self.ports.end() - *self.ports.start()) + 1;
            let port = *self.ports.start() + (u32::from(u16::from_be_bytes(bytes)) % span) as u16;
            if port == self.listen_port
                || tried.contains(&port)
                || self
                    .slots
                    .iter()
                    .any(|slot| slot.mapping.external.port() == port)
            {
                continue;
            }
            tried.push(port);
            if UdpSocket::bind((self.bind, port)).is_ok() {
                return Some(port);
            }
        }
        None
    }

    pub(crate) fn values(&self) -> Values {
        let udp = &self.slots[0].mapping;
        let tcp = &self.slots[1].mapping;
        Values {
            public_ip: *udp.external.ip(),
            udp_port: udp.external.port(),
            tcp_port: tcp.external.port(),
            map: self.slots[2..]
                .iter()
                .map(|slot| (slot.mapping.internal.port(), slot.mapping.external.port()))
                .collect(),
        }
    }

    pub(crate) fn info(&self) -> Info {
        Info {
            method: self.mapper.method().unwrap_or(Method::Pcp),
            allocation_ports: self.slots.len().saturating_sub(2),
            requested: self.wanted,
            permanent: self.slots.iter().any(|slot| slot.mapping.is_permanent()),
        }
    }

    fn due_at(&self, slot: &Slot) -> Instant {
        slot.retry_at.unwrap_or_else(|| {
            let renew = slot
                .mapping
                .renew_at()
                .unwrap_or(slot.mapping.granted_at + PERMANENT_REFRESH);
            // PCP and NAT-PMP cannot be asked, so they are renewed as often
            // as UPnP is checked.
            if self.mapper.method() == Some(Method::Upnp) {
                renew
            } else {
                renew.min(slot.checked_at + CHECK)
            }
        })
    }

    /// `silent` is set once the router has not answered in this round, so
    /// the rest of the round sends nothing: a router that is not there would
    /// make each mapping wait out its own timeout.
    fn renew_slot(&mut self, index: usize, now: Instant, silent: &mut bool) -> Renewed {
        let old = self.slots[index].mapping.clone();
        let renewed = if *silent {
            Err(Error::NoAnswer)
        } else {
            self.mapper.renew(&old)
        };
        let outcome = match renewed {
            Ok(renewal) => Ok((renewal.mapping, renewal.gateway_restarted)),
            Err(error) => {
                *silent |= error == Error::NoAnswer;
                self.slots[index].failures += 1;
                let gone = old.expires_at().is_some_and(|end| end <= now)
                    || (old.is_permanent() && self.slots[index].failures >= PERMANENT_FAILURES);
                if !gone {
                    let retry = now + RETRY;
                    self.slots[index].retry_at =
                        Some(old.expires_at().map_or(retry, |end| retry.min(end)));
                    return Renewed::Retry;
                }
                // The lease has ended: ask again from scratch.
                if *silent {
                    Err(Error::NoAnswer)
                } else {
                    self.request(old.protocol, old.internal.port(), old.external.port())
                        .map(|mapping| (mapping, false))
                }
            }
        };
        let Ok((mapping, restarted)) = outcome else {
            return Renewed::Lost;
        };
        let changed = if mapping.external.ip() != old.external.ip() {
            Some("address")
        } else if mapping.external.port() != old.external.port() {
            Some("port")
        } else {
            None
        };
        let _ = self.record(&mapping);
        self.slots[index] = Slot {
            mapping,
            retry_at: None,
            failures: 0,
            checked_at: now,
        };
        Renewed::Kept { changed, restarted }
    }

    /// Renew what is due. After a router restart every mapping is renewed at
    /// once, so the ones the router lost are put back together.
    pub(crate) fn tick(&mut self) -> Tick {
        let now = self.now();
        let mut changed: Option<&'static str> = None;
        let mut restart = false;
        let mut handled = vec![false; self.slots.len()];
        let mut lost = Vec::new();
        let mut silent = false;
        for pass in 0..2 {
            for (index, done) in handled.iter_mut().enumerate() {
                if *done || (pass == 0 && self.due_at(&self.slots[index]) > now) {
                    continue;
                }
                *done = true;
                match self.renew_slot(index, now, &mut silent) {
                    Renewed::Kept {
                        changed: reason,
                        restarted,
                    } => {
                        changed = changed.or(reason);
                        restart |= restarted;
                    }
                    Renewed::Retry => {}
                    Renewed::Lost if index < 2 => return Tick::Lost(Reason::Expired),
                    Renewed::Lost => {
                        lost.push(index);
                        changed = changed.or(Some("ports"));
                    }
                }
            }
            restart |= self.mapper.take_gateway_restart();
            if !restart || pass == 1 {
                break;
            }
        }
        for (index, done) in handled.iter().enumerate() {
            if *done || silent {
                continue;
            }
            match self.check_slot(index, now, &mut silent) {
                Checked::Held => {}
                Checked::Restored(reason) => {
                    self.restored += 1;
                    changed = changed.or(reason);
                }
                Checked::Lost if index < 2 => return Tick::Lost(Reason::Expired),
                Checked::Lost => {
                    lost.push(index);
                    changed = changed.or(Some("ports"));
                }
            }
        }
        if !lost.is_empty() {
            let dropped: Vec<Entry> = lost
                .iter()
                .map(|index| self.slots[*index].mapping.entry(unix_now()))
                .collect();
            for index in lost.into_iter().rev() {
                self.slots.remove(index);
            }
            let _ = self
                .ledger
                .retain(|known| !dropped.iter().any(|gone| same_mapping(gone, known)));
            if self.slots.len() < 3 {
                return Tick::Lost(Reason::TooFewPorts);
            }
        }
        let Some(reason) = changed else {
            return Tick::Idle;
        };
        if let Err(reason) = self.address_ok(*self.slots[0].mapping.external.ip()) {
            return Tick::Lost(reason);
        }
        Tick::Changed(reason)
    }

    /// Ask a UPnP router whether it still holds a mapping that is not due
    /// for renewal, at most once per [`CHECK`], and add it again if not.
    fn check_slot(&mut self, index: usize, now: Instant, silent: &mut bool) -> Checked {
        let slot = &self.slots[index];
        if self.mapper.method() != Some(Method::Upnp) || slot.checked_at + CHECK > now {
            return Checked::Held;
        }
        let old = slot.mapping.clone();
        let present = self.mapper.present(&old);
        if let Err(Error::NoAnswer) = present {
            // Asked again next minute; the lease is still running.
            *silent = true;
            self.slots[index].checked_at = now;
            return Checked::Held;
        }
        if let Ok(true) = present {
            self.slots[index].checked_at = now;
            return Checked::Held;
        }
        // Gone, held by someone else, or a router that cannot answer the
        // query: add it again with the same values, as a renewal would.
        let unknown = present.is_err();
        match self.mapper.renew(&old) {
            Ok(renewal) => {
                let mapping = renewal.mapping;
                let reason = if mapping.external.ip() != old.external.ip() {
                    Some("address")
                } else if mapping.external.port() != old.external.port() {
                    Some("port")
                } else {
                    None
                };
                let _ = self.record(&mapping);
                self.slots[index] = Slot {
                    mapping,
                    retry_at: None,
                    failures: 0,
                    checked_at: now,
                };
                if unknown {
                    Checked::Held
                } else {
                    Checked::Restored(reason)
                }
            }
            Err(error) => {
                *silent |= error == Error::NoAnswer;
                self.slots[index].checked_at = now;
                // A router that cannot answer the query keeps its lease
                // until renewal says otherwise; a mapping it showed gone and
                // will not take back is lost.
                if unknown || error == Error::NoAnswer {
                    Checked::Held
                } else {
                    Checked::Lost
                }
            }
        }
    }

    /// Mappings put back since the last call.
    pub(crate) fn take_restored(&mut self) -> usize {
        std::mem::take(&mut self.restored)
    }

    /// Remove the mappings this run made, newest first, within `budget`.
    /// A router that stops answering ends the attempt. What is left stays in
    /// the record. Returns what was removed and how many are still recorded.
    pub(crate) fn release(&mut self, budget: Duration) -> (usize, usize) {
        let deadline = Instant::now() + budget;
        let mut removed = 0;
        let mut finished: Vec<Entry> = Vec::new();
        while let Some(slot) = self.slots.pop() {
            let entry = slot.mapping.entry(unix_now());
            if Instant::now() >= deadline {
                self.slots.push(slot);
                break;
            }
            match self.mapper.remove(&slot.mapping) {
                Ok(()) => {
                    removed += 1;
                    finished.push(entry);
                }
                Err(Error::NoAnswer) => {
                    self.slots.push(slot);
                    break;
                }
                Err(error) => {
                    if !keep_record(&entry, &error) {
                        finished.push(entry);
                    }
                }
            }
        }
        let _ = self
            .ledger
            .retain(|known| !finished.iter().any(|gone| same_mapping(gone, known)));
        (removed, self.ledger.entries().len())
    }
}

/// Remove what a previous run recorded. Returns how many mappings were
/// removed and how many records remain.
fn clean(mapper: &mut PortMapper, ledger: &mut Ledger) -> (usize, usize) {
    let mut removed = 0;
    let mut finished: Vec<Entry> = Vec::new();
    for entry in ledger.entries().to_vec() {
        let outcome = mapper
            .cleanup(std::slice::from_ref(&entry), unix_now())
            .pop()
            .unwrap_or(spry_portmap::Cleanup::Gone);
        match outcome {
            spry_portmap::Cleanup::Removed | spry_portmap::Cleanup::Gone => {
                removed += 1;
                finished.push(entry);
            }
            spry_portmap::Cleanup::Expired | spry_portmap::Cleanup::LeftToExpire => {
                finished.push(entry);
            }
            // Another network's mapping can only be removed when that
            // network is back, which matters only if it never expires.
            spry_portmap::Cleanup::OtherNetwork => {
                if entry.expires.is_some() {
                    finished.push(entry);
                }
            }
            spry_portmap::Cleanup::Failed(error) => {
                let silent = matches!(error, Error::NoAnswer);
                if !keep_record(&entry, &error) {
                    finished.push(entry);
                }
                // A silent router will not answer the rest either.
                if silent {
                    break;
                }
            }
        }
    }
    let _ = ledger.retain(|known| !finished.iter().any(|gone| same_mapping(gone, known)));
    (removed, ledger.entries().len())
}

/// The mapping thread and its stop flag. Dropping it stops the thread and
/// waits for it to remove what it can.
pub(crate) struct Task {
    stop: Arc<Stop>,
    thread: Option<thread::JoinHandle<()>>,
}
impl Task {
    pub(crate) fn spawn(plan: Plan, updates: UnboundedSender<Update>) -> io::Result<Self> {
        let stop = Stop::new();
        let flag = stop.clone();
        let thread = thread::Builder::new()
            .name("spry-portmap".into())
            .spawn(move || work(&plan, &flag, &updates))?;
        Ok(Self {
            stop,
            thread: Some(thread),
        })
    }
    /// Ask the thread to remove its mappings and wait for it.
    pub(crate) fn stop(&mut self) {
        self.stop.set();
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}
impl Drop for Task {
    fn drop(&mut self) {
        self.stop();
    }
}

fn work(plan: &Plan, stop: &Stop, updates: &UnboundedSender<Update>) {
    let send = |update: Update| {
        let _ = updates.send(update);
    };
    let mut session = match Session::start(plan, stop, &send) {
        Ok(session) => session,
        Err(reason) => {
            send(Update::Failed(reason));
            return;
        }
    };
    send(Update::Mapped {
        values: session.values(),
        info: session.info(),
    });
    while !stop.wait(TICK) {
        let tick = session.tick();
        let restored = session.take_restored();
        if restored > 0 {
            send(Update::Restored { count: restored });
        }
        match tick {
            Tick::Idle => {}
            Tick::Changed(reason) => send(Update::Changed {
                values: session.values(),
                info: session.info(),
                reason,
            }),
            Tick::Lost(reason) => {
                send(Update::Lost(reason));
                break;
            }
        }
    }
    let (removed, remaining) = session.release(RELEASE_BUDGET);
    send(Update::Released { removed, remaining });
}

#[cfg(test)]
mod tests;
