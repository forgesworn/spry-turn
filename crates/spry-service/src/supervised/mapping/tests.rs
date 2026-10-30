//! The mapping session against the in-house fake gateways, with a fixture
//! clock so renewal takes no real time. Local evidence only: no real router.
use super::*;
use spry_portmap::fake::{
    FakeNatGateway, FakeUpnpGateway, NatBehaviour, NatPmpMode, PcpMode, UpnpBehaviour, UpnpMapping,
};
use std::sync::Mutex;

const LISTEN: u16 = 41000;

/// A clock that moves only when a test says so.
struct Fixture {
    base: Instant,
    offset: Mutex<Duration>,
}
impl Fixture {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            base: Instant::now(),
            offset: Mutex::new(Duration::ZERO),
        })
    }
    fn clock(self: &Arc<Self>) -> Clock {
        let fixture = self.clone();
        Arc::new(move || fixture.base + *fixture.offset.lock().unwrap())
    }
    fn advance(&self, seconds: u64) {
        *self.offset.lock().unwrap() += Duration::from_secs(seconds);
    }
}

struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Self {
        let mut random = [0_u8; 8];
        getrandom::fill(&mut random).unwrap();
        let directory = std::env::temp_dir().join(format!(
            "spry-mapping-{}",
            random
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        ));
        std::fs::create_dir(&directory).unwrap();
        Self(directory)
    }
    fn record(&self) -> PathBuf {
        self.0.join("state.json.mappings")
    }
    fn entries(&self) -> Vec<Entry> {
        Ledger::load(self.record()).unwrap().entries().to_vec()
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn plan(
    nat: &FakeNatGateway,
    upnp: Option<&FakeUpnpGateway>,
    methods: &[Method],
    scratch: &Scratch,
    fixture: &Arc<Fixture>,
) -> Plan {
    let silent = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let ssdp = upnp.map_or_else(
        || match silent.local_addr().unwrap() {
            std::net::SocketAddr::V4(address) => address,
            _ => unreachable!(),
        },
        FakeUpnpGateway::ssdp,
    );
    // The silent socket may close; nothing sends to it when UPnP is not tried.
    drop(silent);
    Plan {
        options: Options {
            gateway: Some(Ipv4Addr::LOCALHOST),
            gateway_port: nat.address().port(),
            ssdp,
            timeout: Duration::from_millis(300),
            methods: methods.to_vec(),
            clock: fixture.clock(),
            ..Options::default()
        },
        bind: Ipv4Addr::LOCALHOST,
        listen_port: LISTEN,
        wanted: 6,
        minimum: 4,
        record: scratch.record(),
        ports: 50000..=50999,
        local_test: true,
    }
}

fn nat() -> FakeNatGateway {
    FakeNatGateway::start(NatBehaviour {
        max_lifetime: 100,
        ..NatBehaviour::default()
    })
}

fn start(plan: &Plan) -> Result<Session, Reason> {
    Session::start(plan, &Stop::new(), &|_| {})
}

#[test]
fn acquires_the_listener_then_allocation_ports_and_records_every_grant() {
    let (gateway, scratch, fixture) = (nat(), Scratch::new(), Fixture::new());
    let plan = plan(&gateway, None, &[Method::Pcp], &scratch, &fixture);
    let session = start(&plan).unwrap();
    let values = session.values();
    assert_eq!(values.public_ip, spry_portmap::fake::EXTERNAL);
    assert_eq!((values.udp_port, values.tcp_port), (LISTEN, LISTEN));
    assert_eq!(values.map.len(), 6);
    for (local, public) in &values.map {
        assert_eq!(local, public, "an untranslated router gives the same port");
        assert!((50000..=50999).contains(local));
    }
    let info = session.info();
    assert_eq!(
        (
            info.method,
            info.allocation_ports,
            info.requested,
            info.permanent
        ),
        (Method::Pcp, 6, 6, false)
    );
    // The listener first, UDP then TCP, then six UDP allocation ports.
    let held = gateway.mappings();
    assert_eq!(held.len(), 8);
    assert_eq!(held[0].protocol, Protocol::Udp);
    assert_eq!(held[0].internal_port, LISTEN);
    assert_eq!(held[1].protocol, Protocol::Tcp);
    assert!(held[2..].iter().all(|m| m.protocol == Protocol::Udp));
    // Every grant is in the record with the nonce that can delete it.
    let recorded = scratch.entries();
    assert_eq!(recorded.len(), 8);
    for entry in &recorded {
        let held = held
            .iter()
            .find(|m| m.internal_port == entry.internal.port() && m.protocol == entry.protocol)
            .unwrap();
        assert_eq!(entry.nonce, held.nonce);
        assert_eq!(entry.external_port, held.external_port);
        assert!(entry.expires.is_some());
    }
}

#[test]
fn a_translated_port_is_used_as_the_router_gave_it() {
    let gateway = FakeNatGateway::start(NatBehaviour {
        translate: true,
        ..NatBehaviour::default()
    });
    let (scratch, fixture) = (Scratch::new(), Fixture::new());
    let plan = plan(&gateway, None, &[Method::Pcp], &scratch, &fixture);
    let session = start(&plan).unwrap();
    let values = session.values();
    assert_eq!(
        (values.udp_port, values.tcp_port),
        (LISTEN + 10000, LISTEN + 10000)
    );
    for (local, public) in &values.map {
        assert_eq!(*public, local + 10000);
    }
}

#[test]
fn nothing_is_renewed_before_half_the_lease_and_everything_is_after() {
    let (gateway, scratch, fixture) = (nat(), Scratch::new(), Fixture::new());
    let plan = plan(&gateway, None, &[Method::Pcp], &scratch, &fixture);
    let mut session = start(&plan).unwrap();
    let before = gateway.requests().len();
    fixture.advance(49);
    assert_eq!(session.tick(), Tick::Idle);
    assert_eq!(gateway.requests().len(), before, "no request before half");
    fixture.advance(2);
    assert_eq!(
        session.tick(),
        Tick::Idle,
        "an unchanged grant changes nothing"
    );
    assert_eq!(
        gateway.requests().len(),
        before + 8,
        "the listener and all six allocation ports renew"
    );
    // Renewal moved the next time on, so the next tick asks for nothing.
    assert_eq!(session.tick(), Tick::Idle);
    assert_eq!(gateway.requests().len(), before + 8);
    assert!(scratch.entries().iter().all(|e| e.expires.is_some()));
}

#[test]
fn a_new_external_address_is_reported_with_the_new_values() {
    let (gateway, scratch, fixture) = (nat(), Scratch::new(), Fixture::new());
    let plan = plan(&gateway, None, &[Method::Pcp], &scratch, &fixture);
    let mut session = start(&plan).unwrap();
    let before = session.values();
    gateway.set(NatBehaviour {
        external: Ipv4Addr::new(100, 128, 0, 9),
        max_lifetime: 100,
        ..NatBehaviour::default()
    });
    fixture.advance(51);
    assert_eq!(session.tick(), Tick::Changed("address"));
    let after = session.values();
    assert_eq!(after.public_ip, Ipv4Addr::new(100, 128, 0, 9));
    assert_eq!(
        (after.udp_port, after.map.clone()),
        (before.udp_port, before.map)
    );
}

#[test]
fn a_router_restart_is_noticed_and_every_mapping_put_back() {
    let (gateway, scratch, fixture) = (nat(), Scratch::new(), Fixture::new());
    let plan = plan(&gateway, None, &[Method::NatPmp], &scratch, &fixture);
    let mut session = start(&plan).unwrap();
    assert_eq!(gateway.mappings().len(), 8);
    gateway.restart();
    assert!(gateway.mappings().is_empty());
    fixture.advance(51);
    // The epoch went back, so the router lost its state; the same ports
    // come back and nothing the relay hands out has changed.
    assert_eq!(session.tick(), Tick::Idle);
    assert_eq!(gateway.mappings().len(), 8);
}

#[test]
fn a_router_that_comes_back_on_other_ports_is_reported() {
    let (gateway, scratch, fixture) = (nat(), Scratch::new(), Fixture::new());
    let plan = plan(&gateway, None, &[Method::Pcp], &scratch, &fixture);
    let mut session = start(&plan).unwrap();
    let before = session.values();
    gateway.restart();
    gateway.set(NatBehaviour {
        translate: true,
        max_lifetime: 100,
        ..NatBehaviour::default()
    });
    fixture.advance(51);
    assert_eq!(session.tick(), Tick::Changed("port"));
    let after = session.values();
    assert_eq!(after.udp_port, before.udp_port + 10000);
    assert_eq!(after.map.len(), before.map.len());
    // The record follows: one entry per local port, at the new external port.
    let recorded = scratch.entries();
    assert_eq!(recorded.len(), 8);
    assert!(recorded.iter().all(|e| e.external_port >= 10000 + 1024));
}

#[test]
fn a_failed_renewal_is_retried_then_a_dead_lease_is_asked_for_again() {
    let (gateway, scratch, fixture) = (nat(), Scratch::new(), Fixture::new());
    let plan = plan(&gateway, None, &[Method::Pcp], &scratch, &fixture);
    let mut session = start(&plan).unwrap();
    gateway.set(NatBehaviour {
        pcp: PcpMode::Silent,
        max_lifetime: 100,
        ..NatBehaviour::default()
    });
    fixture.advance(51);
    // Still inside the lease: nothing changes and the relay keeps running.
    assert_eq!(session.tick(), Tick::Idle);
    gateway.set(NatBehaviour {
        max_lifetime: 100,
        ..NatBehaviour::default()
    });
    // Retried soon, not at the next half lease.
    fixture.advance(31);
    assert_eq!(session.tick(), Tick::Idle);
    assert_eq!(gateway.mappings().len(), 8);
    // Silent until the lease ends: the listener is lost for good.
    gateway.set(NatBehaviour {
        pcp: PcpMode::Silent,
        max_lifetime: 100,
        ..NatBehaviour::default()
    });
    fixture.advance(100);
    assert_eq!(session.tick(), Tick::Lost(Reason::Expired));
}

#[test]
fn a_lost_allocation_port_leaves_a_smaller_map_and_the_relay_going() {
    let (gateway, scratch, fixture) = (nat(), Scratch::new(), Fixture::new());
    let plan = plan(&gateway, None, &[Method::Pcp], &scratch, &fixture);
    let mut session = start(&plan).unwrap();
    // Make the router treat one allocation mapping as someone else's: it
    // refuses both the renewal and a new request for that port.
    let lost = session.slots[3].mapping.internal.port();
    session.slots[3].mapping.owner = spry_portmap::Owner::Pcp { nonce: [7; 12] };
    fixture.advance(51);
    assert_eq!(session.tick(), Tick::Idle, "retry inside the lease");
    fixture.advance(60);
    assert_eq!(session.tick(), Tick::Changed("ports"));
    let values = session.values();
    assert_eq!(values.map.len(), 5);
    assert!(values.map.iter().all(|(local, _)| *local != lost));
    assert_eq!(scratch.entries().len(), 7);
}

#[test]
fn losing_all_but_the_listener_is_a_loss() {
    let (gateway, scratch, fixture) = (nat(), Scratch::new(), Fixture::new());
    let mut plan = plan(&gateway, None, &[Method::Pcp], &scratch, &fixture);
    plan.wanted = 1;
    plan.minimum = 1;
    let mut session = start(&plan).unwrap();
    session.slots[2].mapping.owner = spry_portmap::Owner::Pcp { nonce: [7; 12] };
    fixture.advance(51);
    assert_eq!(session.tick(), Tick::Idle);
    fixture.advance(60);
    assert_eq!(session.tick(), Tick::Lost(Reason::TooFewPorts));
}

#[test]
fn release_removes_what_this_run_made_and_the_record_with_it() {
    let (gateway, scratch, fixture) = (nat(), Scratch::new(), Fixture::new());
    let plan = plan(&gateway, None, &[Method::Pcp], &scratch, &fixture);
    let mut session = start(&plan).unwrap();
    assert_eq!(session.release(RELEASE_BUDGET), (8, 0));
    assert!(gateway.mappings().is_empty());
    assert!(scratch.entries().is_empty());
}

#[test]
fn release_leaves_the_record_when_the_router_goes_quiet() {
    let (gateway, scratch, fixture) = (nat(), Scratch::new(), Fixture::new());
    let plan = plan(&gateway, None, &[Method::Pcp], &scratch, &fixture);
    let mut session = start(&plan).unwrap();
    gateway.set(NatBehaviour {
        pcp: PcpMode::Silent,
        ..NatBehaviour::default()
    });
    let began = Instant::now();
    let (removed, remaining) = session.release(RELEASE_BUDGET);
    assert_eq!((removed, remaining), (0, 8));
    assert!(
        began.elapsed() < Duration::from_secs(2),
        "one silent answer ends the attempt"
    );
    assert_eq!(scratch.entries().len(), 8);
}

#[test]
fn a_crashed_runs_mappings_go_before_the_next_run_asks_for_its_own() {
    let (gateway, scratch, fixture) = (nat(), Scratch::new(), Fixture::new());
    let plan = plan(&gateway, None, &[Method::Pcp], &scratch, &fixture);
    let crashed = start(&plan).unwrap();
    let old: Vec<_> = gateway.mappings();
    // No release: the process died. The router still holds all eight, and
    // would refuse a new nonce for the same listener port.
    drop(crashed);
    assert_eq!(gateway.mappings().len(), 8);
    let reported = Mutex::new(Vec::new());
    let next = Session::start(&plan, &Stop::new(), &|update| {
        reported.lock().unwrap().push(update);
    })
    .unwrap();
    assert_eq!(
        reported.lock().unwrap().as_slice(),
        [Update::Cleaned {
            removed: 8,
            remaining: 0
        }]
    );
    let now: Vec<_> = gateway.mappings();
    assert_eq!(now.len(), 8);
    assert!(
        now.iter().all(|m| old.iter().all(|o| o.nonce != m.nonce)),
        "only the new run's mappings remain"
    );
    drop(next);
}

#[test]
fn another_networks_finite_mapping_is_forgotten_and_a_permanent_one_is_kept() {
    let (gateway, scratch, fixture) = (nat(), Scratch::new(), Fixture::new());
    let plan = plan(&gateway, None, &[Method::Pcp], &scratch, &fixture);
    let mut ledger = Ledger::load(scratch.record()).unwrap();
    let entry = |expires: Option<u64>, method: Method| Entry {
        method,
        protocol: Protocol::Udp,
        gateway: Ipv4Addr::new(192, 168, 7, 1),
        internal: "192.168.7.20:50000".parse().unwrap(),
        external_port: 50000,
        expires,
        nonce: (method == Method::Pcp).then_some([1; 12]),
        control: (method == Method::Upnp).then(|| "http://192.168.7.1:5000/ctl".to_owned()),
        service: (method == Method::Upnp).then_some(spry_portmap::upnp::Service::WanIp1),
        description: (method == Method::Upnp).then(|| "spry relay".to_owned()),
    };
    ledger
        .record(entry(Some(unix_now() + 3600), Method::Pcp))
        .unwrap();
    let mut permanent = entry(None, Method::Upnp);
    permanent.external_port = 50001;
    ledger.record(permanent).unwrap();
    drop(ledger);
    let reported = Mutex::new(Vec::new());
    let session = Session::start(&plan, &Stop::new(), &|update| {
        reported.lock().unwrap().push(update);
    })
    .unwrap();
    assert_eq!(
        reported.lock().unwrap().as_slice(),
        [Update::Cleaned {
            removed: 0,
            remaining: 1
        }]
    );
    // The permanent one stays for the day that network is back.
    assert!(scratch.entries().iter().any(|e| e.expires.is_none()));
    drop(session);
}

#[test]
fn a_permanent_only_upnp_router_is_used_recorded_and_cleaned() {
    let (nat, scratch, fixture) = (nat(), Scratch::new(), Fixture::new());
    let upnp = FakeUpnpGateway::start(UpnpBehaviour {
        permanent_only: true,
        ..UpnpBehaviour::default()
    });
    let plan = plan(&nat, Some(&upnp), &[Method::Upnp], &scratch, &fixture);
    let mut session = start(&plan).unwrap();
    let info = session.info();
    assert_eq!((info.method, info.permanent), (Method::Upnp, true));
    let held = upnp.mappings();
    assert_eq!(held.len(), 8);
    assert!(held.iter().all(|m| m.lease == 0), "permanent leases");
    let recorded = scratch.entries();
    assert_eq!(recorded.len(), 8);
    assert!(
        recorded.iter().all(|e| e.expires.is_none()),
        "recorded as permanent, so the next launch removes them"
    );
    // A crash leaves them on the router; the next run removes them.
    drop(session);
    assert_eq!(upnp.mappings().len(), 8);
    let reported = Mutex::new(Vec::new());
    let mut next = Session::start(&plan, &Stop::new(), &|update| {
        reported.lock().unwrap().push(update);
    })
    .unwrap();
    assert_eq!(
        reported.lock().unwrap().as_slice(),
        [Update::Cleaned {
            removed: 8,
            remaining: 0
        }]
    );
    assert_eq!(next.release(RELEASE_BUDGET), (8, 0));
    assert!(upnp.mappings().is_empty());
    assert!(scratch.entries().is_empty());
    session = start(&plan).unwrap();
    assert!(session.info().permanent);
}

#[test]
fn a_finite_upnp_lease_is_the_shorter_one_and_is_renewed() {
    let (nat, scratch, fixture) = (nat(), Scratch::new(), Fixture::new());
    let upnp = FakeUpnpGateway::start(UpnpBehaviour::default());
    let plan = plan(&nat, Some(&upnp), &[Method::Upnp], &scratch, &fixture);
    let mut session = start(&plan).unwrap();
    assert!(!session.info().permanent);
    let held = upnp.mappings();
    assert_eq!(held.len(), 8);
    assert!(
        held.iter().all(|m| m.lease == 3600),
        "the first request asked for the long lease, then the short one: {held:?}"
    );
    let adds = upnp
        .actions()
        .iter()
        .filter(|a| a.contains("AddPortMapping"))
        .count();
    fixture.advance(1801);
    assert_eq!(session.tick(), Tick::Idle);
    let after = upnp
        .actions()
        .iter()
        .filter(|a| a.contains("AddPortMapping"))
        .count();
    assert_eq!(
        after,
        adds + 8,
        "every mapping is added again at half the lease"
    );
}

#[test]
fn removal_checks_ownership_so_a_foreign_mapping_stays() {
    let (nat, scratch, fixture) = (nat(), Scratch::new(), Fixture::new());
    let upnp = FakeUpnpGateway::start(UpnpBehaviour::default());
    upnp.insert(UpnpMapping {
        protocol: Protocol::Udp,
        external_port: 40123,
        internal: "192.168.1.77:40123".parse().unwrap(),
        description: "someone else".into(),
        lease: 0,
    });
    let plan = plan(&nat, Some(&upnp), &[Method::Upnp], &scratch, &fixture);
    let mut session = start(&plan).unwrap();
    assert_eq!(upnp.mappings().len(), 9);
    assert_eq!(session.release(RELEASE_BUDGET), (8, 0));
    let left = upnp.mappings();
    assert_eq!(left.len(), 1);
    assert_eq!(left[0].description, "someone else");
}

#[test]
fn a_router_that_refuses_the_listener_leaves_nothing_behind() {
    let (scratch, fixture) = (Scratch::new(), Fixture::new());
    let gateway = FakeNatGateway::start(NatBehaviour {
        pcp: PcpMode::Refuse(2),
        natpmp: NatPmpMode::Refuse(2),
        ..NatBehaviour::default()
    });
    let plan = plan(
        &gateway,
        None,
        &[Method::Pcp, Method::NatPmp],
        &scratch,
        &fixture,
    );
    assert_eq!(start(&plan).err(), Some(Reason::Refused));
    assert!(gateway.mappings().is_empty());
    assert!(scratch.entries().is_empty());
}

#[test]
fn a_router_that_never_answers_is_reported_as_silent() {
    let (scratch, fixture) = (Scratch::new(), Fixture::new());
    let gateway = FakeNatGateway::start(NatBehaviour {
        pcp: PcpMode::Silent,
        natpmp: NatPmpMode::Silent,
        ..NatBehaviour::default()
    });
    let plan = plan(
        &gateway,
        None,
        &[Method::Pcp, Method::NatPmp],
        &scratch,
        &fixture,
    );
    assert_eq!(start(&plan).err(), Some(Reason::NoAnswer));
}

#[test]
fn too_few_allocation_ports_release_the_listener_too() {
    let (gateway, scratch, fixture) = (nat(), Scratch::new(), Fixture::new());
    let mut plan = plan(&gateway, None, &[Method::Pcp], &scratch, &fixture);
    plan.minimum = plan.wanted + 1;
    assert_eq!(start(&plan).err(), Some(Reason::TooFewPorts));
    assert!(gateway.mappings().is_empty(), "the listener was given back");
    assert!(scratch.entries().is_empty());
}

#[test]
fn a_stop_during_acquisition_gives_everything_back() {
    let (gateway, scratch, fixture) = (nat(), Scratch::new(), Fixture::new());
    let plan = plan(&gateway, None, &[Method::Pcp], &scratch, &fixture);
    let stop = Stop::new();
    stop.set();
    assert_eq!(
        Session::start(&plan, &stop, &|_| {}).err(),
        Some(Reason::Cancelled)
    );
    assert!(gateway.mappings().is_empty());
}

#[test]
fn the_bind_address_must_be_the_one_that_reaches_the_router() {
    let (gateway, scratch, fixture) = (nat(), Scratch::new(), Fixture::new());
    let mut plan = plan(&gateway, None, &[Method::Pcp], &scratch, &fixture);
    plan.bind = Ipv4Addr::new(192, 168, 1, 20);
    assert_eq!(start(&plan).err(), Some(Reason::WrongInterface));
    assert!(gateway.mappings().is_empty());
}

#[test]
fn an_address_that_cannot_be_reached_from_outside_is_refused_by_kind() {
    for (external, reason) in [
        (Ipv4Addr::new(100, 64, 3, 3), Reason::CarrierGradeNat),
        (Ipv4Addr::new(192, 168, 1, 5), Reason::DoubleNat),
        (spry_portmap::fake::EXTERNAL, Reason::UnusableAddress),
    ] {
        let (scratch, fixture) = (Scratch::new(), Fixture::new());
        let gateway = FakeNatGateway::start(NatBehaviour {
            external,
            ..NatBehaviour::default()
        });
        let mut plan = plan(&gateway, None, &[Method::Pcp], &scratch, &fixture);
        plan.local_test = false;
        assert_eq!(start(&plan).err(), Some(reason), "{external}");
        assert!(gateway.mappings().is_empty(), "{external}: given back");
    }
    // A public address passes the same check.
    let (scratch, fixture) = (Scratch::new(), Fixture::new());
    let gateway = FakeNatGateway::start(NatBehaviour {
        external: Ipv4Addr::new(100, 128, 0, 7),
        ..NatBehaviour::default()
    });
    let mut plan = plan(&gateway, None, &[Method::Pcp], &scratch, &fixture);
    plan.local_test = false;
    assert!(start(&plan).is_ok());
}

#[test]
fn a_record_that_cannot_be_read_is_set_aside_not_a_dead_end() {
    let (gateway, scratch, fixture) = (nat(), Scratch::new(), Fixture::new());
    let plan = plan(&gateway, None, &[Method::Pcp], &scratch, &fixture);
    std::fs::write(scratch.record(), "not a record\n").unwrap();
    assert!(start(&plan).is_ok());
    assert!(scratch.0.join("state.json.mappings.rejected").exists());
    assert_eq!(scratch.entries().len(), 8);
}

#[test]
fn updates_carry_counts_states_and_reason_tokens_only() {
    let values = Values {
        public_ip: Ipv4Addr::new(100, 128, 0, 7),
        udp_port: 51000,
        tcp_port: 51001,
        map: vec![(49200, 51002)],
    };
    let info = Info {
        method: Method::NatPmp,
        allocation_ports: 1,
        requested: 8,
        permanent: true,
    };
    let lines = [
        Update::Cleaned {
            removed: 2,
            remaining: 1,
        },
        Update::Mapped {
            values: values.clone(),
            info,
        },
        Update::Changed {
            values,
            info,
            reason: "address",
        },
        Update::Failed(Reason::CarrierGradeNat),
        Update::Lost(Reason::Expired),
        Update::Released {
            removed: 9,
            remaining: 0,
        },
    ]
    .map(|update| update.event().unwrap());
    assert_eq!(
        lines[1],
        json!({"v":1,"event":"portmap","state":"mapped","method":"natpmp",
               "allocationPorts":1,"requested":8,"permanent":true})
    );
    assert_eq!(
        lines[3],
        json!({"v":1,"event":"portmap","state":"failed","reason":"carrier-grade-nat"})
    );
    for line in &lines {
        let text = line.to_string();
        assert!(text.len() < 200, "{text}");
        for secret in ["100.128", "51000", "51002", "49200", "127.0.0.1"] {
            assert!(!text.contains(secret), "{text}");
        }
    }
    assert!(Update::Failed(Reason::Cancelled).event().is_none());
}

#[test]
fn the_thread_reports_the_grant_a_change_and_the_release_in_order() {
    let (gateway, scratch) = (nat(), Scratch::new());
    // Real time: a four second lease renews after two.
    let gateway_behaviour = NatBehaviour {
        max_lifetime: 4,
        ..NatBehaviour::default()
    };
    gateway.set(gateway_behaviour.clone());
    let fixture = Fixture::new();
    let mut plan = plan(&gateway, None, &[Method::Pcp], &scratch, &fixture);
    plan.options.clock = Arc::new(Instant::now);
    let (send, mut receive) = tokio::sync::mpsc::unbounded_channel();
    let mut task = Task::spawn(plan, send).unwrap();
    let wait = |receive: &mut tokio::sync::mpsc::UnboundedReceiver<Update>| {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            if let Ok(update) = receive.try_recv() {
                return update;
            }
            assert!(Instant::now() < deadline, "no update");
            thread::sleep(Duration::from_millis(20));
        }
    };
    assert!(matches!(wait(&mut receive), Update::Mapped { .. }));
    gateway.set(NatBehaviour {
        external: Ipv4Addr::new(100, 128, 0, 9),
        ..gateway_behaviour
    });
    let Update::Changed { values, reason, .. } = wait(&mut receive) else {
        panic!("expected a change");
    };
    assert_eq!(reason, "address");
    assert_eq!(values.public_ip, Ipv4Addr::new(100, 128, 0, 9));
    task.stop();
    assert_eq!(
        wait(&mut receive),
        Update::Released {
            removed: 8,
            remaining: 0
        }
    );
    assert!(gateway.mappings().is_empty());
}

/// Drop the given mappings from the fake router, as the router seen on 30
/// October 2026 did long before their lease ended.
fn drop_from(upnp: &FakeUpnpGateway, gone: &[(Protocol, u16)]) {
    let kept: Vec<UpnpMapping> = upnp
        .mappings()
        .into_iter()
        .filter(|m| !gone.contains(&(m.protocol, m.external_port)))
        .collect();
    upnp.clear();
    for mapping in kept {
        upnp.insert(mapping);
    }
}

fn count(upnp: &FakeUpnpGateway, action: &str) -> usize {
    upnp.actions().iter().filter(|a| a.contains(action)).count()
}

#[test]
fn a_upnp_mapping_the_router_drops_mid_lease_is_put_back_within_a_minute() {
    let (nat, scratch, fixture) = (nat(), Scratch::new(), Fixture::new());
    let upnp = FakeUpnpGateway::start(UpnpBehaviour::default());
    let plan = plan(&nat, Some(&upnp), &[Method::Upnp], &scratch, &fixture);
    let mut session = start(&plan).unwrap();
    let values = session.values();
    let allocation = values.map[1].1;
    let asked = count(&upnp, "GetSpecificPortMappingEntry");
    drop_from(
        &upnp,
        &[(Protocol::Udp, LISTEN), (Protocol::Udp, allocation)],
    );
    assert_eq!(upnp.mappings().len(), 6);
    fixture.advance(59);
    assert_eq!(session.tick(), Tick::Idle);
    assert_eq!(upnp.mappings().len(), 6, "nothing is asked before a minute");
    assert_eq!(count(&upnp, "GetSpecificPortMappingEntry"), asked);
    fixture.advance(2);
    assert_eq!(
        session.tick(),
        Tick::Idle,
        "the same values come back, so the relay keeps running"
    );
    assert_eq!(session.take_restored(), 2);
    assert_eq!(session.take_restored(), 0);
    assert_eq!(upnp.mappings().len(), 8);
    assert_eq!(session.values(), values);
    assert!(
        upnp.mappings()
            .iter()
            .any(|m| m.protocol == Protocol::Udp && m.external_port == LISTEN)
    );
    assert_eq!(scratch.entries().len(), 8);
}

#[test]
fn a_check_that_finds_everything_held_adds_nothing() {
    let (nat, scratch, fixture) = (nat(), Scratch::new(), Fixture::new());
    let upnp = FakeUpnpGateway::start(UpnpBehaviour::default());
    let plan = plan(&nat, Some(&upnp), &[Method::Upnp], &scratch, &fixture);
    let mut session = start(&plan).unwrap();
    let adds = count(&upnp, "AddPortMapping");
    let asked = count(&upnp, "GetSpecificPortMappingEntry");
    fixture.advance(61);
    assert_eq!(session.tick(), Tick::Idle);
    assert_eq!(count(&upnp, "GetSpecificPortMappingEntry"), asked + 8);
    assert_eq!(count(&upnp, "AddPortMapping"), adds);
    assert_eq!(session.take_restored(), 0);
    fixture.advance(30);
    assert_eq!(session.tick(), Tick::Idle);
    assert_eq!(
        count(&upnp, "GetSpecificPortMappingEntry"),
        asked + 8,
        "each mapping is asked at most once a minute"
    );
}

#[test]
fn a_dropped_allocation_port_the_router_will_not_take_back_shrinks_the_map() {
    let (nat, scratch, fixture) = (nat(), Scratch::new(), Fixture::new());
    let upnp = FakeUpnpGateway::start(UpnpBehaviour::default());
    let plan = plan(&nat, Some(&upnp), &[Method::Upnp], &scratch, &fixture);
    let mut session = start(&plan).unwrap();
    let allocation = session.values().map[0].1;
    drop_from(&upnp, &[(Protocol::Udp, allocation)]);
    upnp.set(UpnpBehaviour {
        refuse: Some(718),
        ..UpnpBehaviour::default()
    });
    fixture.advance(61);
    assert_eq!(session.tick(), Tick::Changed("ports"));
    assert_eq!(session.info().allocation_ports, 5);
    assert!(
        session
            .values()
            .map
            .iter()
            .all(|(_, external)| *external != allocation)
    );
    assert_eq!(scratch.entries().len(), 7);
}

#[test]
fn a_dropped_listener_the_router_will_not_take_back_is_a_loss() {
    let (nat, scratch, fixture) = (nat(), Scratch::new(), Fixture::new());
    let upnp = FakeUpnpGateway::start(UpnpBehaviour::default());
    let plan = plan(&nat, Some(&upnp), &[Method::Upnp], &scratch, &fixture);
    let mut session = start(&plan).unwrap();
    drop_from(&upnp, &[(Protocol::Udp, LISTEN)]);
    upnp.set(UpnpBehaviour {
        refuse: Some(718),
        ..UpnpBehaviour::default()
    });
    fixture.advance(61);
    assert_eq!(session.tick(), Tick::Lost(Reason::Expired));
}

#[test]
fn pcp_mappings_are_renewed_every_minute_since_pcp_cannot_be_asked() {
    let (scratch, fixture) = (Scratch::new(), Fixture::new());
    let gateway = FakeNatGateway::start(NatBehaviour::default());
    let plan = plan(&gateway, None, &[Method::Pcp], &scratch, &fixture);
    let mut session = start(&plan).unwrap();
    let before = gateway.requests().len();
    fixture.advance(59);
    assert_eq!(session.tick(), Tick::Idle);
    assert_eq!(
        gateway.requests().len(),
        before,
        "a 7200 s lease, nothing due yet"
    );
    fixture.advance(2);
    assert_eq!(session.tick(), Tick::Idle);
    assert_eq!(
        gateway.requests().len(),
        before + 8,
        "every mapping renewed, which puts back any the router lost"
    );
}

#[test]
fn a_restore_is_reported_as_a_count_only() {
    let line = Update::Restored { count: 5 }.event().unwrap();
    assert_eq!(
        line,
        json!({"v":1,"event":"portmap","state":"restored","restored":5})
    );
}
