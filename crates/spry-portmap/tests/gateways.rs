//! Mapping lifecycle against the in-house fake gateways on loopback.

use spry_portmap::fake::{
    EXTERNAL, FakeNatGateway, FakeUpnpGateway, NatBehaviour, NatPmpMode, PcpMode, UpnpBehaviour,
    UpnpMapping,
};
use spry_portmap::record::{self, Ledger};
use spry_portmap::upnp::Service;
use spry_portmap::{Cleanup, Error, Method, Options, Owner, PortMapper, Protocol, Request, check};
use std::net::{Ipv4Addr, SocketAddrV4, UdpSocket};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

const LEASE: Duration = Duration::from_secs(7200);

/// A loopback port with nothing behind it.
fn closed_port() -> u16 {
    let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    socket.local_addr().unwrap().port()
}

fn options(nat: Option<&FakeNatGateway>, upnp: Option<&FakeUpnpGateway>) -> Options {
    Options {
        gateway: Some(Ipv4Addr::LOCALHOST),
        gateway_port: nat.map_or_else(closed_port, |nat| nat.address().port()),
        ssdp: upnp.map_or_else(
            || SocketAddrV4::new(Ipv4Addr::LOCALHOST, closed_port()),
            FakeUpnpGateway::ssdp,
        ),
        timeout: Duration::from_millis(400),
        ..Options::default()
    }
}

fn nat(pcp: PcpMode, natpmp: NatPmpMode) -> FakeNatGateway {
    FakeNatGateway::start(NatBehaviour {
        pcp,
        natpmp,
        ..NatBehaviour::default()
    })
}

fn methods(error: &Error) -> Vec<Method> {
    match error {
        Error::NoMethod(attempts) => attempts.iter().map(|(method, _)| *method).collect(),
        other => panic!("expected NoMethod, got {other:?}"),
    }
}

#[test]
fn pcp_maps_renews_and_removes_by_nonce() {
    let gateway = nat(PcpMode::Grant, NatPmpMode::Silent);
    let mut mapper = PortMapper::new(options(Some(&gateway), None)).unwrap();
    assert_eq!(mapper.local(), Ipv4Addr::LOCALHOST);
    let udp = mapper
        .map(Request::new(Protocol::Udp, 3478, LEASE))
        .unwrap();
    let tcp = mapper
        .map(Request::new(Protocol::Tcp, 3478, LEASE))
        .unwrap();
    assert_eq!(mapper.method(), Some(Method::Pcp));
    assert!(mapper.attempts().is_empty());
    assert_eq!(udp.external, SocketAddrV4::new(EXTERNAL, 3478));
    assert_eq!(udp.lifetime, Some(LEASE));
    assert!(!udp.translated());
    let Owner::Pcp { nonce } = udp.owner else {
        panic!("PCP mapping without a nonce")
    };
    let held = gateway.mappings();
    assert_eq!(held.len(), 2);
    assert_eq!(held[0].nonce, Some(nonce));
    assert_ne!(
        held[0].nonce, held[1].nonce,
        "each mapping has its own nonce"
    );
    assert_eq!(mapper.external_address().unwrap(), EXTERNAL);

    let renewal = mapper.renew(&udp).unwrap();
    assert!(!renewal.changed && !renewal.gateway_restarted);
    assert_eq!(renewal.mapping.external, udp.external);
    assert!(renewal.mapping.granted_at >= udp.granted_at);
    // Every PCP request was version 2 MAP; no NAT-PMP was tried.
    assert!(
        gateway
            .requests()
            .iter()
            .all(|r| r.version == 2 && r.opcode == 1)
    );

    mapper.remove(&udp).unwrap();
    mapper.remove(&tcp).unwrap();
    assert!(gateway.mappings().is_empty());
    let last = *gateway.requests().last().unwrap();
    assert_eq!(last.lifetime, 0);
}

#[test]
fn pcp_translated_port_and_shortened_lease() {
    let gateway = FakeNatGateway::start(NatBehaviour {
        translate: true,
        max_lifetime: 600,
        ..NatBehaviour::default()
    });
    let mut mapper = PortMapper::new(options(Some(&gateway), None)).unwrap();
    let mapping = mapper
        .map(Request::new(Protocol::Udp, 40000, LEASE))
        .unwrap();
    assert_eq!(mapping.external.port(), 50000);
    assert!(mapping.translated());
    assert_eq!(mapping.lifetime, Some(Duration::from_secs(600)));
    assert_eq!(
        mapping.renew_at(),
        Some(mapping.granted_at + Duration::from_secs(300))
    );
    // Renewal asks for the original lifetime again, not the shortened one.
    mapper.renew(&mapping).unwrap();
    assert_eq!(gateway.requests().last().unwrap().lifetime, 7200);
}

#[test]
fn pcp_ignores_a_wrong_nonce_and_takes_the_real_answer() {
    let gateway = nat(PcpMode::WrongNonceThenGrant, NatPmpMode::Silent);
    let mut mapper = PortMapper::new(options(Some(&gateway), None)).unwrap();
    let mapping = mapper
        .map(Request::new(Protocol::Udp, 3478, LEASE))
        .unwrap();
    assert_eq!(mapping.method, Method::Pcp);
}

#[test]
fn pcp_problems_fall_back_to_natpmp() {
    let cases = [
        (PcpMode::Silent, Error::NoAnswer),
        (
            PcpMode::WrongNonce,
            Error::Malformed("reply for another mapping"),
        ),
        (PcpMode::Truncated, Error::Malformed("truncated")),
        (PcpMode::FromOtherPort, Error::NoAnswer),
        (PcpMode::NatPmpOnly, Error::UnsupportedVersion),
        (
            PcpMode::Refuse(2),
            Error::Refused {
                method: Method::Pcp,
                code: 2,
                reason: "not authorised",
            },
        ),
    ];
    for (mode, expected) in cases {
        let gateway = nat(mode, NatPmpMode::Grant);
        let mut mapper = PortMapper::new(options(Some(&gateway), None)).unwrap();
        let mapping = mapper
            .map(Request::new(Protocol::Udp, 3478, LEASE))
            .unwrap();
        assert_eq!(mapping.method, Method::NatPmp, "{mode:?}");
        assert_eq!(mapper.attempts(), &[(Method::Pcp, expected)], "{mode:?}");
        assert_eq!(mapping.external, SocketAddrV4::new(EXTERNAL, 3478));
    }
}

#[test]
fn natpmp_maps_translated_renews_and_removes() {
    let gateway = FakeNatGateway::start(NatBehaviour {
        pcp: PcpMode::NatPmpOnly,
        translate: true,
        ..NatBehaviour::default()
    });
    let mut mapper = PortMapper::new(options(Some(&gateway), None)).unwrap();
    let mapping = mapper
        .map(Request::new(Protocol::Tcp, 3478, LEASE))
        .unwrap();
    assert_eq!(mapping.owner, Owner::NatPmp);
    assert_eq!(mapping.external, SocketAddrV4::new(EXTERNAL, 13478));
    assert_eq!(mapper.external_address().unwrap(), EXTERNAL);
    let renewal = mapper.renew(&mapping).unwrap();
    assert!(!renewal.changed);
    assert_eq!(gateway.mappings().len(), 1);
    mapper.remove(&mapping).unwrap();
    assert!(gateway.mappings().is_empty());
}

#[test]
fn natpmp_problems_fall_back_to_upnp() {
    for mode in [
        NatPmpMode::Refuse(2),
        NatPmpMode::Malformed,
        NatPmpMode::Silent,
    ] {
        let gateway = nat(PcpMode::Silent, mode);
        let upnp = FakeUpnpGateway::start(UpnpBehaviour::default());
        let mut mapper = PortMapper::new(options(Some(&gateway), Some(&upnp))).unwrap();
        let mapping = mapper
            .map(Request::new(Protocol::Udp, 3478, LEASE))
            .unwrap();
        assert_eq!(mapping.method, Method::Upnp, "{mode:?}");
        let tried: Vec<_> = mapper
            .attempts()
            .iter()
            .map(|(method, _)| *method)
            .collect();
        assert_eq!(tried, [Method::Pcp, Method::NatPmp]);
        assert_eq!(upnp.mappings().len(), 1);
    }
}

#[test]
fn nothing_grants_reports_each_protocol_in_order() {
    let gateway = nat(PcpMode::Refuse(8), NatPmpMode::Refuse(4));
    let upnp = FakeUpnpGateway::start(UpnpBehaviour {
        refuse: Some(606),
        ..UpnpBehaviour::default()
    });
    let mut mapper = PortMapper::new(options(Some(&gateway), Some(&upnp))).unwrap();
    let error = mapper
        .map(Request::new(Protocol::Udp, 3478, LEASE))
        .unwrap_err();
    assert_eq!(methods(&error), [Method::Pcp, Method::NatPmp, Method::Upnp]);
    assert_eq!(mapper.method(), None);
    assert!(
        error
            .to_string()
            .contains("UPnP IGD refused: action not authorised (code 606)")
    );
}

#[test]
fn keeps_to_the_first_protocol_that_granted() {
    let gateway = nat(PcpMode::Grant, NatPmpMode::Grant);
    let mut mapper = PortMapper::new(options(Some(&gateway), None)).unwrap();
    mapper
        .map(Request::new(Protocol::Udp, 3478, LEASE))
        .unwrap();
    gateway.set(NatBehaviour {
        pcp: PcpMode::Silent,
        ..NatBehaviour::default()
    });
    // No silent switch to NAT-PMP for later mappings.
    assert_eq!(
        mapper.map(Request::new(Protocol::Udp, 50000, LEASE)),
        Err(Error::NoAnswer)
    );
}

#[test]
fn gateway_restart_is_detected_from_the_epoch() {
    for pcp in [PcpMode::Grant, PcpMode::NatPmpOnly] {
        let gateway = nat(pcp, NatPmpMode::Grant);
        let mut mapper = PortMapper::new(options(Some(&gateway), None)).unwrap();
        let mapping = mapper
            .map(Request::new(Protocol::Udp, 3478, LEASE))
            .unwrap();
        gateway.restart();
        assert!(gateway.mappings().is_empty());
        let renewal = mapper.renew(&mapping).unwrap();
        assert!(renewal.gateway_restarted, "{pcp:?}");
        // The renewal recreated the lost mapping.
        assert_eq!(gateway.mappings().len(), 1);
        let again = mapper.renew(&renewal.mapping).unwrap();
        assert!(!again.gateway_restarted, "{pcp:?}");
    }
}

#[test]
fn epoch_lagging_the_fixture_clock_counts_as_a_restart() {
    let gateway = nat(PcpMode::Grant, NatPmpMode::Silent);
    let base = Instant::now();
    let offset = Arc::new(AtomicU64::new(0));
    let clock = {
        let offset = offset.clone();
        Arc::new(move || base + Duration::from_secs(offset.load(Ordering::SeqCst)))
    };
    let mut mapper = PortMapper::new(Options {
        clock,
        ..options(Some(&gateway), None)
    })
    .unwrap();
    let mapping = mapper
        .map(Request::new(Protocol::Udp, 3478, LEASE))
        .unwrap();
    assert_eq!(mapping.granted_at, base);
    // An hour passes for us while the gateway's epoch barely moves.
    offset.store(3600, Ordering::SeqCst);
    let renewal = mapper.renew(&mapping).unwrap();
    assert!(renewal.gateway_restarted);
    assert_eq!(renewal.mapping.granted_at, base + Duration::from_secs(3600));
    assert_eq!(
        renewal.mapping.renew_at(),
        Some(base + Duration::from_secs(3600 + 3600))
    );
}

fn upnp_only(upnp: &FakeUpnpGateway) -> PortMapper {
    PortMapper::new(Options {
        methods: vec![Method::Upnp],
        ..options(None, Some(upnp))
    })
    .unwrap()
}

#[test]
fn upnp_v1_maps_checks_ownership_and_removes() {
    let upnp = FakeUpnpGateway::start(UpnpBehaviour::default());
    let mut mapper = upnp_only(&upnp);
    let mapping = mapper
        .map(Request::new(Protocol::Udp, 3478, LEASE))
        .unwrap();
    assert!(upnp.searches() > 0);
    assert_eq!(mapping.external, SocketAddrV4::new(EXTERNAL, 3478));
    assert_eq!(mapping.lifetime, Some(LEASE));
    let Owner::Upnp {
        service,
        description,
        control,
    } = &mapping.owner
    else {
        panic!("UPnP mapping without UPnP ownership")
    };
    assert_eq!(*service, Service::WanIp1);
    assert_eq!(description, "spry relay");
    assert_eq!(control.path, "/ctl/IPConn");
    assert_eq!(
        upnp.mappings(),
        [UpnpMapping {
            protocol: Protocol::Udp,
            external_port: 3478,
            internal: SocketAddrV4::new(Ipv4Addr::LOCALHOST, 3478),
            description: "spry relay".into(),
            lease: 7200,
        }]
    );
    let renewal = mapper.renew(&mapping).unwrap();
    assert!(!renewal.changed);
    mapper.remove(&mapping).unwrap();
    assert!(upnp.mappings().is_empty());
    let actions = upnp.actions();
    let read = actions
        .iter()
        .rposition(|a| a == "GetSpecificPortMappingEntry")
        .unwrap();
    let delete = actions
        .iter()
        .position(|a| a == "DeletePortMapping")
        .unwrap();
    assert!(
        read < delete,
        "ownership is checked before the delete: {actions:?}"
    );
}

#[test]
fn upnp_v2_takes_a_translated_reserved_port() {
    let upnp = FakeUpnpGateway::start(UpnpBehaviour {
        version: 2,
        ..UpnpBehaviour::default()
    });
    upnp.insert(UpnpMapping {
        protocol: Protocol::Udp,
        external_port: 3478,
        internal: SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 9), 3478),
        description: "another host".into(),
        lease: 0,
    });
    let mut mapper = upnp_only(&upnp);
    let mapping = mapper
        .map(Request::new(Protocol::Udp, 3478, LEASE))
        .unwrap();
    assert!(matches!(
        mapping.owner,
        Owner::Upnp {
            service: Service::WanIp2,
            ..
        }
    ));
    assert_eq!(mapping.external.port(), 3479);
    assert!(mapping.translated());
    assert!(upnp.actions().contains(&"AddAnyPortMapping".to_owned()));
    mapper.remove(&mapping).unwrap();
    // The other host's mapping is untouched.
    assert_eq!(upnp.mappings().len(), 1);
}

#[test]
fn upnp_permanent_only_router_is_used_and_recorded_when_allowed() {
    let upnp = FakeUpnpGateway::start(UpnpBehaviour {
        permanent_only: true,
        ..UpnpBehaviour::default()
    });
    let mut mapper = upnp_only(&upnp);
    let mapping = mapper
        .map(Request::new(Protocol::Tcp, 3478, LEASE))
        .unwrap();
    assert!(mapping.is_permanent());
    assert_eq!(mapping.renew_at(), None);
    assert_eq!(upnp.mappings()[0].lease, 0);
    assert_eq!(mapping.entry(1_000).expires, None);
    // Renewing re-adds it with lease 0, which also restores it after a reboot.
    upnp.clear();
    mapper.renew(&mapping).unwrap();
    assert_eq!(upnp.mappings()[0].lease, 0);
    mapper.remove(&mapping).unwrap();
    assert!(upnp.mappings().is_empty());

    let mut strict = PortMapper::new(Options {
        methods: vec![Method::Upnp],
        allow_permanent: false,
        ..options(None, Some(&upnp))
    })
    .unwrap();
    let error = strict
        .map(Request::new(Protocol::Tcp, 3478, LEASE))
        .unwrap_err();
    assert_eq!(
        error,
        Error::NoMethod(vec![(Method::Upnp, Error::PermanentOnly)])
    );
    assert!(upnp.mappings().is_empty());
}

#[test]
fn upnp_conflict_refusal_and_malformed_replies() {
    let upnp = FakeUpnpGateway::start(UpnpBehaviour::default());
    upnp.insert(UpnpMapping {
        protocol: Protocol::Udp,
        external_port: 3478,
        internal: SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 9), 3478),
        description: "another host".into(),
        lease: 0,
    });
    let mut mapper = upnp_only(&upnp);
    let error = mapper
        .map(Request::new(Protocol::Udp, 3478, LEASE))
        .unwrap_err();
    assert!(matches!(
        &error,
        Error::NoMethod(attempts) if matches!(attempts[0].1, Error::Refused { code: 718, .. })
    ));

    upnp.set(UpnpBehaviour {
        garbage: true,
        ..UpnpBehaviour::default()
    });
    let mut mapper = upnp_only(&upnp);
    let error = mapper
        .map(Request::new(Protocol::Udp, 4000, LEASE))
        .unwrap_err();
    assert!(matches!(
        &error,
        Error::NoMethod(attempts) if matches!(attempts[0].1, Error::Malformed(_))
    ));
}

#[test]
fn upnp_chunked_replies_and_ppp_service() {
    let upnp = FakeUpnpGateway::start(UpnpBehaviour {
        chunked: true,
        ppp: true,
        ..UpnpBehaviour::default()
    });
    let mut mapper = upnp_only(&upnp);
    let mapping = mapper
        .map(Request::new(Protocol::Udp, 3478, LEASE))
        .unwrap();
    assert!(matches!(
        mapping.owner,
        Owner::Upnp {
            service: Service::WanPpp1,
            ..
        }
    ));
    mapper.remove(&mapping).unwrap();
}

#[test]
fn upnp_never_follows_urls_off_the_gateway() {
    let off_lan = FakeUpnpGateway::start(UpnpBehaviour {
        location_host: Some(Ipv4Addr::new(192, 0, 2, 1)),
        ..UpnpBehaviour::default()
    });
    let error = upnp_only(&off_lan)
        .map(Request::new(Protocol::Udp, 3478, LEASE))
        .unwrap_err();
    assert_eq!(error, Error::NoMethod(vec![(Method::Upnp, Error::OffLan)]));

    let off_lan_control = FakeUpnpGateway::start(UpnpBehaviour {
        control_url: Some("http://192.0.2.1:5000/ctl/IPConn".into()),
        ..UpnpBehaviour::default()
    });
    let error = upnp_only(&off_lan_control)
        .map(Request::new(Protocol::Udp, 3478, LEASE))
        .unwrap_err();
    assert_eq!(error, Error::NoMethod(vec![(Method::Upnp, Error::OffLan)]));
    assert!(off_lan_control.actions().is_empty());

    let hostile = FakeUpnpGateway::start(UpnpBehaviour {
        description: Some("<!DOCTYPE root [<!ENTITY x 'y'>]><root>&x;</root>".into()),
        ..UpnpBehaviour::default()
    });
    let error = upnp_only(&hostile)
        .map(Request::new(Protocol::Udp, 3478, LEASE))
        .unwrap_err();
    assert_eq!(
        error,
        Error::NoMethod(vec![(
            Method::Upnp,
            Error::Malformed("document type declarations are refused")
        )])
    );

    let silent = FakeUpnpGateway::start(UpnpBehaviour {
        silent: true,
        ..UpnpBehaviour::default()
    });
    let error = upnp_only(&silent)
        .map(Request::new(Protocol::Udp, 3478, LEASE))
        .unwrap_err();
    assert_eq!(
        error,
        Error::NoMethod(vec![(Method::Upnp, Error::NoAnswer)])
    );
}

#[test]
fn upnp_leaves_a_mapping_that_is_not_ours() {
    let upnp = FakeUpnpGateway::start(UpnpBehaviour::default());
    let mut mapper = upnp_only(&upnp);
    let mapping = mapper
        .map(Request::new(Protocol::Udp, 3478, LEASE))
        .unwrap();
    upnp.set(UpnpBehaviour {
        entry_override: Some((
            SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 9), 3478),
            "spry relay".into(),
        )),
        ..UpnpBehaviour::default()
    });
    assert_eq!(mapper.remove(&mapping), Err(Error::NotOurs));
    assert_eq!(upnp.mappings().len(), 1);
    assert!(!upnp.actions().contains(&"DeletePortMapping".to_owned()));
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn scratch_ledger(name: &str) -> (std::path::PathBuf, Ledger) {
    let directory =
        std::env::temp_dir().join(format!("spry-portmap-{name}-{}", std::process::id()));
    std::fs::create_dir_all(&directory).unwrap();
    let path = directory.join("mappings");
    let _ = std::fs::remove_file(&path);
    let ledger = Ledger::load(&path).unwrap();
    (directory, ledger)
}

#[test]
fn next_launch_removes_a_crashed_runs_mappings() {
    let gateway = nat(PcpMode::Grant, NatPmpMode::Silent);
    let upnp = FakeUpnpGateway::start(UpnpBehaviour {
        permanent_only: true,
        ..UpnpBehaviour::default()
    });
    let (directory, mut ledger) = scratch_ledger("cleanup");
    let now = unix_now();
    {
        // The crashed run: maps, records, never removes.
        let mut pcp = PortMapper::new(options(Some(&gateway), None)).unwrap();
        let mut igd = upnp_only(&upnp);
        for mapping in [
            pcp.map(Request::new(Protocol::Udp, 3478, LEASE)).unwrap(),
            igd.map(Request::new(Protocol::Tcp, 3478, LEASE)).unwrap(),
        ] {
            ledger.record(mapping.entry(now)).unwrap();
        }
    }
    assert_eq!(gateway.mappings().len(), 1);
    assert_eq!(upnp.mappings().len(), 1);

    // A mapping another host holds, recorded as if it were ours, and one
    // from another network.
    upnp.insert(UpnpMapping {
        protocol: Protocol::Udp,
        external_port: 5000,
        internal: SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 9), 5000),
        description: "spry relay".into(),
        lease: 0,
    });
    let mut stranger = ledger.entries()[1].clone();
    stranger.protocol = Protocol::Udp;
    stranger.external_port = 5000;
    stranger.internal = SocketAddrV4::new(Ipv4Addr::LOCALHOST, 5000);
    ledger.record(stranger).unwrap();
    let mut elsewhere = ledger.entries()[0].clone();
    elsewhere.gateway = Ipv4Addr::new(10, 0, 0, 1);
    ledger.record(elsewhere).unwrap();
    let mut natpmp = ledger.entries()[0].clone();
    natpmp.method = Method::NatPmp;
    natpmp.nonce = None;
    natpmp.external_port = 6000;
    ledger.record(natpmp).unwrap();
    let mut expired = ledger.entries()[0].clone();
    expired.external_port = 7000;
    expired.expires = Some(now - 1);
    ledger.record(expired).unwrap();

    // The next launch reads the record back and cleans up.
    let ledger = Ledger::load(ledger.path()).unwrap();
    let mut mapper = PortMapper::new(Options {
        ssdp: upnp.ssdp(),
        ..options(Some(&gateway), None)
    })
    .unwrap();
    let outcomes = mapper.cleanup(ledger.entries(), now);
    assert_eq!(
        outcomes,
        [
            Cleanup::Removed,
            Cleanup::Removed,
            Cleanup::Failed(Error::NotOurs),
            Cleanup::OtherNetwork,
            Cleanup::LeftToExpire,
            Cleanup::Expired,
        ]
    );
    assert!(
        gateway.mappings().is_empty(),
        "PCP leftover removed by nonce"
    );
    assert_eq!(
        upnp.mappings().len(),
        1,
        "only the other host's mapping remains"
    );
    assert_eq!(upnp.mappings()[0].external_port, 5000);
    // A second pass finds the removed ones gone.
    let again = mapper.cleanup(&ledger.entries()[1..2], now);
    assert_eq!(again, [Cleanup::Gone]);
    std::fs::remove_dir_all(directory).unwrap();
}

#[test]
fn record_round_trips_real_mappings() {
    let gateway = nat(PcpMode::Grant, NatPmpMode::Silent);
    let mut mapper = PortMapper::new(options(Some(&gateway), None)).unwrap();
    let mapping = mapper
        .map(Request::new(Protocol::Udp, 3478, LEASE))
        .unwrap();
    let entry = mapping.entry(1_000);
    let text = record::encode(std::slice::from_ref(&entry)).unwrap();
    assert_eq!(record::decode(&text).unwrap(), [entry]);
}

#[test]
fn check_maps_reports_and_removes() {
    let gateway = nat(PcpMode::Silent, NatPmpMode::Grant);
    let report = check::run(check::CheckOptions {
        mapper: options(Some(&gateway), None),
        port: Some(51000),
        ..check::CheckOptions::default()
    });
    assert!(report.succeeded(), "{report}");
    assert_eq!(report.method, Some(Method::NatPmp));
    assert_eq!(report.outcomes.len(), 2);
    assert!(
        gateway.mappings().is_empty(),
        "the check removes what it mapped"
    );
    let text = report.to_string();
    assert!(text.contains("PCP: no answer"), "{text}");
    assert!(text.contains("NAT-PMP: granted"), "{text}");
    assert!(
        text.contains("UDP 51000: external port 51000, lease 120 s"),
        "{text}"
    );
    assert!(text.contains("TCP 51000: removed"), "{text}");

    let nothing = nat(PcpMode::Silent, NatPmpMode::Silent);
    let report = check::run(check::CheckOptions {
        mapper: Options {
            methods: vec![Method::Pcp, Method::NatPmp],
            ..options(Some(&nothing), None)
        },
        port: Some(51000),
        ..check::CheckOptions::default()
    });
    assert!(!report.succeeded());
    assert_eq!(
        report.outcomes.len(),
        1,
        "TCP is not retried after UDP found no protocol"
    );
    assert!(report.to_string().contains("Turn on UPnP"), "{report}");
}
