use super::*;

const TEST_SECRET: &[u8] = b"synthetic-supervised-secret-not-for-deployment";

fn key(seed: u8) -> String {
    Identity::from_secret(&[seed; 32]).unwrap().public_key()
}
fn environment() -> Environment {
    Environment {
        secret: Some(TEST_SECRET.to_vec()),
        ..Environment::default()
    }
}
/// A complete, valid argument list. 100.128.0.7 lies just outside every
/// refused range; no test sends a packet to it.
fn arguments() -> Vec<(&'static str, String)> {
    vec![
        ("--exit-on-stdin-close", String::new()),
        ("--pairing-key", key(2)),
        (
            "--state-file",
            "uncreated-supervised-fixture/state.json".into(),
        ),
        ("--control-relay", "wss://relay.example/".into()),
        ("--bind", "192.168.1.20".into()),
        ("--public-ip", "100.128.0.7".into()),
        ("--listen-port", "41000".into()),
        ("--public-udp-port", "51000".into()),
        ("--public-tcp-port", "51001".into()),
        ("--relay-port-map", "41002:51002".into()),
        ("--relay-port-map", "41003:51007".into()),
    ]
}
fn flatten(arguments: &[(&str, String)]) -> Vec<String> {
    let mut flat = Vec::new();
    for (name, value) in arguments {
        flat.push((*name).to_owned());
        if *name != "--exit-on-stdin-close" {
            flat.push(value.clone());
        }
    }
    flat
}
fn parse(arguments: &[(&str, String)]) -> Result<Settings, SetupError> {
    Settings::parse(&flatten(arguments), &environment())
}
fn with(name: &'static str, value: &str) -> Vec<(&'static str, String)> {
    let mut list: Vec<_> = arguments()
        .into_iter()
        .filter(|(existing, _)| *existing != name)
        .collect();
    list.push((name, value.to_owned()));
    list
}
fn without(name: &str) -> Vec<(&'static str, String)> {
    arguments()
        .into_iter()
        .filter(|(existing, _)| *existing != name)
        .collect()
}

#[test]
fn explicit_values_become_two_turn_urls_home_caps_and_a_mapped_relay() {
    let settings = parse(&arguments()).unwrap();
    assert_eq!(
        settings.urls(),
        [
            "turn:100.128.0.7:51000?transport=udp",
            "turn:100.128.0.7:51001?transport=tcp"
        ]
    );
    assert_eq!(
        (
            settings.allocations,
            settings.per_user,
            settings.connections,
            settings.bytes_per_second
        ),
        (8, 2, 16, 125_000)
    );
    assert_eq!(settings.mappings, [(41002, 51002), (41003, 51007)]);
    assert_eq!(settings.relays, ["wss://relay.example/"]);
    let relay = settings.relay_config();
    assert_eq!(relay.listen, "192.168.1.20:41000".parse().unwrap());
    assert_eq!(
        relay.relay_ip,
        "192.168.1.20".parse::<std::net::IpAddr>().unwrap()
    );
    assert_eq!(relay.advertised_ip, Some("100.128.0.7".parse().unwrap()));
    assert_eq!(relay.relay_port_range, None);
    let mapped: Vec<_> = relay
        .relay_port_mappings
        .as_ref()
        .unwrap()
        .iter()
        .map(|mapping| (mapping.local_port, mapping.advertised_port))
        .collect();
    assert_eq!(mapped, [(41002, 51002), (41003, 51007)]);
    assert_eq!(
        (
            relay.max_allocations,
            relay.max_per_user,
            relay.max_connections,
            relay.bytes_per_second
        ),
        (8, 2, 16, 125_000)
    );
    assert!(!relay.allow_loopback_peers && !relay.local_peer_bridge);
    assert_eq!(format!("{settings:?}"), "Settings { .. }");
}

#[test]
fn caps_may_be_raised_to_the_standard_maximum_and_no_further() {
    let mut raised = arguments();
    raised.extend([
        ("--max-allocations", "32".to_owned()),
        ("--max-per-user", "8".to_owned()),
        ("--max-tcp-connections", "32".to_owned()),
        ("--bytes-per-second", "67108864".to_owned()),
    ]);
    let settings = parse(&raised).unwrap();
    assert_eq!(
        (
            settings.allocations,
            settings.per_user,
            settings.connections,
            settings.bytes_per_second
        ),
        (32, 8, 32, 67_108_864)
    );
    // An unset per-user cap follows a lowered total.
    assert_eq!(parse(&with("--max-allocations", "1")).unwrap().per_user, 1);
    for (name, bad, error) in [
        ("--max-allocations", "33", ALLOCATIONS),
        ("--max-allocations", "0", ALLOCATIONS),
        ("--max-allocations", "+8", ALLOCATIONS),
        ("--max-per-user", "9", PER_USER),
        ("--max-per-user", "0", PER_USER),
        ("--max-tcp-connections", "33", CONNECTIONS),
        ("--max-tcp-connections", "", CONNECTIONS),
        ("--bytes-per-second", "67108865", BANDWIDTH),
        ("--bytes-per-second", "0", BANDWIDTH),
        ("--bytes-per-second", "1e6", BANDWIDTH),
    ] {
        assert_eq!(parse(&with(name, bad)).unwrap_err(), error, "{name} {bad}");
    }
    let mut over = with("--max-allocations", "2");
    over.push(("--max-per-user", "3".into()));
    assert_eq!(parse(&over).unwrap_err(), PER_USER);
}

#[test]
fn every_network_value_is_required_and_never_guessed() {
    for (name, error) in [
        ("--exit-on-stdin-close", STDIN),
        ("--pairing-key", PAIRING_KEY),
        ("--state-file", STATE_FILE),
        ("--control-relay", CONTROL_RELAYS),
        ("--bind", BIND),
        ("--public-ip", PUBLIC_IP),
        ("--listen-port", LISTEN_PORT),
        ("--public-udp-port", PUBLIC_UDP_PORT),
        ("--public-tcp-port", PUBLIC_TCP_PORT),
        ("--relay-port-map", PORT_MAP),
    ] {
        assert_eq!(parse(&without(name)).unwrap_err(), error, "{name}");
    }
}

#[test]
fn addresses_must_be_concrete_and_the_advertised_address_public() {
    for bad in [
        "0.0.0.0",
        "127.0.0.1",
        "224.0.0.1",
        "255.255.255.255",
        "169.254.1.1",
        "::1",
        "fd00::1",
        "192.168.1",
        "",
    ] {
        assert_eq!(parse(&with("--bind", bad)).unwrap_err(), BIND, "{bad}");
    }
    for bad in [
        "192.168.1.1",
        "10.0.0.1",
        "172.16.0.1",
        "100.64.0.1",
        "100.127.255.255",
        "203.0.113.9",
        "127.0.0.1",
        "169.254.0.1",
        "192.0.0.1",
        "198.18.0.1",
        "192.0.2.1",
        "198.51.100.1",
        "224.0.0.1",
        "240.0.0.1",
        "0.0.0.0",
        "2001:db8::1",
        "relay.example",
    ] {
        assert_eq!(
            parse(&with("--public-ip", bad)).unwrap_err(),
            PUBLIC_IP,
            "{bad}"
        );
    }
    // Just outside carrier-grade NAT space, so public; never contacted.
    assert!(parse(&with("--public-ip", "100.128.0.8")).is_ok());
}

#[test]
fn ports_stay_high_distinct_and_apart_from_the_listener() {
    for (name, error) in [
        ("--listen-port", LISTEN_PORT),
        ("--public-udp-port", PUBLIC_UDP_PORT),
        ("--public-tcp-port", PUBLIC_TCP_PORT),
    ] {
        for bad in ["0", "1023", "65536", "-1", " 41000", "41000 ", "0x1000", ""] {
            assert_eq!(parse(&with(name, bad)).unwrap_err(), error, "{name} {bad}");
        }
    }
    assert!(parse(&with("--listen-port", "1024")).is_ok());
    for bad in [
        "41002",
        "41002:",
        ":51002",
        "41002:51002:1",
        "1023:51002",
        "41002:1023",
        "41002:65536",
        // The local listener port.
        "41000:51010",
        // The public UDP listener port.
        "41010:51000",
    ] {
        assert_eq!(
            parse(&with("--relay-port-map", bad)).unwrap_err(),
            PORT_MAP,
            "{bad}"
        );
    }
    // The public TCP listener port may also carry a UDP allocation.
    assert!(parse(&with("--relay-port-map", "41010:51001")).is_ok());
    let mut duplicate_local = arguments();
    duplicate_local.push(("--relay-port-map", "41002:51020".into()));
    assert_eq!(parse(&duplicate_local).unwrap_err(), PORT_MAP);
    let mut duplicate_public = arguments();
    duplicate_public.push(("--relay-port-map", "41020:51002".into()));
    assert_eq!(parse(&duplicate_public).unwrap_err(), PORT_MAP);
    let mut many = without("--relay-port-map");
    for index in 0..MAX_MAPPINGS as u16 {
        many.push((
            "--relay-port-map",
            format!("{}:{}", 42000 + index, 52000 + index),
        ));
    }
    assert_eq!(parse(&many).unwrap().mappings.len(), MAX_MAPPINGS);
    many.push(("--relay-port-map", "43000:53000".into()));
    assert_eq!(parse(&many).unwrap_err(), PORT_MAP);
}

#[test]
fn a_host_on_its_public_address_maps_every_port_to_itself() {
    let mut same = with("--bind", "100.128.0.7");
    assert_eq!(parse(&same).unwrap_err(), SAME_ADDRESS);
    same = vec![
        ("--exit-on-stdin-close", String::new()),
        ("--pairing-key", key(2)),
        (
            "--state-file",
            "uncreated-supervised-fixture/state.json".into(),
        ),
        ("--control-relay", "wss://relay.example/".into()),
        ("--bind", "100.128.0.7".into()),
        ("--public-ip", "100.128.0.7".into()),
        ("--listen-port", "41000".into()),
        ("--public-udp-port", "41000".into()),
        ("--public-tcp-port", "41000".into()),
        ("--relay-port-map", "41002:41002".into()),
    ];
    assert!(parse(&same).is_ok());
}

#[test]
fn control_relays_are_one_to_four_distinct_public_wss_urls() {
    let mut four = without("--control-relay");
    for host in ["a", "b", "c", "d"] {
        four.push(("--control-relay", format!("wss://{host}.relay.example/")));
    }
    assert_eq!(parse(&four).unwrap().relays.len(), 4);
    four.push(("--control-relay", "wss://e.relay.example/".into()));
    assert_eq!(parse(&four).unwrap_err(), CONTROL_RELAYS);
    for bad in [
        "ws://relay.example/",
        "wss://127.0.0.1/",
        "wss://[::1]/",
        "wss://relay.local/",
        "wss://relay/",
        "https://relay.example/",
        "wss://user@relay.example/",
        "wss://relay.example/?x=1",
        "not a url",
    ] {
        assert_eq!(
            parse(&with("--control-relay", bad)).unwrap_err(),
            CONTROL_RELAYS,
            "{bad}"
        );
    }
    let mut repeated = arguments();
    repeated.push(("--control-relay", "wss://relay.example/".into()));
    assert_eq!(parse(&repeated).unwrap_err(), CONTROL_RELAYS);
}

#[test]
fn the_pairing_key_is_a_lowercase_x_only_key() {
    for bad in [
        "",
        "00",
        &key(2).to_uppercase(),
        &format!("{}0", key(2)),
        &"g".repeat(64),
    ] {
        assert_eq!(
            parse(&with("--pairing-key", bad)).unwrap_err(),
            PAIRING_KEY,
            "{bad}"
        );
    }
}

#[test]
fn unknown_repeated_and_valueless_options_are_refused() {
    let base = flatten(&arguments());
    for extra in [
        vec!["--public".to_owned()],
        vec!["--http-port".to_owned(), "3744".to_owned()],
        vec!["--relay-ports".to_owned(), "49160:49191".to_owned()],
        vec!["--exit-on-stdin-close".to_owned()],
        vec!["--bind".to_owned(), "192.168.1.21".to_owned()],
        vec!["--listen-port".to_owned()],
        vec!["serve".to_owned()],
    ] {
        let mut args = base.clone();
        args.extend(extra.clone());
        assert_eq!(
            Settings::parse(&args, &environment()).unwrap_err(),
            ARGUMENT,
            "{extra:?}"
        );
    }
}

#[test]
fn the_environment_is_limited_to_the_secret_seal_and_fixture_settings() {
    let args = flatten(&arguments());
    let refused = |environment: Environment| Settings::parse(&args, &environment).unwrap_err();
    assert_eq!(refused(Environment::default()), SECRET);
    assert_eq!(
        refused(Environment {
            secret: Some(vec![b'x'; 31]),
            ..Environment::default()
        }),
        SECRET
    );
    for seal in ["auto", "off", "", "REQUIRED", " required"] {
        assert_eq!(
            refused(Environment {
                seal: Some(seal.into()),
                ..environment()
            }),
            SEAL,
            "{seal}"
        );
    }
    assert!(
        Settings::parse(
            &args,
            &Environment {
                seal: Some("required".into()),
                ..environment()
            }
        )
        .is_ok()
    );
    for value in ["false", "1", "", "TRUE"] {
        assert_eq!(
            refused(Environment {
                local_test: Some(value.into()),
                ..environment()
            }),
            LOCAL_TEST
        );
    }
    assert_eq!(
        refused(Environment {
            foreign: true,
            ..environment()
        }),
        FOREIGN_SETTING
    );
}

#[test]
fn the_local_fixture_alone_allows_loopback_binds_and_ws_relays() {
    let fixture = Environment {
        local_test: Some("true".into()),
        ..environment()
    };
    let mut list = with("--bind", "127.0.0.1");
    list.retain(|(name, _)| *name != "--control-relay");
    list.push(("--control-relay", "ws://127.0.0.1:7777/".into()));
    let settings = Settings::parse(&flatten(&list), &fixture).unwrap();
    assert!(settings.relay_config().allow_loopback_peers);
    assert_eq!(parse(&list).unwrap_err(), CONTROL_RELAYS);
    list.retain(|(name, _)| *name != "--control-relay");
    list.push(("--control-relay", "wss://relay.example/".into()));
    assert_eq!(parse(&list).unwrap_err(), BIND);
    // The fixture still refuses an unspecified or multicast advertised address.
    for bad in ["0.0.0.0", "224.0.0.1"] {
        let mut list = with("--public-ip", bad);
        list.retain(|(name, _)| *name != "--bind");
        list.push(("--bind", "127.0.0.1".into()));
        assert_eq!(
            Settings::parse(&flatten(&list), &fixture).unwrap_err(),
            PUBLIC_IP
        );
    }
}

/// A scratch state directory removed when the test ends.
struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Self {
        let mut random = [0_u8; 16];
        getrandom::fill(&mut random).unwrap();
        let path =
            std::env::temp_dir().join(format!("spry-supervised-{}", spry_access::hex(&random)));
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

const NOW: u64 = 1_800_000_000;
const ENDPOINT: &str = "spry://4d4b6cd1361032ca9bd2aeb9d900aa4d45d9ead80ac9423374c451a7254d0766?relay=wss%3A%2F%2Frelay.example%2F";

fn handler(scratch: &Scratch) -> (Handler, Settings, String) {
    let state_file = scratch.0.join("state.json");
    let settings = parse(&with("--state-file", state_file.to_str().unwrap())).unwrap();
    let (mut authority, pairing) = authority(&settings, ENDPOINT, NOW).unwrap();
    authority.config.ready = true;
    let identity = Arc::new(Identity::derive(&settings.secret).unwrap());
    (
        Handler::new(Arc::new(ServiceState::new(authority)), identity),
        settings,
        pairing,
    )
}
fn ask(handler: &Handler, signer: &str, path: &str, body: Value) -> (u16, Value) {
    handler.handle(
        &AcceptedRequest {
            id: "0".repeat(64),
            key: signer.to_owned(),
            path: path.into(),
            body,
            expires_at: NOW + 30,
        },
        NOW,
    )
}
fn card(answer: &Value) -> StandardCard {
    StandardCard::verify(serde_json::from_value(answer["node"].clone()).unwrap(), NOW).unwrap()
}

#[test]
fn only_room_grant_paths_answer_and_grants_are_sealed_from_the_start() {
    let scratch = Scratch::new();
    let (handler, settings, pairing) = handler(&scratch);
    let host = key(2);
    let (status, granted) = ask(
        &handler,
        &host,
        "/v1/grants",
        json!({"pairing":pairing,"scope":spry_access::hash("synthetic-room")}),
    );
    assert_eq!(status, 200, "{granted}");
    assert_eq!(granted["endpoint"], ENDPOINT);
    let node = card(&granted);
    assert_eq!(
        node.event.pubkey,
        Identity::derive(TEST_SECRET).unwrap().public_key()
    );
    assert!(!granted.to_string().contains("spry.invalid"));
    let token = granted["token"].as_str().unwrap().to_owned();

    // Sealed before any registration: nobody redeems, the host included,
    // and a refusal carries no card.
    for signer in [key(3), host.clone()] {
        let (status, refused) = ask(&handler, &signer, "/v1/credentials", json!({"grant":token}));
        assert_eq!(
            (status, refused.clone()),
            (403, json!({"error":"Call access has expired."}))
        );
    }
    // Only the trusted pairing key may create or register.
    let (status, _) = ask(
        &handler,
        &key(4),
        "/v1/grants",
        json!({"pairing":pairing,"scope":spry_access::hash("another-room")}),
    );
    assert_eq!(status, 403);
    let devices = json!({"v":1,"pairing":pairing,"grant":token,"add":[host, key(3)],"revision":1});
    let (status, _) = ask(&handler, &key(4), "/v1/grants/devices", devices.clone());
    assert_eq!(status, 403);
    let (status, registered) = ask(&handler, &host, "/v1/grants/devices", devices);
    assert_eq!(
        (status, registered),
        (
            200,
            json!({"v":1,"sealed":false,"enforced":true,"devices":2})
        )
    );
    let (status, issued) = ask(&handler, &key(3), "/v1/credentials", json!({"grant":token}));
    assert_eq!(status, 200, "{issued}");
    assert_eq!(issued["urls"], json!(settings.urls()));
    assert_eq!(card(&issued).event.id, node.event.id, "cards are stable");
    assert!(!issued.to_string().contains("spry.invalid"));
    // An unregistered key stays out; a confirmed member may vouch for it.
    let (status, _) = ask(&handler, &key(5), "/v1/credentials", json!({"grant":token}));
    assert_eq!(status, 403);
    let (status, vouched) = ask(
        &handler,
        &key(3),
        "/v1/grants/vouch",
        json!({"v":1,"grant":token,"add":[key(5)]}),
    );
    assert_eq!((status, vouched), (200, json!({"v":1,"added":1})));
    let (status, issued) = ask(&handler, &key(5), "/v1/credentials", json!({"grant":token}));
    assert_eq!(status, 200, "{issued}");
    assert!(issued.get("node").is_some());

    // Every other path is refused before the authority sees it, so the
    // pairing survives even a correctly signed self-removal.
    for path in [
        "/v1/pairings/claim",
        "/v1/pairings/remove-self",
        "/v1/pairings",
        "/v1/pairings/list",
        "/v1/pairings/remove",
        "/v1/grants/remove",
        "/v1/peers",
        "/v1/public/credentials",
        "/v1/status",
    ] {
        let (status, refused) = ask(
            &handler,
            &host,
            path,
            json!({"id":pairing,"pairing":pairing,"grant":token,"code":"x","v":1}),
        );
        assert_eq!(
            (status, refused),
            (404, json!({"error":"Not found."})),
            "{path}"
        );
    }
    let (status, _) = ask(&handler, &key(3), "/v1/credentials", json!({"grant":token}));
    assert_eq!(status, 200);
}

#[test]
fn credentials_wait_for_the_relay_and_state_restarts_with_the_same_pairing() {
    let scratch = Scratch::new();
    let state_file = scratch.0.join("state.json");
    let settings = parse(&with("--state-file", state_file.to_str().unwrap())).unwrap();
    let (authority_before, pairing) = authority(&settings, ENDPOINT, NOW).unwrap();
    assert!(!authority_before.config.ready);
    assert_eq!(authority_before.config.seal, Seal::Required);
    assert_eq!(authority_before.advertised_endpoint(), ENDPOINT);
    let identity = Arc::new(Identity::derive(&settings.secret).unwrap());
    let handler = Handler::new(Arc::new(ServiceState::new(authority_before)), identity);
    let (status, granted) = ask(
        &handler,
        &key(2),
        "/v1/grants",
        json!({"pairing":pairing,"scope":spry_access::hash("synthetic-room")}),
    );
    assert_eq!(status, 200);
    let token = granted["token"].as_str().unwrap().to_owned();
    let devices = json!({"v":1,"pairing":pairing,"grant":token,"add":[key(3)],"revision":1});
    assert_eq!(ask(&handler, &key(2), "/v1/grants/devices", devices).0, 200);
    let (status, waiting) = ask(&handler, &key(3), "/v1/credentials", json!({"grant":token}));
    assert_eq!(status, 503, "{waiting}");
    assert!(waiting.get("node").is_none());
    drop(handler);

    // A restart with new relays keeps the pairing and grant, and advertises
    // the new endpoint even though the old one was saved.
    let next = "spry://4d4b6cd1361032ca9bd2aeb9d900aa4d45d9ead80ac9423374c451a7254d0766?relay=wss%3A%2F%2Fother.example%2F";
    let (mut restarted, again) = authority(&settings, next, NOW + 60).unwrap();
    assert_eq!(again, pairing);
    assert_eq!(restarted.advertised_endpoint(), next);
    restarted.config.ready = true;
    let issued = restarted
        .handle(
            "/v1/credentials",
            &key(3),
            &json!({"grant":token}),
            NOW + 61,
        )
        .unwrap();
    assert_eq!(issued["urls"], json!(settings.urls()));
}
