use serde_json::json;
use spry_link::{
    Refused,
    control::{self, ControlEndpoint, RelayPolicy},
    identity::Identity,
};

#[test]
fn control_uris_are_bounded_canonical_and_have_no_implicit_relays() {
    let identity = Identity::from_secret(&[1; 32]).unwrap();
    let endpoint = ControlEndpoint::new(
        identity.public_key(),
        vec![
            "wss://relay-b.example".into(),
            "wss://relay-a.example".into(),
        ],
        RelayPolicy::Public,
    )
    .unwrap();
    let parsed = ControlEndpoint::parse(&endpoint.uri().unwrap(), RelayPolicy::Public).unwrap();
    assert_eq!(parsed.public_key, identity.public_key());
    assert_eq!(parsed.relays, endpoint.relays);
    for relays in [
        vec![],
        vec!["ws://relay.example".into()],
        vec!["wss://localhost".into()],
        vec!["wss://127.0.0.1".into()],
        vec!["wss://relay.example?a=1".into()],
        vec!["wss://relay.example".into(); 5],
    ] {
        assert!(ControlEndpoint::new(identity.public_key(), relays, RelayPolicy::Public).is_err());
    }
    let fixture = ControlEndpoint::new(
        identity.public_key(),
        vec!["ws://127.0.0.1:12345".into()],
        RelayPolicy::LocalFixture,
    )
    .unwrap();
    assert!(ControlEndpoint::parse(&fixture.uri().unwrap(), RelayPolicy::Public).is_err());
}

#[test]
fn encrypted_requests_and_responses_bind_identity_action_request_and_expiry() {
    let node = Identity::from_secret(&[1; 32]).unwrap();
    let client = Identity::from_secret(&[2; 32]).unwrap();
    let other = Identity::from_secret(&[3; 32]).unwrap();
    let target = ControlEndpoint::new(
        node.public_key(),
        vec!["wss://relay.example".into()],
        RelayPolicy::Public,
    )
    .unwrap();
    let request = control::request(
        &client,
        &target,
        "/v1/credentials",
        &json!({"grant":"generated"}),
        1000,
    )
    .unwrap();
    let accepted = control::open_request(&node, &request, 1001).unwrap();
    assert_eq!(accepted.path, "/v1/credentials");
    assert_eq!(accepted.body, json!({"grant":"generated"}));
    assert_eq!(accepted.key, client.public_key());
    assert!(control::open_request(&other, &request, 1001).is_err());
    assert!(control::open_request(&node, &request, 1030).is_err());
    let response = control::response(&node, &accepted, 200, &json!({"urls":[]}), 1001).unwrap();
    assert_eq!(
        control::open_response(&client, &request, &target, &response, 1002).unwrap(),
        (200, json!({"urls":[]}))
    );
    let different = control::request(
        &client,
        &target,
        "/v1/credentials",
        &json!({"grant":"generated"}),
        1000,
    )
    .unwrap();
    assert!(control::open_response(&client, &different, &target, &response, 1002).is_err());
    assert!(control::open_response(&other, &request, &target, &response, 1002).is_err());
    let forged = control::response(&other, &accepted, 200, &json!({"urls":[]}), 1001).unwrap();
    assert!(control::open_response(&client, &request, &target, &forged, 1002).is_err());
    assert!(control::request(&client, &target, "/v1/pairings", &json!({}), 1000).is_err());
    // Room-grant registration and vouching reach `spry:` nodes too.
    for path in ["/v1/grants/devices", "/v1/grants/vouch"] {
        let request = control::request(&client, &target, path, &json!({"v":1}), 1000).unwrap();
        assert_eq!(
            control::open_request(&node, &request, 1001).unwrap().path,
            path
        );
    }
    for path in ["/v1/grants/remove", "/v1/pairings/list", "/v1/grants/other"] {
        assert!(control::request(&client, &target, path, &json!({}), 1000).is_err());
    }
    assert!(
        control::request(
            &client,
            &target,
            "/v1/credentials",
            &json!({"grant":"x".repeat(8192)}),
            1000
        )
        .is_err()
    );
    assert_eq!(
        control::response(&node, &accepted, 200, &json!(true), 1001).unwrap_err(),
        Refused::Size
    );
}
