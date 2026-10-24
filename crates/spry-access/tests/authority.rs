use base64::{
    Engine,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use secp256k1::{Keypair, SecretKey, schnorr};
use serde_json::{Value, json};
use spry_access::{Authority, Config, GRANT_TTL, hash, hex};

const NOW: u64 = 1_800_000_000;

#[test]
fn another_calling_application_supplies_its_own_origin_and_pairing_target() {
    let config = Config::new(
        "https://relay.example:3744",
        "https://another-app.example/connect/",
        &public(1),
        b"synthetic-test-secret-not-for-deployment",
        None,
    )
    .expect("generic host configuration");
    assert_eq!(
        config.origins,
        std::collections::HashSet::from([
            "https://relay.example:3744".to_owned(),
            "https://relay.example".to_owned(),
            "https://another-app.example".to_owned(),
        ])
    );
    let mut authority = Authority::new(config);
    authority.config.ready = true;
    let link = authority
        .handle("/v1/pairings", &public(1), &json!({}), NOW)
        .expect("owner pairing");
    assert!(
        link["url"]
            .as_str()
            .unwrap()
            .starts_with("https://another-app.example/connect/#spry=")
    );
}
fn key(seed: u8) -> Keypair {
    Keypair::from_secret_key(&SecretKey::from_secret_bytes([seed; 32]).expect("synthetic key"))
}
fn public(seed: u8) -> String {
    hex(&key(seed).x_only_public_key().0.to_byte_array())
}
fn fixture() -> Authority {
    let mut config = Config::new(
        "https://relay.example:3744",
        "https://kithmoot.example/j/",
        &public(1),
        b"synthetic-test-secret-not-for-deployment",
        None,
    )
    .expect("fixture config");
    config.ready = true;
    Authority::new(config)
}
fn pair(authority: &mut Authority) -> (Value, String) {
    let created = authority
        .handle("/v1/pairings", &public(1), &json!({}), NOW)
        .expect("pairing start");
    let payload: Value = serde_json::from_slice(
        &URL_SAFE_NO_PAD
            .decode(
                created["url"]
                    .as_str()
                    .expect("url")
                    .split("#spry=")
                    .nth(1)
                    .expect("fragment"),
            )
            .expect("base64url"),
    )
    .expect("pairing JSON");
    let code = payload["code"].as_str().expect("code").to_owned();
    (
        authority
            .handle("/v1/pairings/claim", &public(2), &json!({"code":code}), NOW)
            .expect("claim"),
        code,
    )
}
fn grant(authority: &mut Authority, id: &Value, now: u64) -> Value {
    authority
        .handle(
            "/v1/grants",
            &public(2),
            &json!({"pairing":id,"scope":hash("synthetic-scope")}),
            now,
        )
        .expect("grant")
}
fn signed(path: &str, body: &[u8], now: u64, nonce: u8) -> String {
    signed_for(path, body, now, nonce, None)
}
fn signed_for(path: &str, body: &[u8], now: u64, nonce: u8, audience: Option<&str>) -> String {
    let mut tags = json!([
        ["u", format!("https://relay.example:3744{path}")],
        ["method", "POST"],
        ["payload", hash(body)],
        ["nonce", URL_SAFE_NO_PAD.encode([nonce; 32])]
    ]);
    if let Some(audience) = audience {
        tags.as_array_mut().unwrap().push(json!(["aud", audience]));
    }
    let id = hash(
        serde_json::to_vec(&json!([0, public(1), now, 27235, tags, ""])).expect("canonical event"),
    );
    let id_bytes: Vec<u8> = id
        .as_bytes()
        .chunks_exact(2)
        .map(|p| u8::from_str_radix(std::str::from_utf8(p).expect("hex"), 16).expect("hex"))
        .collect();
    let sig = hex(&schnorr::sign_with_aux_rand(&id_bytes, &key(1), &[0; 32]).to_byte_array());
    "Nostr ".to_owned() + &STANDARD.encode(serde_json::to_vec(&json!({"kind":27235,"created_at":now,"tags":tags,"content":"","pubkey":public(1),"id":id,"sig":sig})).expect("event"))
}

#[test]
fn pair_once_individual_credentials_renew_and_revoke() {
    let mut a = fixture();
    let (pair, _) = pair(&mut a);
    let access = grant(&mut a, &pair["id"], NOW);
    let one = a
        .handle(
            "/v1/credentials",
            &public(2),
            &json!({"grant":access["token"]}),
            NOW,
        )
        .expect("credentials");
    let two = a
        .handle(
            "/v1/credentials",
            &public(3),
            &json!({"grant":access["token"]}),
            NOW,
        )
        .expect("guest credentials");
    assert_ne!(one["username"], two["username"]);
    assert_eq!(one["expiresAt"], NOW + 300);
    assert!(
        !one["username"]
            .as_str()
            .expect("username")
            .contains(&public(2))
    );
    let access = grant(&mut a, &pair["id"], NOW + 240);
    let renewed = a
        .handle(
            "/v1/credentials",
            &public(2),
            &json!({"grant":access["token"]}),
            NOW + 240,
        )
        .expect("renewed");
    assert_eq!(renewed["expiresAt"], NOW + 540);
    a.handle(
        "/v1/pairings/remove-self",
        &public(2),
        &json!({"id":pair["id"]}),
        NOW + 241,
    )
    .expect("revoke");
    assert!(
        a.handle(
            "/v1/credentials",
            &public(3),
            &json!({"grant":access["token"]}),
            NOW + 241
        )
        .is_err()
    );
    assert!(
        a.handle(
            "/v1/grants",
            &public(2),
            &json!({"pairing":pair["id"],"scope":hash("synthetic-scope")}),
            NOW + 241
        )
        .is_err()
    );
}
#[test]
fn ownership_one_use_and_expiry_are_enforced() {
    let mut a = fixture();
    assert!(
        a.handle("/v1/pairings", &public(3), &json!({}), NOW)
            .is_err()
    );
    let (pair, code) = pair(&mut a);
    assert!(
        a.handle("/v1/pairings/claim", &public(3), &json!({"code":code}), NOW)
            .is_err()
    );
    assert!(
        a.handle(
            "/v1/grants",
            &public(3),
            &json!({"pairing":pair["id"],"scope":hash("scope")}),
            NOW
        )
        .is_err()
    );
    assert!(
        a.handle(
            "/v1/pairings/remove-self",
            &public(3),
            &json!({"id":pair["id"]}),
            NOW
        )
        .is_err()
    );
    assert!(
        a.handle("/v1/pairings/list", &public(3), &json!({}), NOW)
            .is_err()
    );
    let access = grant(&mut a, &pair["id"], NOW);
    assert!(
        a.handle(
            "/v1/credentials",
            &public(3),
            &json!({"grant":access["token"]}),
            NOW + GRANT_TTL + 1
        )
        .is_err()
    );
}
#[test]
fn signatures_bind_body_endpoint_nonce_and_freshness() {
    let mut a = fixture();
    let signed = signed("/v1/pairings", b"{}", NOW, 1);
    assert!(a.authenticate(&signed, "/v1/grants", b"{}", NOW).is_err());
    assert!(
        a.authenticate(&signed, "/v1/pairings", b"{\"different\":true}", NOW)
            .is_err()
    );
    assert_eq!(
        a.authenticate(&signed, "/v1/pairings", b"{}", NOW)
            .expect("approved"),
        public(1)
    );
    assert!(a.authenticate(&signed, "/v1/pairings", b"{}", NOW).is_err());
    assert!(
        a.authenticate(&signed, "/v1/pairings", b"{}", NOW + 61)
            .is_err()
    );
}
#[test]
fn overload_is_bounded_and_expired_capacity_is_reclaimed() {
    let mut a = fixture();
    let (pair, _) = pair(&mut a);
    for i in 0..64 {
        a.handle(
            "/v1/grants",
            &public(2),
            &json!({"pairing":pair["id"],"scope":hash(i.to_string())}),
            NOW,
        )
        .expect("bounded grant");
    }
    assert_eq!(
        a.handle(
            "/v1/grants",
            &public(2),
            &json!({"pairing":pair["id"],"scope":hash("overflow")}),
            NOW
        )
        .expect_err("full")
        .0,
        429
    );
    a.handle(
        "/v1/grants",
        &public(2),
        &json!({"pairing":pair["id"],"scope":hash("overflow")}),
        NOW + GRANT_TTL + 1,
    )
    .expect("expired slots reclaimed");
    for _ in 0..120 {
        a.rate("synthetic-address", NOW).expect("bounded requests");
    }
    assert_eq!(
        a.rate("synthetic-address", NOW).expect_err("rate capped").0,
        429
    );
    a.rate("synthetic-address", NOW + 61)
        .expect("window reclaimed");
}
#[test]
fn readiness_never_claims_a_relay_that_has_not_started() {
    let mut a = fixture();
    a.config.ready = false;
    assert_eq!(
        a.handle("/v1/pairings", &public(1), &json!({}), NOW)
            .expect_err("not ready")
            .0,
        503
    );
}

#[test]
fn group_access_survives_restart_without_the_paired_client_and_is_revoked_durably() {
    struct Scratch(std::path::PathBuf);
    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    let mut random = [0_u8; 16];
    getrandom::fill(&mut random).expect("fixture randomness");
    let scratch = Scratch(std::env::temp_dir().join(format!("spry-authority-{}", hex(&random))));
    std::fs::create_dir(&scratch.0).expect("fixture directory");
    let path = scratch.0.join("pairings.json");
    let mut a = fixture();
    a.config.state_file = Some(path.clone());
    let transport = "spry://generated-fixture-routing-descriptor";
    assert!(
        a.set_transport_endpoint(&public(3), transport.into())
            .is_err()
    );
    a.set_transport_endpoint(&public(1), transport.into())
        .expect("owner configures transport");
    assert_eq!(
        a.authenticate(
            &signed("/v1/pairings", b"{}", NOW, 99),
            "/v1/pairings",
            b"{}",
            NOW
        )
        .expect("HTTP signature retains HTTPS target"),
        public(1)
    );
    let (pair, _) = pair(&mut a);
    assert_eq!(pair["endpoint"], transport);
    let access = grant(&mut a, &pair["id"], NOW);
    let stored = std::fs::read_to_string(&path).expect("saved state");
    assert!(!stored.contains(access["token"].as_str().expect("access token")));
    assert!(!stored.contains("synthetic-test-secret"));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&path)
                .expect("state metadata")
                .permissions()
                .mode()
                & 0o077,
            0
        );
    }
    drop(a);
    let mut restarted = fixture();
    restarted.config.state_file = Some(path.clone());
    restarted.restore().expect("restore");
    assert_eq!(restarted.advertised_endpoint(), transport);
    let credentials = restarted
        .handle(
            "/v1/credentials",
            &public(3),
            &json!({"grant":access["token"]}),
            NOW + 2 * 86400,
        )
        .expect("guest renews without owner online");
    assert_eq!(credentials["expiresAt"], NOW + 2 * 86400 + 300);
    assert_eq!(credentials["accessExpiresAt"], NOW + 2 * 86400 + GRANT_TTL);
    restarted
        .handle(
            "/v1/pairings/remove-self",
            &public(2),
            &json!({"id":pair["id"]}),
            NOW + 2 * 86400 + 1,
        )
        .expect("durable revocation");
    let mut again = fixture();
    again.config.state_file = Some(path);
    again.restore().expect("restore revoked state");
    assert!(
        again
            .handle(
                "/v1/credentials",
                &public(3),
                &json!({"grant":access["token"]}),
                NOW + 2 * 86400 + 2
            )
            .is_err()
    );
}

#[test]
fn device_capacity_expires_without_requiring_a_new_group_grant() {
    let mut a = fixture();
    let (pair, _) = pair(&mut a);
    let access = grant(&mut a, &pair["id"], NOW);
    for seed in 2..34 {
        a.handle(
            "/v1/credentials",
            &public(seed),
            &json!({"grant":access["token"]}),
            NOW,
        )
        .expect("bounded device");
    }
    assert_eq!(
        a.handle(
            "/v1/credentials",
            &public(34),
            &json!({"grant":access["token"]}),
            NOW
        )
        .expect_err("device cap")
        .0,
        429
    );
    a.handle(
        "/v1/credentials",
        &public(34),
        &json!({"grant":access["token"]}),
        NOW + 601,
    )
    .expect("inactive device slots reclaimed");
}

#[test]
fn private_http_proofs_cannot_be_replayed_to_a_node_with_the_same_local_hostname() {
    let mut a = fixture();
    a.config.audience = Some("node-a".into());
    let mut b = fixture();
    b.config.audience = Some("node-b".into());
    let proof = signed_for("/v1/pairings", b"{}", NOW, 77, Some("node-a"));
    a.authenticate(&proof, "/v1/pairings", b"{}", NOW)
        .expect("correct private node");
    assert!(b.authenticate(&proof, "/v1/pairings", b"{}", NOW).is_err());
    assert!(
        a.authenticate(
            &signed("/v1/pairings", b"{}", NOW, 78),
            "/v1/pairings",
            b"{}",
            NOW
        )
        .is_err()
    );
}
