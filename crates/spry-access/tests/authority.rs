use base64::{
    Engine,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use secp256k1::{Keypair, SecretKey, schnorr};
use serde_json::{Value, json};
use spry_access::{
    Authority, Config, GRANT_TTL, MAX_MEMBERS, MAX_NODE_MEMBERS, MAX_STATE, MAX_VOUCHED, Refused,
    Seal, VOUCH_TTL, hash, hex,
};

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

#[test]
fn public_credentials_are_off_by_default_and_unlinkable_when_on() {
    use hmac::{Hmac, Mac};
    let mut authority = fixture();
    assert!(!authority.config.public);
    let body = json!({"v":1});
    assert_eq!(authority.public_rate("192.0.2.10", NOW).unwrap_err().0, 404);
    assert_eq!(authority.public_credentials(&body, NOW).unwrap_err().0, 404);
    authority.config.public = true;
    for wrong in [
        json!({}),
        json!({"v":2}),
        json!({"v":1,"grant":"x"}),
        json!([1]),
    ] {
        assert_eq!(
            authority.public_credentials(&wrong, NOW).unwrap_err().0,
            400
        );
    }
    let first = authority.public_credentials(&body, NOW).unwrap();
    let second = authority.public_credentials(&body, NOW).unwrap();
    assert_eq!(
        first.as_object().unwrap().keys().collect::<Vec<_>>(),
        ["credential", "expiresAt", "urls", "username"]
    );
    assert_eq!(first["expiresAt"], NOW + 3600);
    assert_eq!(first["urls"], json!(authority.config.urls));
    let mut labels = std::collections::HashSet::new();
    for issued in [&first, &second] {
        let username = issued["username"].as_str().unwrap();
        let label = username
            .strip_prefix(&format!("{}:pub-", NOW + 3600))
            .unwrap();
        assert!(label.len() == 24 && label.bytes().all(|b| b.is_ascii_hexdigit()));
        assert!(labels.insert(label.to_owned()));
        let mut mac =
            Hmac::<sha1::Sha1>::new_from_slice(b"synthetic-test-secret-not-for-deployment")
                .unwrap();
        mac.update(username.as_bytes());
        assert_eq!(
            issued["credential"],
            STANDARD.encode(mac.finalize().into_bytes())
        );
    }
    authority.config.ready = false;
    let refused = authority.public_credentials(&body, NOW).unwrap_err();
    assert_eq!((refused.0, refused.1), (503, authority.config.readiness));
}

#[test]
fn public_limits_are_separate_bounded_and_swept() {
    let mut authority = fixture();
    authority.config.public = true;
    for _ in 0..6 {
        authority.public_rate("192.0.2.10", NOW).unwrap();
    }
    assert_eq!(authority.public_rate("192.0.2.10", NOW).unwrap_err().0, 429);
    // The owner's limiter is untouched by anonymous use.
    authority.rate("192.0.2.10", NOW).unwrap();
    for source in 0..26 {
        authority
            .public_rate(&format!("198.51.100.{source}"), NOW)
            .unwrap();
    }
    assert_eq!(
        authority.public_rate("203.0.113.1", NOW).unwrap_err().0,
        429
    );
    // A fresh minute admits callers again.
    authority.public_rate("192.0.2.10", NOW + 60).unwrap();

    let mut authority = fixture();
    authority.config.public = true;
    for source in 0..256 {
        let address = format!("2001:db8::{source:x}");
        if source < 32 {
            authority.public_rate(&address, NOW).unwrap();
        } else {
            // The global limit holds whatever the spread of sources.
            assert_eq!(authority.public_rate(&address, NOW).unwrap_err().0, 429);
        }
    }
    authority.public_rate("2001:db8::1", NOW + 61).unwrap();
}

#[test]
fn owners_and_paired_apps_keep_their_place_however_many_strangers_arrive() {
    let mut a = fixture();
    pair(&mut a);
    // Unauthenticated sources and strangers' keys fill their own tables.
    for source in 0..256 {
        a.rate(&format!("198.51.100.{source}"), NOW).unwrap();
    }
    assert_eq!(a.rate("203.0.113.1", NOW).unwrap_err().0, 429);
    for stranger in 0..256 {
        a.key_rate(&hash(format!("stranger-{stranger}")), NOW)
            .unwrap();
    }
    assert_eq!(
        a.key_rate(&hash("one-more-stranger"), NOW).unwrap_err().0,
        429
    );
    // The owner and the paired app still have room, with the usual cap.
    a.key_rate(&public(2), NOW).unwrap();
    for _ in 0..120 {
        a.key_rate(&public(1), NOW).unwrap();
    }
    let capped = a.key_rate(&public(1), NOW).unwrap_err();
    assert_eq!(
        (capped.0, capped.1),
        (429, "Too many requests. Try again shortly.")
    );
    a.key_rate(&public(1), NOW + 61).unwrap();
}

// Room-grant sealing.

const EXPIRED: &str = "Call access has expired.";

/// A distinct synthetic signing key for any `n`, beyond the 255 of `public`.
fn wide(n: u32) -> String {
    let mut secret = [0_u8; 32];
    secret[0] = 1;
    secret[28..].copy_from_slice(&n.to_be_bytes());
    hex(
        &Keypair::from_secret_key(&SecretKey::from_secret_bytes(secret).expect("synthetic key"))
            .x_only_public_key()
            .0
            .to_byte_array(),
    )
}
fn wides(range: std::ops::Range<u32>) -> Vec<String> {
    range.map(wide).collect()
}
/// Claims a fresh pairing for `claimant` and returns its id.
fn pair_with(authority: &mut Authority, claimant: &str, now: u64) -> String {
    let created = authority
        .handle("/v1/pairings", &public(1), &json!({}), now)
        .expect("pairing start");
    let payload: Value = serde_json::from_slice(
        &URL_SAFE_NO_PAD
            .decode(
                created["url"]
                    .as_str()
                    .unwrap()
                    .split("#spry=")
                    .nth(1)
                    .unwrap(),
            )
            .unwrap(),
    )
    .unwrap();
    authority
        .handle(
            "/v1/pairings/claim",
            claimant,
            &json!({"code":payload["code"]}),
            now,
        )
        .expect("claim")["id"]
        .as_str()
        .unwrap()
        .to_owned()
}
fn grant_for(
    authority: &mut Authority,
    pairing: &str,
    signer: &str,
    scope: &str,
    now: u64,
) -> String {
    authority
        .handle(
            "/v1/grants",
            signer,
            &json!({"pairing":pairing,"scope":hash(scope)}),
            now,
        )
        .expect("grant")["token"]
        .as_str()
        .unwrap()
        .to_owned()
}
/// One paired app (`public(2)`) holding one grant.
fn room() -> (Authority, String, String) {
    let mut a = fixture();
    let pairing = pair_with(&mut a, &public(2), NOW);
    let token = grant_for(&mut a, &pairing, &public(2), "synthetic-scope", NOW);
    (a, pairing, token)
}
#[allow(clippy::too_many_arguments)]
fn register_as(
    a: &mut Authority,
    signer: &str,
    pairing: &str,
    token: &str,
    add: &[String],
    remove: &[String],
    seal: bool,
    revision: u64,
    now: u64,
) -> spry_access::Result<Value> {
    a.handle(
        "/v1/grants/devices",
        signer,
        &json!({"v":1,"pairing":pairing,"grant":token,"add":add,"remove":remove,"seal":seal,"revision":revision}),
        now,
    )
}
fn register(
    a: &mut Authority,
    pairing: &str,
    token: &str,
    add: &[String],
    seal: bool,
    revision: u64,
    now: u64,
) -> Value {
    register_as(a, &public(2), pairing, token, add, &[], seal, revision, now).expect("register")
}
fn redeem(a: &mut Authority, signer: &str, token: &str, now: u64) -> spry_access::Result<Value> {
    a.handle("/v1/credentials", signer, &json!({"grant":token}), now)
}
fn vouch(
    a: &mut Authority,
    signer: &str,
    token: &str,
    add: &[String],
    now: u64,
) -> spry_access::Result<Value> {
    a.handle(
        "/v1/grants/vouch",
        signer,
        &json!({"v":1,"grant":token,"add":add}),
        now,
    )
}
fn refusal(result: spry_access::Result<Value>) -> (u16, &'static str) {
    let Refused(status, message) = result.expect_err("refused");
    (status, message)
}
struct Scratch(std::path::PathBuf);
impl Scratch {
    fn new() -> Self {
        let mut random = [0_u8; 16];
        getrandom::fill(&mut random).expect("fixture randomness");
        let path = std::env::temp_dir().join(format!("spry-seal-{}", hex(&random)));
        std::fs::create_dir(&path).expect("fixture directory");
        Self(path)
    }
    fn file(&self) -> std::path::PathBuf {
        self.0.join("pairings.json")
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
fn saved(path: &std::path::Path) -> Value {
    serde_json::from_slice(&std::fs::read(path).expect("state")).expect("state JSON")
}
fn restarted(path: &std::path::Path) -> Authority {
    let mut a = fixture();
    a.config.state_file = Some(path.to_owned());
    a.restore().expect("restore");
    a
}

#[test]
fn auto_mode_seals_when_the_registrar_asks_and_then_refuses_unlisted_keys() {
    let (mut a, pairing, token) = room();
    assert_eq!(a.config.seal, Seal::Auto);
    redeem(&mut a, &public(4), &token, NOW).expect("unsealed grants admit any signer");
    let listed = [public(2), public(3)];
    let response = register(&mut a, &pairing, &token, &listed, false, 1, NOW);
    assert_eq!(
        response,
        json!({"v":1,"sealed":false,"enforced":false,"devices":2})
    );
    redeem(&mut a, &public(5), &token, NOW).expect("still unsealed");
    let response = register(&mut a, &pairing, &token, &[], true, 2, NOW);
    assert_eq!(
        response,
        json!({"v":1,"sealed":true,"enforced":true,"devices":2})
    );
    redeem(&mut a, &public(2), &token, NOW).expect("registrar");
    redeem(&mut a, &public(3), &token, NOW).expect("listed guest");
    // The refusal a token holder sees is the expired-grant refusal.
    assert_eq!(
        refusal(redeem(&mut a, &public(6), &token, NOW)),
        (403, EXPIRED)
    );
    assert_eq!(
        refusal(redeem(&mut a, &public(6), &"A".repeat(43), NOW)),
        (403, EXPIRED)
    );
    // `seal: false` never unseals.
    let response = register(&mut a, &pairing, &token, &[], false, 3, NOW);
    assert_eq!(response["sealed"], true);
    assert_eq!(
        refusal(redeem(&mut a, &public(6), &token, NOW + 1)),
        (403, EXPIRED)
    );
}

#[test]
fn required_mode_enforces_every_grant_and_off_mode_never_does() {
    let (mut a, pairing, token) = room();
    a.config.seal = Seal::Required;
    // Including a grant created before the switch.
    assert_eq!(
        refusal(redeem(&mut a, &public(2), &token, NOW)),
        (403, EXPIRED)
    );
    let fresh = grant_for(&mut a, &pairing, &public(2), "second-scope", NOW);
    assert_eq!(
        refusal(redeem(&mut a, &public(2), &fresh, NOW)),
        (403, EXPIRED)
    );
    let response = register(&mut a, &pairing, &fresh, &[public(2)], false, 1, NOW);
    assert_eq!(
        response,
        json!({"v":1,"sealed":false,"enforced":true,"devices":1})
    );
    redeem(&mut a, &public(2), &fresh, NOW).expect("registered first, then redeemed");
    assert_eq!(
        refusal(redeem(&mut a, &public(3), &fresh, NOW)),
        (403, EXPIRED)
    );

    let (mut a, pairing, token) = room();
    a.config.seal = Seal::Off;
    let response = register(&mut a, &pairing, &token, &[public(3)], true, 1, NOW);
    assert_eq!(
        response,
        json!({"v":1,"sealed":true,"enforced":false,"devices":1})
    );
    vouch(&mut a, &public(3), &token, &[public(7)], NOW).expect("vouching is accepted");
    redeem(&mut a, &public(9), &token, NOW).expect("stored, never enforced");
    // Switching back to auto enforces the stored seal.
    a.config.seal = Seal::Auto;
    assert_eq!(
        refusal(redeem(&mut a, &public(9), &token, NOW)),
        (403, EXPIRED)
    );
    redeem(&mut a, &public(7), &token, NOW).expect("vouched key");
}

#[test]
fn only_the_owning_pairing_registers_and_strangers_learn_nothing_about_tokens() {
    let (mut a, pairing, token) = room();
    let other = pair_with(&mut a, &public(5), NOW);
    let theirs = grant_for(&mut a, &other, &public(5), "their-scope", NOW);
    let add = [public(3)];
    // Another pairing, with its own valid pairing id, cannot touch the grant.
    assert_eq!(
        refusal(register_as(
            &mut a,
            &public(5),
            &other,
            &token,
            &add,
            &[],
            true,
            1,
            NOW
        )),
        (403, "Approval required.")
    );
    // A signer naming a pairing it does not hold gets the same refusal for a
    // live token and for nonsense.
    let nonsense = "A".repeat(43);
    for grant in [token.as_str(), nonsense.as_str(), "short"] {
        assert_eq!(
            refusal(register_as(
                &mut a,
                &public(9),
                &pairing,
                grant,
                &add,
                &[],
                true,
                1,
                NOW
            )),
            (403, "Approval required.")
        );
    }
    // The owning pairing cannot reach into another pairing's grant.
    assert_eq!(
        refusal(register_as(
            &mut a,
            &public(2),
            &pairing,
            &theirs,
            &add,
            &[],
            true,
            1,
            NOW
        )),
        (403, "Approval required.")
    );
    assert_eq!(
        refusal(register_as(
            &mut a,
            &public(2),
            &pairing,
            &"A".repeat(43),
            &add,
            &[],
            true,
            1,
            NOW
        )),
        (403, EXPIRED)
    );
    // Nothing was registered or sealed by the refused attempts.
    redeem(&mut a, &public(9), &token, NOW).expect("still unsealed");
    assert_eq!(
        refusal(register_as(
            &mut a,
            &public(2),
            &pairing,
            &token,
            &add,
            &[],
            true,
            1,
            NOW + GRANT_TTL + 1
        )),
        (403, EXPIRED)
    );
}

#[test]
fn registration_bodies_are_bounded_and_exact() {
    let (mut a, pairing, token) = room();
    let not_a_point = "f".repeat(64);
    let upper = public(3).to_ascii_uppercase();
    let many = wides(0..33);
    let base = json!({"v":1,"pairing":pairing,"grant":token,"revision":1});
    let with = |field: &str, value: Value| {
        let mut body = base.clone();
        body[field] = value;
        body
    };
    let mut unknown = base.clone();
    unknown["extra"] = json!(true);
    let mut unversioned = base.clone();
    unversioned.as_object_mut().unwrap().remove("v");
    let mut unrevised = base.clone();
    unrevised.as_object_mut().unwrap().remove("revision");
    for body in [
        unknown,
        unversioned,
        unrevised,
        with("v", json!(2)),
        with("add", json!(many)),
        with("remove", json!(many)),
        with("add", json!([public(3), public(3)])),
        with("add", json!([upper])),
        with("add", json!([not_a_point])),
        with("add", json!([public(3).get(..63).unwrap()])),
        with("add", json!("not a list")),
        with("add", json!([3])),
        with("seal", json!("yes")),
        with("seal", json!(1)),
        with("revision", json!(-1)),
        with("revision", json!(1.5)),
        with("revision", json!("1")),
        with("revision", json!(9_007_199_254_740_992_u64)),
        json!({"v":1,"pairing":pairing,"grant":token,"revision":1,"add":[public(3)],"remove":[public(3)]}),
    ] {
        assert_eq!(
            refusal(a.handle("/v1/grants/devices", &public(2), &body, NOW)),
            (400, "Invalid request."),
            "{body}"
        );
    }
    let mut vouch_bodies = vec![
        json!({"v":1,"grant":token}),
        json!({"v":1,"grant":token,"add":[]}),
        json!({"v":1,"grant":token,"add":wides(0..5)}),
        json!({"v":1,"grant":token,"add":[public(3)],"pairing":pairing}),
        json!({"grant":token,"add":[public(3)]}),
    ];
    vouch_bodies.push(json!({"v":1,"grant":token,"add":["f".repeat(64)]}));
    for body in vouch_bodies {
        assert_eq!(
            refusal(a.handle("/v1/grants/vouch", &public(2), &body, NOW)),
            (400, "Invalid request."),
            "{body}"
        );
    }
    // Thirty-two keys each way is the limit, not over it.
    register(&mut a, &pairing, &token, &wides(0..32), false, 1, NOW);
    let response = register_as(
        &mut a,
        &public(2),
        &pairing,
        &token,
        &wides(32..64),
        &wides(0..32),
        false,
        2,
        NOW,
    )
    .expect("thirty-two each way");
    assert_eq!(response["devices"], 32);
}

#[test]
fn revisions_must_advance_within_ninety_seconds() {
    let (mut a, pairing, token) = room();
    register(&mut a, &pairing, &token, &[public(3)], false, 10, NOW);
    for stale in [10, 9] {
        assert_eq!(
            refusal(register_as(
                &mut a,
                &public(2),
                &pairing,
                &token,
                &[public(4)],
                &[],
                true,
                stale,
                NOW + 1
            )),
            (409, "Out of date. Try again.")
        );
    }
    // A refused request changed nothing.
    redeem(&mut a, &public(4), &token, NOW + 1).expect("not sealed by a replay");
    register(&mut a, &pairing, &token, &[], false, 11, NOW + 2);
    register(&mut a, &pairing, &token, &[], false, 5, NOW + 2 + 90);
}

#[test]
fn members_vouch_for_newcomers_within_bounds() {
    let (mut a, pairing, token) = room();
    let member = public(3);
    register(
        &mut a,
        &pairing,
        &token,
        &[public(2), member.clone()],
        true,
        1,
        NOW,
    );
    // Strangers, and token holders with no entry, are told the grant expired.
    assert_eq!(
        refusal(vouch(&mut a, &public(9), &token, &[public(10)], NOW)),
        (403, EXPIRED)
    );
    assert_eq!(
        refusal(vouch(&mut a, &member, &"A".repeat(43), &[public(10)], NOW)),
        (403, EXPIRED)
    );
    assert_eq!(
        vouch(&mut a, &member, &token, &[public(10)], NOW).expect("vouch"),
        json!({"v":1,"added":1})
    );
    redeem(&mut a, &public(10), &token, NOW).expect("vouched key redeems");
    // A vouched key cannot vouch.
    assert_eq!(
        refusal(vouch(&mut a, &public(10), &token, &[public(11)], NOW)),
        (403, EXPIRED)
    );
    // Already listed keys are untouched and uncounted; a confirmed key is
    // never downgraded, so it can still vouch.
    assert_eq!(
        vouch(&mut a, &member, &token, &[public(10), public(2)], NOW).expect("no-op"),
        json!({"v":1,"added":0})
    );
    vouch(&mut a, &public(2), &token, &[public(12)], NOW).expect("still confirmed");
    // The registrar adding a vouched key confirms it.
    register(&mut a, &pairing, &token, &[public(12)], false, 2, NOW + 10);
    vouch(&mut a, &public(12), &token, &[public(13)], NOW + 10).expect("confirmed now");
    // Not renewed by use: a vouched key lapses a day after the vouch.
    redeem(&mut a, &public(10), &token, NOW + VOUCH_TTL - 1).expect("within the day");
    assert_eq!(
        refusal(redeem(&mut a, &public(10), &token, NOW + VOUCH_TTL)),
        (403, EXPIRED)
    );
    redeem(&mut a, &public(12), &token, NOW + VOUCH_TTL + 10).expect("confirmed lease");
}

#[test]
fn vouches_are_capped_per_grant_and_per_sponsor() {
    let (mut a, pairing, token) = room();
    let (one, two) = (public(3), public(4));
    register(
        &mut a,
        &pairing,
        &token,
        &[one.clone(), two.clone()],
        true,
        1,
        NOW,
    );
    vouch(&mut a, &one, &token, &wides(0..4), NOW).unwrap();
    vouch(&mut a, &two, &token, &wides(4..8), NOW).unwrap();
    // Eight vouched entries at once per grant, whoever vouched.
    assert_eq!(
        refusal(vouch(&mut a, &one, &token, &wides(8..9), NOW)),
        (429, "Spry is busy. Try again shortly.")
    );
    // Confirming them frees the grant's allowance, not the sponsor's.
    register(&mut a, &pairing, &token, &wides(0..8), false, 2, NOW);
    vouch(&mut a, &one, &token, &wides(8..12), NOW).unwrap();
    assert_eq!(
        refusal(vouch(&mut a, &one, &token, &wides(12..14), NOW)),
        (429, "Spry is busy. Try again shortly.")
    );
    // Nothing partial: a request over the allowance adds nothing.
    assert_eq!(
        refusal(redeem(&mut a, &wide(12), &token, NOW)),
        (403, EXPIRED)
    );
    // Another member keeps its own allowance.
    vouch(&mut a, &two, &token, &wides(12..16), NOW).unwrap();
    redeem(&mut a, &wide(12), &token, NOW).unwrap();
    // A day later both allowances have lapsed with the vouched entries.
    vouch(&mut a, &one, &token, &wides(16..20), NOW + VOUCH_TTL).unwrap();
}

#[test]
fn removal_refuses_the_next_redemption_and_frees_the_device_slot() {
    let (mut a, pairing, token) = room();
    let keys = wides(0..33);
    register(&mut a, &pairing, &token, &keys[..32], true, 1, NOW);
    register(&mut a, &pairing, &token, &keys[32..], false, 2, NOW);
    for key in &keys[..32] {
        redeem(&mut a, key, &token, NOW).expect("within the device limit");
    }
    assert_eq!(
        refusal(redeem(&mut a, &keys[32], &token, NOW)),
        (429, "This call has reached its device limit.")
    );
    // An unlisted key is refused before the limit and takes no slot.
    assert_eq!(
        refusal(redeem(&mut a, &public(9), &token, NOW)),
        (403, EXPIRED)
    );
    register_as(
        &mut a,
        &public(2),
        &pairing,
        &token,
        &[],
        &keys[..1],
        false,
        3,
        NOW + 1,
    )
    .expect("remove");
    assert_eq!(
        refusal(redeem(&mut a, &keys[0], &token, NOW + 1)),
        (403, EXPIRED)
    );
    redeem(&mut a, &keys[32], &token, NOW + 1).expect("the freed slot");
}

#[test]
fn confirmed_leases_renew_at_most_daily_and_lapse_when_idle() {
    let scratch = Scratch::new();
    let (mut a, pairing, token) = room();
    a.config.state_file = Some(scratch.file());
    let (idle, active) = (public(3), public(4));
    register(
        &mut a,
        &pairing,
        &token,
        &[idle.clone(), active.clone()],
        true,
        1,
        NOW,
    );
    let lease = |a: &Authority, key: &str| -> Option<u64> {
        let state = saved(a.config.state_file.as_ref().unwrap());
        state["grants"][0]["members"]
            .as_array()
            .and_then(|members| members.iter().find(|member| member[0] == key))
            .map(|member| member[1].as_u64().unwrap())
    };
    assert_eq!(lease(&a, &active), Some(NOW + GRANT_TTL));
    redeem(&mut a, &active, &token, NOW + 3600).unwrap();
    assert_eq!(
        lease(&a, &active),
        Some(NOW + GRANT_TTL),
        "not renewed within a day"
    );
    redeem(&mut a, &active, &token, NOW + 86_401).unwrap();
    assert_eq!(lease(&a, &active), Some(NOW + 86_401 + GRANT_TTL));
    // The idle entry lapses; the grant, kept alive by use, does not.
    assert_eq!(
        refusal(redeem(&mut a, &idle, &token, NOW + GRANT_TTL)),
        (403, EXPIRED)
    );
    redeem(&mut a, &active, &token, NOW + GRANT_TTL).unwrap();
    register(&mut a, &pairing, &token, &[], false, 2, NOW + GRANT_TTL);
    assert_eq!(
        lease(&a, &idle),
        None,
        "expired entries are swept from state"
    );
    // Removing the grant, then the pairing, drops the members with them.
    a.handle(
        "/v1/grants/remove",
        &public(2),
        &json!({"pairing":pairing,"grant":token}),
        NOW + GRANT_TTL + 1,
    )
    .unwrap();
    assert!(
        saved(&scratch.file())["grants"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    let token = grant_for(
        &mut a,
        &pairing,
        &public(2),
        "synthetic-scope",
        NOW + GRANT_TTL + 2,
    );
    register(
        &mut a,
        &pairing,
        &token,
        std::slice::from_ref(&active),
        true,
        3,
        NOW + GRANT_TTL + 2,
    );
    a.handle(
        "/v1/pairings/remove-self",
        &public(2),
        &json!({"id":pairing}),
        NOW + GRANT_TTL + 3,
    )
    .unwrap();
    assert!(
        saved(&scratch.file())["grants"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        refusal(redeem(&mut a, &active, &token, NOW + GRANT_TTL + 3)),
        (403, EXPIRED)
    );
}

#[test]
fn a_full_grant_evicts_its_least_used_idle_entry_or_refuses() {
    let (mut a, pairing, token) = room();
    let keys = wides(0..MAX_MEMBERS as u32);
    register(&mut a, &pairing, &token, &keys[..32], true, 1, NOW);
    register(&mut a, &pairing, &token, &keys[32..], false, 2, NOW);
    for key in &keys[..10] {
        redeem(&mut a, key, &token, NOW).unwrap();
    }
    // Leases lapse; five are back on the call, five merely used before.
    for key in &keys[5..10] {
        redeem(&mut a, key, &token, NOW + 601).unwrap();
    }
    let newcomer = wide(1000);
    let response = register(
        &mut a,
        &pairing,
        &token,
        std::slice::from_ref(&newcomer),
        false,
        3,
        NOW + 601,
    );
    assert_eq!(response["devices"], MAX_MEMBERS);
    // Never-used entries count as oldest; the smallest key breaks the tie.
    let victim = keys[10..].iter().min().unwrap().clone();
    assert_eq!(
        refusal(redeem(&mut a, &victim, &token, NOW + 602)),
        (403, EXPIRED)
    );
    redeem(&mut a, &newcomer, &token, NOW + 602).unwrap();
    for key in &keys[..10] {
        redeem(&mut a, key, &token, NOW + 602).expect("used entries kept");
    }

    // With every entry live, vouched or named in the request, nothing goes.
    let (mut a, pairing, token) = room();
    let keys = wides(0..56);
    register(&mut a, &pairing, &token, &keys[..32], true, 1, NOW);
    register(&mut a, &pairing, &token, &keys[32..], false, 2, NOW);
    vouch(&mut a, &keys[0], &token, &wides(100..104), NOW).unwrap();
    vouch(&mut a, &keys[1], &token, &wides(104..108), NOW).unwrap();
    for key in &keys[..32] {
        redeem(&mut a, key, &token, NOW).unwrap();
    }
    let mut add = keys[32..].to_vec();
    add.extend(wides(200..208));
    assert_eq!(
        refusal(register_as(
            &mut a,
            &public(2),
            &pairing,
            &token,
            &add,
            &[],
            false,
            3,
            NOW
        )),
        (429, "This call has reached its device limit.")
    );
    // A vouch never evicts.
    register_as(
        &mut a,
        &public(2),
        &pairing,
        &token,
        &[],
        &wides(100..101),
        false,
        4,
        NOW,
    )
    .unwrap();
    let full = register(&mut a, &pairing, &token, &wides(300..301), false, 5, NOW);
    assert_eq!(full["devices"], MAX_MEMBERS);
    assert_eq!(
        refusal(vouch(&mut a, &keys[2], &token, &wides(400..401), NOW)),
        (429, "This call has reached its device limit.")
    );
    assert_eq!(MAX_VOUCHED, 8);
}

#[test]
fn the_node_holds_at_most_1024_registered_keys() {
    let (mut a, pairing, _) = room();
    let per = MAX_MEMBERS as u32;
    let grants = MAX_NODE_MEMBERS as u32 / per;
    for g in 0..grants {
        let token = grant_for(&mut a, &pairing, &public(2), &format!("scope-{g}"), NOW);
        register(
            &mut a,
            &pairing,
            &token,
            &wides(g * per..g * per + 32),
            false,
            1,
            NOW,
        );
        register(
            &mut a,
            &pairing,
            &token,
            &wides(g * per + 32..(g + 1) * per),
            false,
            2,
            NOW,
        );
    }
    let token = grant_for(&mut a, &pairing, &public(2), "one-more", NOW);
    assert_eq!(
        refusal(register_as(
            &mut a,
            &public(2),
            &pairing,
            &token,
            &[wide(90_000)],
            &[],
            false,
            1,
            NOW
        )),
        (429, "Spry is already helping too many calls.")
    );
    // Making room on one grant makes room on the node.
    let first = grant_for(&mut a, &pairing, &public(2), "scope-0", NOW);
    register_as(
        &mut a,
        &public(2),
        &pairing,
        &first,
        &[],
        &wides(0..1),
        false,
        3,
        NOW,
    )
    .unwrap();
    register(&mut a, &pairing, &token, &[wide(90_000)], false, 2, NOW);
    assert_eq!(
        refusal(vouch(&mut a, &wide(90_000), &token, &[wide(90_001)], NOW)),
        (429, "Spry is already helping too many calls.")
    );
}

#[test]
fn members_and_seal_survive_restart_and_old_state_loads_unsealed() {
    let scratch = Scratch::new();
    let (mut a, pairing, token) = room();
    a.config.state_file = Some(scratch.file());
    register(&mut a, &pairing, &token, &[public(3)], true, 1, NOW);
    vouch(&mut a, &public(3), &token, &[public(4)], NOW).unwrap();
    let stored = std::fs::read_to_string(scratch.file()).unwrap();
    assert!(!stored.contains(&token));
    assert_eq!(saved(&scratch.file())["version"], 1);
    let grant = &saved(&scratch.file())["grants"][0];
    assert_eq!(grant["sealed"], true);
    assert_eq!(grant["members"].as_array().unwrap().len(), 2);
    let mut b = restarted(&scratch.file());
    redeem(&mut b, &public(3), &token, NOW + 1).expect("confirmed after restart");
    redeem(&mut b, &public(4), &token, NOW + 1).expect("vouched after restart");
    assert_eq!(
        refusal(redeem(&mut b, &public(5), &token, NOW + 1)),
        (403, EXPIRED)
    );
    // The revision guard is in memory only, so it does not survive.
    register(&mut b, &pairing, &token, &[], false, 1, NOW + 2);

    // A state file written before sealing existed loads every grant unsealed.
    let mut old = saved(&scratch.file());
    for grant in old["grants"].as_array_mut().unwrap() {
        let grant = grant.as_object_mut().unwrap();
        grant.remove("sealed");
        grant.remove("members");
    }
    write_state(&scratch.file(), &old);
    let mut c = restarted(&scratch.file());
    redeem(&mut c, &public(5), &token, NOW + 3).expect("unsealed");
    // An unsealed grant with no members writes neither field.
    register(&mut c, &pairing, &token, &[], false, 1, NOW + 4);
    let grant = saved(&scratch.file())["grants"][0].clone();
    assert!(grant.get("sealed").is_none() && grant.get("members").is_none());
}

fn write_state(path: &std::path::Path, state: &Value) {
    use std::io::Write;
    let _ = std::fs::remove_file(path);
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options
        .open(path)
        .unwrap()
        .write_all(&serde_json::to_vec(state).unwrap())
        .unwrap();
}

#[test]
fn restore_refuses_state_beyond_the_member_bounds() {
    let scratch = Scratch::new();
    let (mut a, pairing, token) = room();
    a.config.state_file = Some(scratch.file());
    register(&mut a, &pairing, &token, &[public(3)], true, 1, NOW);
    let good = saved(&scratch.file());
    let member = |key: String, vouched: bool| json!([key, NOW + 100, vouched]);
    let cases: Vec<Value> = vec![
        json!(
            wides(0..65)
                .into_iter()
                .map(|key| member(key, false))
                .collect::<Vec<_>>()
        ),
        json!(
            wides(0..9)
                .into_iter()
                .map(|key| member(key, true))
                .collect::<Vec<_>>()
        ),
        json!([member(public(3), false), member(public(3), true)]),
        json!([member("f".repeat(64), false)]),
        json!([member(public(3).to_ascii_uppercase(), false)]),
        json!([[public(3), NOW + 100]]),
        json!([[public(3), NOW + 100, false, "extra"]]),
        json!([[public(3), -1, false]]),
    ];
    for members in cases {
        let mut state = good.clone();
        state["grants"][0]["members"] = members;
        write_state(&scratch.file(), &state);
        let mut b = fixture();
        b.config.state_file = Some(scratch.file());
        assert_eq!(
            b.restore().unwrap_err().0,
            503,
            "{}",
            state["grants"][0]["members"]
        );
    }
    let mut state = good.clone();
    state["grants"][0]["sealed"] = json!("yes");
    write_state(&scratch.file(), &state);
    let mut b = fixture();
    b.config.state_file = Some(scratch.file());
    assert!(b.restore().is_err());

    // More than 1024 members across grants, each grant within its own bound.
    let mut state = good.clone();
    let template = state["grants"][0].clone();
    let mut grants = Vec::new();
    for g in 0..17_u32 {
        let mut grant = template.clone();
        grant["scope"] = json!(hash(format!("scope-{g}")));
        grant["members"] = json!(
            wides(g * 64..(g + 1) * 64)
                .into_iter()
                .map(|key| member(key, false))
                .collect::<Vec<_>>()
        );
        grants.push(grant);
    }
    state["grants"] = json!(grants);
    write_state(&scratch.file(), &state);
    let mut b = fixture();
    b.config.state_file = Some(scratch.file());
    assert!(b.restore().is_err());
    state["grants"].as_array_mut().unwrap().pop();
    write_state(&scratch.file(), &state);
    let mut b = fixture();
    b.config.state_file = Some(scratch.file());
    b.restore().expect("1024 members restore");
}

/// The state a node at every bound writes stays within the read limit, and
/// a copy of the v0.3 structures still parses it, so rolling back starts.
#[test]
fn a_full_state_fits_the_read_limit_and_parses_as_v0_3_state() {
    #[derive(serde::Deserialize, serde::Serialize)]
    struct OldSaved {
        version: u8,
        pairs: Vec<OldPairing>,
        #[serde(default)]
        grants: Vec<OldGrant>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        transport_endpoint: Option<String>,
    }
    #[derive(serde::Deserialize, serde::Serialize)]
    struct OldPairing {
        id: String,
        key: String,
        #[serde(rename = "createdAt")]
        created_at: u64,
    }
    #[derive(serde::Deserialize, serde::Serialize)]
    struct OldGrant {
        pair: String,
        scope: String,
        salt: String,
        #[serde(skip)]
        token: String,
        expires: u64,
        #[serde(skip)]
        devices: std::collections::HashMap<String, u64>,
    }

    let scratch = Scratch::new();
    let mut a = fixture();
    a.config.state_file = Some(scratch.file());
    a.set_transport_endpoint(&public(1), format!("spry://{}", "x".repeat(2041)))
        .unwrap();
    let pairings: Vec<(String, String)> = (0..16)
        .map(|p| {
            let key = wide(50_000 + p);
            (pair_with(&mut a, &key, NOW), key)
        })
        .collect();
    let per = (MAX_NODE_MEMBERS / 64) as u32;
    let mut tokens = Vec::new();
    for g in 0..64_u32 {
        let (pairing, key) = &pairings[g as usize % 16];
        let token = grant_for(&mut a, pairing, key, &format!("scope-{g}"), NOW);
        register_as(
            &mut a,
            key,
            pairing,
            &token,
            &wides(g * per..(g + 1) * per),
            &[],
            true,
            1,
            NOW,
        )
        .unwrap();
        tokens.push(token);
    }
    let size = std::fs::metadata(scratch.file()).unwrap().len() as usize;
    assert!(size <= MAX_STATE, "{size} bytes");
    let state = saved(&scratch.file());
    assert_eq!(state["pairs"].as_array().unwrap().len(), 16);
    assert_eq!(state["grants"].as_array().unwrap().len(), 64);
    let mut b = restarted(&scratch.file());
    redeem(&mut b, &wide(0), &tokens[0], NOW + 1).expect("restored member");
    assert_eq!(
        refusal(redeem(&mut b, &wide(99_999), &tokens[0], NOW + 1)),
        (403, EXPIRED)
    );

    // Rolling back: the old binary parses the file, and its next save drops
    // the new fields, which then loads unsealed.
    let bytes = std::fs::read(scratch.file()).unwrap();
    let old: OldSaved = serde_json::from_slice(&bytes).expect("v0.3 parses the new state");
    assert_eq!(old.grants.len(), 64);
    assert!(
        old.grants
            .iter()
            .all(|g| g.token.is_empty() && g.devices.is_empty())
    );
    write_state(&scratch.file(), &serde_json::to_value(&old).unwrap());
    assert!(
        !std::fs::read_to_string(scratch.file())
            .unwrap()
            .contains("members")
    );
    let mut c = restarted(&scratch.file());
    redeem(&mut c, &wide(99_999), &tokens[0], NOW + 2).expect("rolled back state is unsealed");
}
