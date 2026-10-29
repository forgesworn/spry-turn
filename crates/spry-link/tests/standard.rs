use spry_link::{
    Refused,
    identity::{Event, Identity},
    peer::{CARD_KIND, PeerCard},
    standard::{PROFILE, StandardCard},
};

fn node() -> Identity {
    Identity::from_secret(&[1; 32]).unwrap()
}

#[test]
fn a_standard_card_names_only_its_profile_and_expires_like_a_peer_card() {
    let card = StandardCard::sign(&node(), 1000).unwrap();
    assert_eq!(card.event.kind, CARD_KIND);
    assert_eq!(card.event.pubkey, node().public_key());
    assert_eq!(
        card.event.content,
        r#"{"profile":"spry-standard-v1","v":1}"#
    );
    assert_eq!(card.event.tags, [["expiration", "1600"]]);
    assert_eq!(card.expires_at, 1600);
    assert_eq!(PROFILE, "spry-standard-v1");
    assert!(StandardCard::verify(card.event.clone(), 1599).is_ok());
    assert_eq!(
        StandardCard::verify(card.event.clone(), 1600).unwrap_err(),
        Refused::Expired
    );
    // Not from the future.
    assert!(StandardCard::verify(card.event.clone(), 900).is_err());
    let reproducible = StandardCard::sign_with_aux(&node(), 1000, &[0; 32]).unwrap();
    assert_eq!(
        reproducible.event.id,
        StandardCard::sign_with_aux(&node(), 1000, &[0; 32])
            .unwrap()
            .event
            .id
    );
}

#[test]
fn the_private_mesh_never_accepts_a_standard_card_and_the_reverse() {
    let standard = StandardCard::sign(&node(), 1000).unwrap();
    assert!(PeerCard::verify(standard.event, 1001).is_err());
    let peer = PeerCard::sign(&node(), "[fd12:3456::2]:3745".parse().unwrap(), 1000).unwrap();
    assert!(StandardCard::verify(peer.event, 1001).is_err());
}

fn signed(content: &str, tags: Vec<Vec<String>>, kind: u16) -> Event {
    node()
        .sign_with_aux(kind, tags, content.into(), 1000, &[0; 32])
        .unwrap()
}

#[test]
fn addresses_extra_fields_and_altered_cards_are_refused() {
    let expiry = || vec![vec!["expiration".to_string(), "1600".to_string()]];
    for content in [
        r#"{"v":1,"profile":"spry-standard-v1","address":"203.0.113.7"}"#,
        r#"{"v":1,"profile":"spry-standard-v1","address":"[fd12:3456::2]:3745"}"#,
        r#"{"v":1,"profile":"spry-standard-v1","name":"node.example"}"#,
        r#"{"v":2,"profile":"spry-standard-v1"}"#,
        r#"{"v":1,"profile":"spry-peer-v1"}"#,
        r#"{"v":1}"#,
        r#"["spry-standard-v1"]"#,
        "spry-standard-v1",
    ] {
        assert!(
            StandardCard::verify(signed(content, expiry(), CARD_KIND), 1001).is_err(),
            "{content}"
        );
    }
    let content = r#"{"v":1,"profile":"spry-standard-v1"}"#;
    assert!(StandardCard::verify(signed(content, expiry(), CARD_KIND), 1001).is_ok());
    // Wrong kind, missing, doubled, extra or too-long expiration tags.
    assert!(StandardCard::verify(signed(content, expiry(), 24182), 1001).is_err());
    assert!(StandardCard::verify(signed(content, vec![], CARD_KIND), 1001).is_err());
    let mut doubled = expiry();
    doubled.extend(expiry());
    assert!(StandardCard::verify(signed(content, doubled, CARD_KIND), 1001).is_err());
    let mut extra = expiry();
    extra.push(vec!["p".into(), node().public_key()]);
    assert!(StandardCard::verify(signed(content, extra, CARD_KIND), 1001).is_err());
    let long = vec![vec!["expiration".to_string(), "1601".to_string()]];
    assert_eq!(
        StandardCard::verify(signed(content, long, CARD_KIND), 1001).unwrap_err(),
        Refused::Expired
    );
    // A changed byte breaks the signature.
    let mut altered = signed(content, expiry(), CARD_KIND);
    altered.created_at += 1;
    assert!(StandardCard::verify(altered, 1001).is_err());
    let mut forged = signed(content, expiry(), CARD_KIND);
    forged.pubkey = Identity::from_secret(&[2; 32]).unwrap().public_key();
    assert!(StandardCard::verify(forged, 1001).is_err());
}

#[test]
fn the_shared_vector_is_the_reproducible_card_and_only_a_standard_card() {
    let vectors: serde_json::Value =
        serde_json::from_str(include_str!("../../../tests/vectors/spry-link.json")).unwrap();
    let now = vectors["now"].as_u64().unwrap();
    let event: Event = serde_json::from_value(vectors["standardNode"].clone()).unwrap();
    let expected = StandardCard::sign_with_aux(&node(), now, &[0; 32]).unwrap();
    assert_eq!(
        serde_json::to_value(&event).unwrap(),
        serde_json::to_value(&expected.event).unwrap()
    );
    assert!(StandardCard::verify(event.clone(), now + 1).is_ok());
    assert!(PeerCard::verify(event, now + 1).is_err());
    let peer: Event = serde_json::from_value(vectors["node"].clone()).unwrap();
    assert!(PeerCard::verify(peer.clone(), now + 1).is_ok());
    assert!(StandardCard::verify(peer, now + 1).is_err());
}
