use spry_link::{
    Refused,
    identity::Identity,
    peer::{self, Datagram, PacketSession, PeerCard},
};

#[test]
fn registry_withdraws_scopes_rejects_stale_cards_and_reclaims_expired_capacity() {
    use spry_link::registry::PeerRegistry;
    let own = Identity::from_secret(&[1; 32]).unwrap();
    let remote = Identity::from_secret(&[2; 32]).unwrap();
    let card = PeerCard::sign(&remote, "[fd00::2]:3745".parse().unwrap(), 1000).unwrap();
    let newer = PeerCard::sign(&remote, "[fd00::2]:3745".parse().unwrap(), 1100).unwrap();
    let mut registry = PeerRegistry::new(own.public_key()).unwrap();
    registry
        .update("owner_room_a", std::slice::from_ref(&card.event), 1001)
        .unwrap();
    registry
        .update("owner_room_b", std::slice::from_ref(&newer.event), 1101)
        .unwrap();
    assert_eq!(registry.active(1101).len(), 1);
    assert_eq!(
        registry.update("owner_room_a", &[card.event], 1101),
        Err(Refused::Replay)
    );
    registry.update("owner_room_a", &[], 1101).unwrap();
    assert_eq!(registry.active(1101).len(), 1);
    registry.retain_scopes(|_| false);
    assert!(registry.active(1101).is_empty());
    registry
        .update("owner_room_c", &[newer.event], 1101)
        .unwrap();
    assert!(registry.active(1700).is_empty());
    registry.sweep(1700);
    for seed in 3..=10 {
        let identity = Identity::from_secret(&[seed; 32]).unwrap();
        let card = PeerCard::sign(
            &identity,
            format!("[fd00::{seed}]:3745").parse().unwrap(),
            1800,
        )
        .unwrap();
        registry
            .update(&format!("scope_{seed}"), &[card.event], 1801)
            .unwrap();
    }
    let extra = Identity::from_secret(&[11; 32]).unwrap();
    let card = PeerCard::sign(&extra, "[fd00::11]:3745".parse().unwrap(), 1800).unwrap();
    assert_eq!(
        registry.update("extra", &[card.event], 1801),
        Err(Refused::Overload)
    );
    assert_eq!(registry.active(1801).len(), 8);
    assert!(registry.active(2400).is_empty());
}

#[test]
fn cards_only_authorise_the_fixed_private_mesh_service_and_expire() {
    let identity = Identity::from_secret(&[3; 32]).unwrap();
    let card = PeerCard::sign(&identity, "[fd00::1]:3745".parse().unwrap(), 1000).unwrap();
    assert_eq!(
        card.alias,
        peer::relay_alias(&identity.public_key()).unwrap()
    );
    assert!(PeerCard::verify(card.event.clone(), 1600).is_err());
    for address in [
        "[::1]:3745",
        "[2001:db8::1]:3745",
        "[fd00::1]:22",
        "127.0.0.1:3745",
    ] {
        let event = identity
            .sign(
                peer::CARD_KIND,
                vec![vec!["expiration".into(), "1600".into()]],
                serde_json::json!({"v":1,"profile":"spry-peer-v1","address":address}).to_string(),
                1000,
            )
            .unwrap();
        assert!(PeerCard::verify(event, 1001).is_err(), "{address}");
    }
}

#[test]
fn challenge_proofs_bind_both_nodes_and_connection_nonces() {
    let a = Identity::from_secret(&[1; 32]).unwrap();
    let b = Identity::from_secret(&[2; 32]).unwrap();
    let proof = peer::hello(&a, &b.public_key(), &[3; 32], &[4; 32], 1000).unwrap();
    peer::verify_hello(
        &proof,
        &a.public_key(),
        &b.public_key(),
        &[3; 32],
        &[4; 32],
        1001,
    )
    .unwrap();
    assert!(
        peer::verify_hello(
            &proof,
            &b.public_key(),
            &a.public_key(),
            &[3; 32],
            &[4; 32],
            1001
        )
        .is_err()
    );
    assert!(
        peer::verify_hello(
            &proof,
            &a.public_key(),
            &b.public_key(),
            &[5; 32],
            &[4; 32],
            1001
        )
        .is_err()
    );
    assert!(
        peer::verify_hello(
            &proof,
            &a.public_key(),
            &b.public_key(),
            &[3; 32],
            &[4; 32],
            1030
        )
        .is_err()
    );
}

#[test]
fn encrypted_frames_reject_tampering_replay_wrong_direction_and_invalid_ports() {
    let a = Identity::from_secret(&[1; 32]).unwrap();
    let b = Identity::from_secret(&[2; 32]).unwrap();
    let mut one = PacketSession::new(&a, &b.public_key(), &[3; 32], &[4; 32], true).unwrap();
    let mut two = PacketSession::new(&b, &a.public_key(), &[3; 32], &[4; 32], false).unwrap();
    let packet = Datagram {
        source_port: 49160,
        destination_port: 49161,
        bytes: vec![0, 255, 0, 1, 17],
    };
    let wire = one.seal(Some(&packet)).unwrap();
    assert!(one.open(&wire).is_err());
    let mut broken = wire.clone();
    broken[50] ^= 1;
    assert!(two.open(&broken).is_err());
    assert_eq!(two.open(&wire).unwrap(), Some(packet));
    assert_eq!(two.open(&wire), Err(Refused::Authentication));
    assert_eq!(one.open(&two.seal(None).unwrap()).unwrap(), None);
    let invalid = Datagram {
        source_port: 22,
        destination_port: 49161,
        bytes: vec![1],
    };
    assert!(one.seal(Some(&invalid)).is_err());
    let large = Datagram {
        source_port: 49160,
        destination_port: 49161,
        bytes: vec![1; peer::MAX_DATAGRAM + 1],
    };
    assert!(one.seal(Some(&large)).is_err());
    let maximum = Datagram {
        source_port: 49160,
        destination_port: 49161,
        bytes: vec![1; peer::MAX_DATAGRAM],
    };
    assert_eq!(
        two.open(&one.seal(Some(&maximum)).unwrap()).unwrap(),
        Some(maximum)
    );
    assert!(two.open(&vec![0; peer::MAX_WIRE_PACKET + 1]).is_err());
}

#[test]
fn an_in_flight_update_cannot_restore_withdrawn_peer_routes() {
    use spry_link::registry::PeerRegistry;
    let own = Identity::from_secret(&[1; 32]).unwrap();
    let peer = Identity::from_secret(&[2; 32]).unwrap();
    let card = PeerCard::sign(&peer, "[fd12::2]:3745".parse().unwrap(), 100).unwrap();
    let mut registry = PeerRegistry::new(own.public_key()).unwrap();
    registry
        .update_revision("scope", 1, std::slice::from_ref(&card.event), 100)
        .unwrap();
    registry.update_revision("scope", 3, &[], 101).unwrap();
    assert!(
        registry
            .update_revision("scope", 2, std::slice::from_ref(&card.event), 102)
            .is_err()
    );
    assert!(registry.active(102).is_empty());
    registry
        .update_revision("scope", 4, &[card.event], 103)
        .unwrap();
    assert_eq!(registry.active(103).len(), 1);
}

#[test]
fn optional_host_names_are_signed_bounded_hints_without_changing_the_private_target() {
    let identity = Identity::from_secret(&[1; 32]).unwrap();
    let card = PeerCard::sign_named(
        &identity,
        "[fd12::2]:3745".parse().unwrap(),
        Some("node.private"),
        100,
    )
    .unwrap();
    assert_eq!(card.name.as_deref(), Some("node.private"));
    assert_eq!(card.address, "[fd12::2]:3745".parse().unwrap());
    for name in [
        "https://node.private",
        "node.private:22",
        "node..private",
        "node/private",
        "-node.private",
        "node.private.",
    ] {
        assert!(PeerCard::sign_named(&identity, card.address, Some(name), 100).is_err());
    }
}
