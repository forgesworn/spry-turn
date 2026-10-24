use spry_link::{
    MAX_EVENT, MAX_PLAINTEXT, Refused,
    identity::{Event, Identity},
    nip44, unhex,
};

#[test]
fn official_nip44_v2_vector_matches_both_directions() {
    // NIP-44's published example; public synthetic scalar/nonce values.
    let a = Identity::from_secret(
        &unhex::<32>("0000000000000000000000000000000000000000000000000000000000000001").unwrap(),
    )
    .unwrap();
    let b = Identity::from_secret(
        &unhex::<32>("0000000000000000000000000000000000000000000000000000000000000002").unwrap(),
    )
    .unwrap();
    let expected =
        unhex::<32>("c41c775356fd92eadc63ff5a0dc1da211b268cbea22316767095b2871ea1412d").unwrap();
    assert_eq!(
        nip44::conversation_key(&a, &b.public_key()).unwrap(),
        expected
    );
    assert_eq!(
        nip44::conversation_key(&b, &a.public_key()).unwrap(),
        expected
    );
    let nonce =
        unhex::<32>("0000000000000000000000000000000000000000000000000000000000000001").unwrap();
    let payload = "AgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABee0G5VSK0/9YypIObAtDKfYEAjD35uVkHyB0F4DwrcNaCXlCWZKaArsGrY6M9wnuTMxWfp1RTN9Xga8no+kF5Vsb";
    assert_eq!(
        nip44::encrypt_with_nonce("a", &expected, &nonce).unwrap(),
        payload
    );
    assert_eq!(nip44::decrypt(payload, &expected).unwrap(), "a");
}

#[test]
fn encryption_bounds_utf8_buckets_and_refuses_modified_payloads() {
    let key = [7; 32];
    for length in [1, 31, 32, 33, 255, 256, 257, 4096, MAX_PLAINTEXT] {
        let text = "x".repeat(length);
        let encrypted = nip44::encrypt(&text, &key).unwrap();
        assert_eq!(nip44::decrypt(&encrypted, &key).unwrap(), text);
        assert!(nip44::decrypt(&encrypted, &[8; 32]).is_err());
        let mut broken = encrypted.into_bytes();
        broken[90] = if broken[90] == b'A' { b'B' } else { b'A' };
        assert!(nip44::decrypt(std::str::from_utf8(&broken).unwrap(), &key).is_err());
    }
    let unicode = "A🫏é";
    assert_eq!(
        nip44::decrypt(&nip44::encrypt(unicode, &key).unwrap(), &key).unwrap(),
        unicode
    );
    assert_eq!(nip44::encrypt("", &key), Err(Refused::Size));
    assert_eq!(
        nip44::encrypt(&"x".repeat(MAX_PLAINTEXT + 1), &key),
        Err(Refused::Size)
    );
    assert!(nip44::decrypt(&"A".repeat(100_000), &key).is_err());
    for value in ["", "#unsupported", "x", &"A".repeat(132)] {
        assert!(nip44::decrypt(value, &key).is_err());
    }
}

#[test]
fn signatures_bind_target_expiry_tags_and_ciphertext_before_decryption() {
    let a = Identity::from_secret(&[1; 32]).unwrap();
    let b = Identity::from_secret(&[2; 32]).unwrap();
    let key = nip44::conversation_key(&a, &b.public_key()).unwrap();
    let event = a
        .sign(
            24181,
            vec![
                vec!["p".into(), b.public_key()],
                vec!["expiration".into(), "1030".into()],
            ],
            nip44::encrypt("generated request", &key).unwrap(),
            1000,
        )
        .unwrap();
    let parsed = Event::parse(&serde_json::to_vec(&event).unwrap()).unwrap();
    parsed.addressed_to(&b.public_key(), 24181, 1001).unwrap();
    assert!(parsed.addressed_to(&a.public_key(), 24181, 1001).is_err());
    assert!(parsed.addressed_to(&b.public_key(), 24182, 1001).is_err());
    assert!(parsed.addressed_to(&b.public_key(), 24181, 1030).is_err());
    let mut modified = parsed.clone();
    modified.content.push('A');
    assert!(modified.verify().is_err());
    let duplicate = a
        .sign(
            24181,
            vec![
                vec!["p".into(), b.public_key()],
                vec!["p".into(), b.public_key()],
                vec!["expiration".into(), "1030".into()],
            ],
            "generated".into(),
            1000,
        )
        .unwrap();
    assert!(
        duplicate
            .addressed_to(&b.public_key(), 24181, 1001)
            .is_err()
    );
    assert!(Event::parse(&vec![b' '; MAX_EVENT + 1]).is_err());
    assert!(Identity::from_secret(&[0; 32]).is_err());
    assert!(a.shared_secret(&"f".repeat(64)).is_err());
    assert_eq!(
        Identity::derive(b"synthetic-master-not-for-deployment")
            .unwrap()
            .public_key(),
        Identity::derive(b"synthetic-master-not-for-deployment")
            .unwrap()
            .public_key()
    );
}
