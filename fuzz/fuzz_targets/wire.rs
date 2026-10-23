#![no_main]
#![forbid(unsafe_code)]

use libfuzzer_sys::fuzz_target;
use spry_turn::{auth, wire};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

fuzz_target!(|data: &[u8]| {
    // Exercise all borrowed accessors only after their public parser accepts.
    if let Some(message) = wire::Message::parse(data) {
        assert!(message.attributes().count() <= 128);
        for (kind, value) in message.attributes() {
            let _ = message.attr(kind);
            let _ = message.number(kind);
            let _ = message.address(kind);
            let _ = wire::decode_address(value, &message.transaction);
        }
        let _ = message.verify(b"generated fuzz key");
        let _ = message.verify(data);
    }
    if let Some((number, payload)) = wire::channel(data) {
        assert!((0x4000..=0x4fff).contains(&number));
        assert!(payload.len() <= data.len().saturating_sub(4));
    }
    if let Some(length) = wire::frame_len(data) {
        assert!(length <= 65_556);
    }
    let transaction = [0x42; 12];
    let _ = wire::decode_address(data, &transaction);
    let nonces = auth::Nonces::from_key([0x23; 32]);
    let ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
    let _ = nonces.valid(data, 1_000, ip, "generated fuzz realm");
    if let Ok(username) = std::str::from_utf8(data) {
        let _ = auth::expires(username);
    }

    // Structured round trips keep auth/address branches reachable while raw
    // mutation above explores malformed envelopes, padding and integrity tags.
    let mut builder = wire::Builder::new(wire::ALLOCATE, 0, transaction);
    let payload = &data[..data.len().min(65_400)];
    builder.attr(wire::DATA, payload);
    let ip = Ipv4Addr::new(
        data.first().copied().unwrap_or(0),
        data.get(1).copied().unwrap_or(0),
        data.get(2).copied().unwrap_or(0),
        data.get(3).copied().unwrap_or(0),
    );
    let address = SocketAddr::new(IpAddr::V4(ip), payload.len() as u16);
    builder.address(wire::PEER, address);
    let bytes = builder.finish(Some(b"generated fuzz key"));
    let parsed = wire::Message::parse(&bytes).expect("bounded builder envelope");
    assert!(parsed.verify(b"generated fuzz key"));
    assert!(!parsed.verify(b"different generated key"));
    assert_eq!(parsed.attr(wire::DATA), Some(payload));
    assert_eq!(parsed.address(wire::PEER), Some(address));
});
