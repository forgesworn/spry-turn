#![no_main]
#![forbid(unsafe_code)]

use libfuzzer_sys::fuzz_target;
use spry_link::{
    advert,
    control::{ControlEndpoint, RelayPolicy},
    identity::{Event, Identity},
    nip44,
    peer::{CARD_KIND, PeerCard},
    standard::StandardCard,
};

const NOW: u64 = 1_800_000_000;

// Events, pairing links and encrypted payloads arrive from Nostr relays and
// from people. Raw mutation explores the envelope; the signed round trip
// keeps the advert, card and tag rules reachable behind signature checks.
fuzz_target!(|data: &[u8]| {
    if let Ok(event) = Event::parse(data) {
        consider(event);
    }

    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let _ = ControlEndpoint::parse(text, RelayPolicy::Public);
    let _ = ControlEndpoint::parse(text, RelayPolicy::LocalFixture);
    let _ = nip44::decrypt(text, &[0x23; 32]);
    let _ = advert::region_valid(text);
    let _ = advert::note_valid(text);
    let _ = advert::privacy_valid(text);

    // A sealed payload must open to the same text under the same key.
    if let Ok(sealed) = nip44::encrypt_with_nonce(text, &[0x23; 32], &[0x31; 32]) {
        assert_eq!(nip44::decrypt(&sealed, &[0x23; 32]).as_deref(), Ok(text));
    }

    // The first line chooses the kind and the tags, tab separated, each tag
    // as `name value`; the remainder is the content. The target signs it, so
    // mutation reaches the rules that follow a valid signature.
    let (head, content) = text.split_once('\n').unwrap_or(("", text));
    let mut fields = head.split('\t');
    let kind = match fields.next() {
        Some("advert") => advert::KIND,
        Some("card") => CARD_KIND,
        _ => 1,
    };
    let tags = fields
        .take(8)
        .map(|field| match field.split_once(' ') {
            Some((name, value)) => vec![name.to_owned(), value.to_owned()],
            None => vec![field.to_owned()],
        })
        .collect();
    let identity = Identity::from_secret(&[0x42; 32]).expect("generated fuzz key");
    if let Ok(event) = identity.sign_with_aux(kind, tags, content.to_owned(), NOW, &[0x17; 32]) {
        consider(event);
    }
});

fn consider(event: Event) {
    let _ = event.tag("d");
    let _ = event.tag("expiration");
    let _ = event.addressed_to(&event.pubkey, event.kind, NOW);
    let _ = advert::verify(&event, NOW);
    let mut book = advert::AdvertBook::new(4);
    if book.accept(&event, NOW).is_ok() {
        assert!(book.watermark(&event.pubkey).is_some());
        assert!(book.open(NOW).count() <= 4);
    }
    let _ = PeerCard::verify(event.clone(), NOW);
    let _ = StandardCard::verify(event, NOW);
}
