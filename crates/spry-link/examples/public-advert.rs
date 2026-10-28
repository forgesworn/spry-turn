//! Writes docs/fixtures/public-advert-v1.json: synthetic public-mode adverts
//! from a fixed test key, never a real one. Signing uses fixed auxiliary
//! bytes, so regenerating gives the same file.
//!
//! Each case is a list of events given in order to a fresh `AdvertBook` at
//! `now`, with the expected verdict for each: `open`, `withdrawn`, or the
//! name of the refusal. `privacy` gives, for each event, the operator
//! privacy link a verifier must expose, or null.
use serde_json::{Value, json};
use spry_link::{
    advert::{self, AdvertBook, KIND, Offer},
    identity::{Event, Identity},
};

const NOW: u64 = 1_793_000_000;
const AUX: [u8; 32] = [0; 32];
const PRIVACY: &str = "https://operator.example/privacy";

fn offer() -> Offer {
    Offer {
        credentials: "https://relay.example/v1/public/credentials".into(),
        urls: vec![
            "turn:relay.example:3478?transport=udp".into(),
            "turn:relay.example:3478?transport=tcp".into(),
            "turns:relay.example:5349?transport=tcp".into(),
        ],
        note: Some("Synthetic operator note".into()),
    }
}
fn sign(node: &Identity, tags: Vec<Vec<String>>, content: String, at: u64) -> Event {
    node.sign_with_aux(KIND, tags, content, at, &AUX).unwrap()
}
fn open_at(node: &Identity, at: u64) -> Event {
    let (tags, content) = advert::open_parts(&offer(), Some("GB"), None, at).unwrap();
    sign(node, tags, content, at)
}
/// Signs an open advert whose content skips the builder's own checks.
fn raw_open(node: &Identity, offer: &Offer, at: u64) -> Event {
    let (tags, _) = advert::open_parts(&self::offer(), None, None, at).unwrap();
    sign(node, tags, serde_json::to_string(offer).unwrap(), at)
}
/// Signs an open advert carrying `links` as privacy tags, unchecked.
fn with_privacy(node: &Identity, links: &[&str], at: u64) -> Event {
    let (mut tags, content) = advert::open_parts(&offer(), Some("GB"), None, at).unwrap();
    for link in links {
        tags.push(vec!["privacy".into(), (*link).into()]);
    }
    sign(node, tags, content, at)
}
fn case(name: &str, events: Vec<Event>) -> Value {
    let mut book = AdvertBook::new(advert::MAX_TRACKED);
    let (expect, privacy): (Vec<String>, Vec<Option<String>>) = events
        .iter()
        .map(|event| match book.accept(event, NOW) {
            Ok(found) => (
                match found.status {
                    advert::Status::Open(_) => "open".into(),
                    advert::Status::Withdrawn => "withdrawn".into(),
                },
                found.privacy,
            ),
            Err(refused) => (format!("{refused:?}"), None),
        })
        .unzip();
    json!({"name":name,"events":events,"expect":expect,"privacy":privacy})
}

fn main() {
    let node = Identity::from_secret(&[5; 32]).unwrap();
    let open = open_at(&node, NOW - 60);
    let (tags, content) = advert::withdrawn_parts(NOW).unwrap();
    let withdrawn = sign(&node, tags, content, NOW);

    let mut forged = open.clone();
    forged
        .sig
        .replace_range(..2, if &forged.sig[..2] == "00" { "11" } else { "00" });
    let (mut tags, content) = advert::open_parts(&offer(), None, None, NOW).unwrap();
    tags.retain(|tag| tag[0] != "expiration");
    let unexpiring = sign(&node, tags, content, NOW);
    let (mut tags, content) = advert::open_parts(&offer(), None, None, NOW).unwrap();
    for tag in &mut tags {
        if tag[0] == "expiration" {
            tag[1] = (NOW + advert::MAX_LIFETIME + 1).to_string();
        }
    }
    let far = sign(&node, tags, content, NOW);
    let (mut tags, content) = advert::open_parts(&offer(), None, None, NOW).unwrap();
    for tag in &mut tags {
        if tag[0] == "expiration" {
            tag[1] = format!("+{}", NOW + 60);
        }
    }
    let signed_expiration = sign(&node, tags, content, NOW);
    let future = open_at(&node, NOW + advert::MAX_FUTURE + 1);
    let mut literal = offer();
    literal.credentials = "https://192.0.2.1/v1/public/credentials".into();
    literal.urls = vec!["turn:192.0.2.1:3478?transport=udp".into()];
    let literal = raw_open(&node, &literal, NOW);
    let mut mismatched = offer();
    mismatched.urls[1] = "turn:other.example:3478?transport=tcp".into();
    let mismatched = raw_open(&node, &mismatched, NOW);
    let mut other_port = offer();
    other_port.urls[1] = "turn:relay.example:22?transport=tcp".into();
    let other_port = raw_open(&node, &other_port, NOW);
    let mut punycode = offer();
    punycode.credentials = "https://xn--rlay-6qa.example/v1/public/credentials".into();
    punycode.urls = vec!["turn:xn--rlay-6qa.example:3478?transport=udp".into()];
    let punycode = raw_open(&node, &punycode, NOW);
    let (tags, content) = advert::open_parts(&offer(), Some("GB"), Some(PRIVACY), NOW).unwrap();
    let private = sign(&node, tags, content, NOW);
    let mut long = with_privacy(&node, &[PRIVACY], NOW);
    for tag in &mut long.tags {
        if tag[0] == "privacy" {
            // Well formed apart from its length, which the shape check refuses
            // before the signature is examined.
            tag[1] = format!("https://operator.example/{}", "p".repeat(232));
        }
    }

    let cases = vec![
        case("valid open advert", vec![open.clone()]),
        case("valid withdrawal", vec![withdrawn.clone()]),
        case("bad signature", vec![forged]),
        case("missing expiration", vec![unexpiring]),
        case("expiration more than two hours ahead", vec![far]),
        case("created_at more than ten minutes ahead", vec![future]),
        case("expiration with a sign", vec![signed_expiration]),
        case("IP-literal credential endpoint", vec![literal]),
        case("TURN host differs from the endpoint", vec![mismatched]),
        case("TURN port outside 3478, 5349 and 443", vec![other_port]),
        case(
            "older open after newer withdrawn",
            vec![withdrawn, open.clone()],
        ),
        case("the same advert twice", vec![open.clone(), open]),
        case("xn-- credential host", vec![punycode]),
        case("valid open advert with a privacy link", vec![private]),
        case("privacy link over 256 bytes", vec![long]),
        case(
            "repeated privacy tag",
            vec![with_privacy(&node, &[PRIVACY, PRIVACY], NOW)],
        ),
    ];
    let mut cases = cases;
    for (name, link) in [
        ("privacy link over http", "http://operator.example/privacy"),
        (
            "privacy link with a port",
            "https://operator.example:8443/privacy",
        ),
        (
            "privacy link with a query",
            "https://operator.example/privacy?x=1",
        ),
        (
            "privacy link with a fragment",
            "https://operator.example/privacy#x",
        ),
        (
            "privacy link with a percent-escape",
            "https://operator.example/privacy%20notice",
        ),
        (
            "privacy link with an uppercase host",
            "https://Operator.example/privacy",
        ),
        ("privacy link on an IP literal", "https://192.0.2.1/privacy"),
        (
            "privacy link with an xn-- label",
            "https://xn--oprator-bva.example/privacy",
        ),
        (
            "privacy link with a dot segment",
            "https://operator.example/a/../privacy",
        ),
    ] {
        cases.push(case(name, vec![with_privacy(&node, &[link], NOW)]));
    }
    let fixture = json!({"schema":1,"synthetic":true,"profile":"spry-public-advert-v1",
        "now":NOW,"nodeKeyRepeatedByte":5,"nodeKey":node.public_key(),"cases":cases});
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../docs/fixtures/public-advert-v1.json"
    );
    std::fs::create_dir_all(std::path::Path::new(path).parent().unwrap()).unwrap();
    std::fs::write(path, serde_json::to_string_pretty(&fixture).unwrap() + "\n").unwrap();
}
