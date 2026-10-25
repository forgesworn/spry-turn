//! Writes docs/fixtures/public-advert-v1.json: synthetic public-mode adverts
//! from a fixed test key, never a real one. Signing uses fixed auxiliary
//! bytes, so regenerating gives the same file.
//!
//! Each case is a list of events given in order to a fresh `AdvertBook` at
//! `now`, with the expected verdict for each: `open`, `withdrawn`, or the
//! name of the refusal.
use serde_json::{Value, json};
use spry_link::{
    advert::{self, AdvertBook, KIND, Offer},
    identity::{Event, Identity},
};

const NOW: u64 = 1_793_000_000;
const AUX: [u8; 32] = [0; 32];

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
    let (tags, content) = advert::open_parts(&offer(), Some("GB"), at).unwrap();
    sign(node, tags, content, at)
}
/// Signs an open advert whose content skips the builder's own checks.
fn raw_open(node: &Identity, offer: &Offer, at: u64) -> Event {
    let (tags, _) = advert::open_parts(&self::offer(), None, at).unwrap();
    sign(node, tags, serde_json::to_string(offer).unwrap(), at)
}
fn case(name: &str, events: Vec<Event>) -> Value {
    let mut book = AdvertBook::new(advert::MAX_TRACKED);
    let expect: Vec<String> = events
        .iter()
        .map(|event| match book.accept(event, NOW) {
            Ok(found) => match found.status {
                advert::Status::Open(_) => "open".into(),
                advert::Status::Withdrawn => "withdrawn".into(),
            },
            Err(refused) => format!("{refused:?}"),
        })
        .collect();
    json!({"name":name,"events":events,"expect":expect})
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
    let (mut tags, content) = advert::open_parts(&offer(), None, NOW).unwrap();
    tags.retain(|tag| tag[0] != "expiration");
    let unexpiring = sign(&node, tags, content, NOW);
    let (mut tags, content) = advert::open_parts(&offer(), None, NOW).unwrap();
    for tag in &mut tags {
        if tag[0] == "expiration" {
            tag[1] = (NOW + advert::MAX_LIFETIME + 1).to_string();
        }
    }
    let far = sign(&node, tags, content, NOW);
    let future = open_at(&node, NOW + advert::MAX_FUTURE + 1);
    let mut literal = offer();
    literal.credentials = "https://192.0.2.1/v1/public/credentials".into();
    literal.urls = vec!["turn:192.0.2.1:3478?transport=udp".into()];
    let literal = raw_open(&node, &literal, NOW);
    let mut mismatched = offer();
    mismatched.urls[1] = "turn:other.example:3478?transport=tcp".into();
    let mismatched = raw_open(&node, &mismatched, NOW);

    let cases = vec![
        case("valid open advert", vec![open.clone()]),
        case("valid withdrawal", vec![withdrawn.clone()]),
        case("bad signature", vec![forged]),
        case("missing expiration", vec![unexpiring]),
        case("expiration more than two hours ahead", vec![far]),
        case("created_at more than ten minutes ahead", vec![future]),
        case("IP-literal credential endpoint", vec![literal]),
        case("TURN host differs from the endpoint", vec![mismatched]),
        case(
            "older open after newer withdrawn",
            vec![withdrawn, open.clone()],
        ),
        case("the same advert twice", vec![open.clone(), open]),
    ];
    let fixture = json!({"schema":1,"synthetic":true,"profile":"spry-public-advert-v1",
        "now":NOW,"nodeKeyRepeatedByte":5,"nodeKey":node.public_key(),"cases":cases});
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../docs/fixtures/public-advert-v1.json"
    );
    std::fs::create_dir_all(std::path::Path::new(path).parent().unwrap()).unwrap();
    std::fs::write(path, serde_json::to_string_pretty(&fixture).unwrap() + "\n").unwrap();
}
