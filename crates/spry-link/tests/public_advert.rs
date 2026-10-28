use serde_json::Value;
use spry_link::{
    advert::{self, AdvertBook, Status},
    identity::Event,
};

/// Clients test against the committed file; this checks the shared verifier
/// gives every recorded verdict, and that the file covers the spec's cases.
#[test]
fn committed_public_advert_fixture_gives_the_expected_verdicts() {
    let fixture: Value =
        serde_json::from_str(include_str!("../../../docs/fixtures/public-advert-v1.json")).unwrap();
    assert_eq!(fixture["schema"], 1);
    assert_eq!(fixture["synthetic"], true);
    let now = fixture["now"].as_u64().unwrap();
    let cases = fixture["cases"].as_array().unwrap();
    let mut verdicts = Vec::new();
    for case in cases {
        let mut book = AdvertBook::new(advert::MAX_TRACKED);
        let events: Vec<Event> = serde_json::from_value(case["events"].clone()).unwrap();
        let expected: Vec<String> = serde_json::from_value(case["expect"].clone()).unwrap();
        let privacy: Vec<Option<String>> = serde_json::from_value(case["privacy"].clone()).unwrap();
        assert_eq!(events.len(), expected.len());
        assert_eq!(events.len(), privacy.len());
        for ((event, expected), privacy) in events.iter().zip(&expected).zip(&privacy) {
            assert_eq!(event.pubkey, fixture["nodeKey"]);
            let (verdict, exposed) = match book.accept(event, now) {
                Ok(found) => (
                    match found.status {
                        Status::Open(_) => "open".to_owned(),
                        Status::Withdrawn => "withdrawn".to_owned(),
                    },
                    found.privacy,
                ),
                Err(refused) => (format!("{refused:?}"), None),
            };
            assert_eq!(&verdict, expected, "{}", case["name"]);
            assert_eq!(&exposed, privacy, "{}", case["name"]);
        }
        verdicts.push((case["name"].as_str().unwrap().to_owned(), expected));
    }
    let find = |name: &str| {
        verdicts
            .iter()
            .find(|(case, _)| case == name)
            .map(|(_, expected)| expected.clone())
            .unwrap_or_else(|| panic!("missing case {name}"))
    };
    assert_eq!(find("valid open advert"), ["open"]);
    assert_eq!(find("valid withdrawal"), ["withdrawn"]);
    assert_eq!(find("bad signature"), ["Authentication"]);
    assert_eq!(find("missing expiration"), ["Expired"]);
    assert_eq!(find("expiration more than two hours ahead"), ["Expired"]);
    assert_eq!(find("created_at more than ten minutes ahead"), ["Expired"]);
    assert_eq!(find("IP-literal credential endpoint"), ["Destination"]);
    assert_eq!(find("TURN host differs from the endpoint"), ["Destination"]);
    assert_eq!(find("expiration with a sign"), ["Expired"]);
    assert_eq!(
        find("TURN port outside 3478, 5349 and 443"),
        ["Destination"]
    );
    assert_eq!(
        find("older open after newer withdrawn"),
        ["withdrawn", "Replay"]
    );
    assert_eq!(find("xn-- credential host"), ["Destination"]);
    assert_eq!(find("valid open advert with a privacy link"), ["open"]);
    assert_eq!(find("privacy link over 256 bytes"), ["Size"]);
    for name in [
        "repeated privacy tag",
        "privacy link over http",
        "privacy link with a port",
        "privacy link with a query",
        "privacy link with a fragment",
        "privacy link with a percent-escape",
        "privacy link with an uppercase host",
        "privacy link on an IP literal",
        "privacy link with an xn-- label",
        "privacy link with a dot segment",
    ] {
        assert_eq!(find(name), ["Destination"], "{name}");
    }
    let linked = cases
        .iter()
        .find(|case| case["name"] == "valid open advert with a privacy link")
        .unwrap();
    assert_eq!(
        linked["privacy"],
        serde_json::json!(["https://operator.example/privacy"])
    );
    let linked: Vec<Event> = serde_json::from_value(linked["events"].clone()).unwrap();
    assert_eq!(linked[0].tags.len(), 7);
    assert!(serde_json::to_string(&linked[0]).unwrap().len() <= advert::MAX_ADVERT);
    let valid: Vec<Event> = serde_json::from_value(cases[0]["events"].clone()).unwrap();
    let text = serde_json::to_string(&valid[0]).unwrap();
    assert!(text.len() <= advert::MAX_ADVERT);
    for secret in ["credential", "username", "secret"] {
        assert!(!valid[0].content.contains(&format!("\"{secret}\"")));
    }
}
