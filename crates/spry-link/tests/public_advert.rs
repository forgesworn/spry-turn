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
        assert_eq!(events.len(), expected.len());
        for (event, expected) in events.iter().zip(&expected) {
            assert_eq!(event.pubkey, fixture["nodeKey"]);
            let verdict = match book.accept(event, now) {
                Ok(found) => match found.status {
                    Status::Open(_) => "open".to_owned(),
                    Status::Withdrawn => "withdrawn".to_owned(),
                },
                Err(refused) => format!("{refused:?}"),
            };
            assert_eq!(&verdict, expected, "{}", case["name"]);
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
    assert_eq!(
        find("older open after newer withdrawn"),
        ["withdrawn", "Replay"]
    );
    let valid: Vec<Event> = serde_json::from_value(cases[0]["events"].clone()).unwrap();
    let text = serde_json::to_string(&valid[0]).unwrap();
    assert!(text.len() <= advert::MAX_ADVERT);
    for secret in ["credential", "username", "secret"] {
        assert!(!valid[0].content.contains(&format!("\"{secret}\"")));
    }
}
