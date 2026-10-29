//! Synthetic wire fixtures shared by the independent clients; never real keys.
use serde_json::json;
use spry_link::{
    control::{self, ControlEndpoint, RelayPolicy},
    identity::Identity,
    peer::PeerCard,
    standard::StandardCard,
};
fn main() {
    let node = Identity::from_secret(&[1; 32]).unwrap();
    let client = Identity::from_secret(&[2; 32]).unwrap();
    let now = 1_700_000_000;
    let target = ControlEndpoint::new(
        node.public_key(),
        vec!["wss://relay.example/".into()],
        RelayPolicy::Public,
    )
    .unwrap();
    let request = control::request(
        &client,
        &target,
        "/v1/grants",
        &json!({"scope":"generated"}),
        now,
    )
    .unwrap();
    let accepted = control::open_request(&node, &request, now).unwrap();
    let response = control::response(&node, &accepted, 200, &json!({"ok":true}), now).unwrap();
    let card = PeerCard::sign(&node, "[fd12:3456::2]:3745".parse().unwrap(), now)
        .unwrap()
        .event;
    // Zero auxiliary randomness makes this card reproducible byte for byte.
    let standard = StandardCard::sign_with_aux(&node, now, &[0; 32])
        .unwrap()
        .event;
    println!("{}", serde_json::to_string_pretty(&json!({"schema":1,"synthetic":true,"now":now,"nodeKeyRepeatedByte":1,"clientKeyRepeatedByte":2,
        "endpoint":target.uri().unwrap(),"request":request,"response":response,"node":card,"standardNode":standard})).unwrap());
}
