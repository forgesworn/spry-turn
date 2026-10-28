//! Targeted control requests carried in signed, encrypted ephemeral Nostr events.
use crate::{
    Refused, Result,
    identity::{Event, Identity},
    nip44, unhex,
};
use secp256k1::XOnlyPublicKey;
use serde_json::{Value, json};
use std::collections::HashSet;
use url::Url;

pub const REQUEST_KIND: u16 = 24181;
pub const RESPONSE_KIND: u16 = 24182;
pub const MAX_BODY: usize = 8192;
const PATHS: [&str; 7] = [
    "/v1/pairings/claim",
    "/v1/pairings/remove-self",
    "/v1/grants",
    "/v1/grants/devices",
    "/v1/grants/vouch",
    "/v1/credentials",
    "/v1/peers",
];

#[derive(Clone, Copy)]
pub enum RelayPolicy {
    Public,
    LocalFixture,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ControlEndpoint {
    pub public_key: String,
    pub relays: Vec<String>,
}
impl ControlEndpoint {
    pub fn new(public_key: String, relays: Vec<String>, policy: RelayPolicy) -> Result<Self> {
        XOnlyPublicKey::from_byte_array(unhex::<32>(&public_key)?).map_err(|_| Refused::Key)?;
        if !(1..=4).contains(&relays.len()) {
            return Err(Refused::Size);
        }
        let mut canonical = HashSet::new();
        for relay in relays {
            let url = Url::parse(&relay).map_err(|_| Refused::Destination)?;
            let Some(host) = url.host_str() else {
                return Err(Refused::Destination);
            };
            let local = matches!(policy, RelayPolicy::LocalFixture)
                && url.scheme() == "ws"
                && matches!(host, "127.0.0.1" | "localhost" | "[::1]");
            if relay.len() > 256
                || (!local
                    && (url.scheme() != "wss"
                        || !host.contains('.')
                        || host.parse::<std::net::IpAddr>().is_ok()
                        || host.starts_with('[')
                        || host.split('.').next_back().is_some_and(|suffix| {
                            matches!(
                                suffix,
                                "local" | "localhost" | "internal" | "invalid" | "test"
                            )
                        })))
                || !url.username().is_empty()
                || url.password().is_some()
                || url.fragment().is_some()
                || url.query().is_some()
            {
                return Err(Refused::Destination);
            }
            if !canonical.insert(url.to_string()) {
                return Err(Refused::Destination);
            }
        }
        let mut relays: Vec<_> = canonical.into_iter().collect();
        relays.sort();
        Ok(Self { public_key, relays })
    }
    pub fn parse(uri: &str, policy: RelayPolicy) -> Result<Self> {
        if uri.len() > 2048 {
            return Err(Refused::Size);
        }
        let uri = Url::parse(uri).map_err(|_| Refused::Destination)?;
        if uri.scheme() != "spry"
            || !uri.username().is_empty()
            || uri.password().is_some()
            || uri.port().is_some()
            || uri.fragment().is_some()
            || !matches!(uri.path(), "" | "/")
        {
            return Err(Refused::Destination);
        }
        let mut relays = Vec::new();
        for (key, value) in uri.query_pairs() {
            if key != "relay" {
                return Err(Refused::Destination);
            }
            relays.push(value.into_owned());
        }
        Self::new(
            uri.host_str().ok_or(Refused::Destination)?.into(),
            relays,
            policy,
        )
    }
    pub fn uri(&self) -> Result<String> {
        let mut uri =
            Url::parse(&format!("spry://{}", self.public_key)).map_err(|_| Refused::Key)?;
        for relay in &self.relays {
            uri.query_pairs_mut().append_pair("relay", relay);
        }
        let uri = uri.to_string();
        if uri.len() > 2048 {
            return Err(Refused::Size);
        }
        Ok(uri)
    }
}

pub struct AcceptedRequest {
    pub id: String,
    pub key: String,
    pub path: String,
    pub body: Value,
    pub expires_at: u64,
}
fn request_body(path: &str, body: &Value) -> Result<()> {
    if !PATHS.contains(&path) || !body.is_object() {
        return Err(Refused::Destination);
    }
    if serde_json::to_vec(body)
        .map_err(|_| Refused::Encoding)?
        .len()
        > MAX_BODY
    {
        return Err(Refused::Size);
    }
    Ok(())
}
pub fn request(
    identity: &Identity,
    target: &ControlEndpoint,
    path: &str,
    body: &Value,
    now: u64,
) -> Result<Event> {
    request_body(path, body)?;
    let plaintext = json!({"v":1,"path":path,"body":body}).to_string();
    let encrypted = nip44::encrypt(
        &plaintext,
        &nip44::conversation_key(identity, &target.public_key)?,
    )?;
    identity.sign(
        REQUEST_KIND,
        vec![
            vec!["p".into(), target.public_key.clone()],
            vec!["expiration".into(), now.saturating_add(30).to_string()],
        ],
        encrypted,
        now,
    )
}
pub fn open_request(identity: &Identity, event: &Event, now: u64) -> Result<AcceptedRequest> {
    event.addressed_to(&identity.public_key(), REQUEST_KIND, now)?;
    let plaintext = nip44::decrypt(
        &event.content,
        &nip44::conversation_key(identity, &event.pubkey)?,
    )?;
    let value: Value = serde_json::from_str(&plaintext).map_err(|_| Refused::Encoding)?;
    if value["v"] != 1 {
        return Err(Refused::Encoding);
    }
    let path = value["path"].as_str().ok_or(Refused::Destination)?;
    request_body(path, &value["body"])?;
    Ok(AcceptedRequest {
        id: event.id.clone(),
        key: event.pubkey.clone(),
        path: path.into(),
        body: value["body"].clone(),
        expires_at: event
            .tag("expiration")?
            .parse()
            .map_err(|_| Refused::Expired)?,
    })
}
pub fn response(
    identity: &Identity,
    request: &AcceptedRequest,
    status: u16,
    body: &Value,
    now: u64,
) -> Result<Event> {
    if !(200..=599).contains(&status)
        || !body.is_object()
        || serde_json::to_vec(body)
            .map_err(|_| Refused::Encoding)?
            .len()
            > MAX_BODY
    {
        return Err(Refused::Size);
    }
    let plaintext = json!({"v":1,"status":status,"body":body}).to_string();
    let encrypted = nip44::encrypt(
        &plaintext,
        &nip44::conversation_key(identity, &request.key)?,
    )?;
    identity.sign(
        RESPONSE_KIND,
        vec![
            vec!["p".into(), request.key.clone()],
            vec!["e".into(), request.id.clone()],
            vec!["expiration".into(), now.saturating_add(30).to_string()],
        ],
        encrypted,
        now,
    )
}
pub fn open_response(
    identity: &Identity,
    request: &Event,
    target: &ControlEndpoint,
    event: &Event,
    now: u64,
) -> Result<(u16, Value)> {
    event.addressed_to(&identity.public_key(), RESPONSE_KIND, now)?;
    if event.pubkey != target.public_key || event.tag("e")? != request.id {
        return Err(Refused::Authentication);
    }
    let plaintext = nip44::decrypt(
        &event.content,
        &nip44::conversation_key(identity, &event.pubkey)?,
    )?;
    let value: Value = serde_json::from_str(&plaintext).map_err(|_| Refused::Encoding)?;
    let status = value["status"]
        .as_u64()
        .filter(|value| (200..=599).contains(value))
        .ok_or(Refused::Encoding)?;
    if value["v"] != 1
        || !value["body"].is_object()
        || serde_json::to_vec(&value["body"])
            .map_err(|_| Refused::Encoding)?
            .len()
            > MAX_BODY
    {
        return Err(Refused::Size);
    }
    Ok((status as u16, value["body"].clone()))
}
