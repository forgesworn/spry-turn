//! Public-mode relay adverts: Nostr kind 31478, signed by the node transport
//! identity. One implementation of the build rules and the client checks, so
//! nodes, clients and fixtures agree. No sockets, DNS or clocks.
use crate::{
    Refused, Result,
    identity::{Event, Identity},
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use url::{Host, Url};

pub const KIND: u16 = 31478;
pub const IDENTIFIER: &str = "spry-turn";
pub const CREDENTIAL_PATH: &str = "/v1/public/credentials";
/// Largest serialised advert a client accepts.
pub const MAX_ADVERT: usize = 4096;
/// Longest permitted gap between `created_at` and `expiration`.
pub const MAX_LIFETIME: u64 = 2 * 60 * 60;
/// Furthest a `created_at` may sit ahead of the reader's clock.
pub const MAX_FUTURE: u64 = 10 * 60;
pub const MAX_NOTE: usize = 140;
pub const MAX_URLS: usize = 4;
const MAX_URL: usize = 256;
/// Hard ceiling on transport keys one [`AdvertBook`] tracks.
pub const MAX_TRACKED: usize = 1024;

/// What an open advert offers. A withdrawn advert carries none of this.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Offer {
    pub credentials: String,
    pub urls: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Status {
    Open(Offer),
    Withdrawn,
}

/// A verified advert. A signature names the key that made the statement;
/// it says nothing about the operator's identity, honesty or jurisdiction.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Advert {
    pub public_key: String,
    pub created_at: u64,
    pub expires_at: u64,
    /// The operator's own claim, never verified.
    pub region: Option<String>,
    pub status: Status,
}

pub fn region_valid(region: &str) -> bool {
    region.len() == 2 && region.bytes().all(|byte| byte.is_ascii_uppercase())
}
pub fn note_valid(note: &str) -> bool {
    note.len() <= MAX_NOTE && !note.chars().any(char::is_control)
}

/// Static checks only. A client must still refuse names that resolve to
/// private, loopback, link-local or reserved addresses when it connects.
fn credential_host(endpoint: &str) -> Result<String> {
    if endpoint.len() > MAX_URL {
        return Err(Refused::Size);
    }
    let url = Url::parse(endpoint).map_err(|_| Refused::Destination)?;
    let Some(Host::Domain(host)) = url.host() else {
        return Err(Refused::Destination);
    };
    let labels: Vec<_> = host.split('.').collect();
    if url.scheme() != "https"
        // Only the canonical spelling: no explicit port, even :443.
        || url.as_str() != endpoint
        || !url.username().is_empty()
        || url.password().is_some()
        || url.port().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || url.path() != CREDENTIAL_PATH
        || labels.len() < 2
        || labels.iter().any(|label| {
            label.is_empty()
                || label.len() > 63
                || !label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
        || labels.last().is_some_and(|suffix| {
            suffix.bytes().all(|byte| byte.is_ascii_digit())
                || matches!(
                    *suffix,
                    "local" | "localhost" | "internal" | "invalid" | "test"
                )
        })
    {
        return Err(Refused::Destination);
    }
    Ok(host.to_owned())
}
fn turn_host(uri: &str) -> Result<&str> {
    if uri.len() > MAX_URL {
        return Err(Refused::Size);
    }
    let (secure, rest) = if let Some(rest) = uri.strip_prefix("turns:") {
        (true, rest)
    } else if let Some(rest) = uri.strip_prefix("turn:") {
        (false, rest)
    } else {
        return Err(Refused::Destination);
    };
    let (address, query) = rest
        .split_once('?')
        .map_or((rest, None), |(a, q)| (a, Some(q)));
    match query {
        None | Some("transport=tcp") => {}
        Some("transport=udp") if !secure => {}
        _ => return Err(Refused::Destination),
    }
    let host = match address.rsplit_once(':') {
        Some((host, port)) => {
            if port.is_empty()
                || port.len() > 5
                || !port.bytes().all(|byte| byte.is_ascii_digit())
                || port.parse::<u16>().map_or(true, |port| port == 0)
            {
                return Err(Refused::Destination);
            }
            host
        }
        None => address,
    };
    Ok(host)
}
impl Offer {
    /// Rule 4 of docs/public-mode.md, plus the note and size bounds.
    pub fn validate(&self) -> Result<()> {
        let host = credential_host(&self.credentials)?;
        if !(1..=MAX_URLS).contains(&self.urls.len()) {
            return Err(Refused::Size);
        }
        for uri in &self.urls {
            if !turn_host(uri)?.eq_ignore_ascii_case(&host) {
                return Err(Refused::Destination);
            }
        }
        if self.note.as_deref().is_some_and(|note| !note_valid(note)) {
            return Err(Refused::Size);
        }
        Ok(())
    }
}

fn tags(status: &str, region: Option<&str>, now: u64) -> Result<Vec<Vec<String>>> {
    let mut tags = vec![
        vec!["d".into(), IDENTIFIER.into()],
        vec!["v".into(), "1".into()],
        vec!["status".into(), status.into()],
        vec!["auth".into(), "public".into()],
        vec![
            "expiration".into(),
            now.saturating_add(MAX_LIFETIME).to_string(),
        ],
    ];
    if let Some(region) = region {
        if !region_valid(region) {
            return Err(Refused::Destination);
        }
        tags.push(vec!["g".into(), region.into()]);
    }
    Ok(tags)
}
/// Tags and content of an open advert, for [`Identity::sign`].
pub fn open_parts(
    offer: &Offer,
    region: Option<&str>,
    now: u64,
) -> Result<(Vec<Vec<String>>, String)> {
    offer.validate()?;
    let content = serde_json::to_string(offer).map_err(|_| Refused::Encoding)?;
    Ok((tags("open", region, now)?, content))
}
/// Tags and content of a withdrawal. It names no region and offers nothing.
pub fn withdrawn_parts(now: u64) -> Result<(Vec<Vec<String>>, String)> {
    Ok((tags("withdrawn", None, now)?, "{}".into()))
}
fn bounded(event: &Event) -> Result<()> {
    if serde_json::to_vec(event)
        .map_err(|_| Refused::Encoding)?
        .len()
        > MAX_ADVERT
    {
        return Err(Refused::Size);
    }
    Ok(())
}
pub fn open(identity: &Identity, offer: &Offer, region: Option<&str>, now: u64) -> Result<Event> {
    let (tags, content) = open_parts(offer, region, now)?;
    let event = identity.sign(KIND, tags, content, now)?;
    bounded(&event)?;
    Ok(event)
}
pub fn withdrawn(identity: &Identity, now: u64) -> Result<Event> {
    let (tags, content) = withdrawn_parts(now)?;
    let event = identity.sign(KIND, tags, content, now)?;
    bounded(&event)?;
    Ok(event)
}

/// Client rules 2 and 4 for one event. Rule 3 needs history: use [`AdvertBook`].
pub fn verify(event: &Event, now: u64) -> Result<Advert> {
    bounded(event)?;
    event.verify()?;
    if event.kind != KIND
        || event.tag("d")? != IDENTIFIER
        || event.tag("v")? != "1"
        || event.tag("auth")? != "public"
    {
        return Err(Refused::Destination);
    }
    let expires_at: u64 = event
        .tag("expiration")
        .map_err(|_| Refused::Expired)?
        .parse()
        .map_err(|_| Refused::Expired)?;
    if event.created_at > now.saturating_add(MAX_FUTURE)
        || expires_at <= now
        || expires_at > event.created_at.saturating_add(MAX_LIFETIME)
    {
        return Err(Refused::Expired);
    }
    let region = if event
        .tags
        .iter()
        .any(|tag| tag.first().is_some_and(|name| name == "g"))
    {
        let region = event.tag("g")?;
        if !region_valid(region) {
            return Err(Refused::Destination);
        }
        Some(region.to_owned())
    } else {
        None
    };
    let status = match event.tag("status")? {
        "open" => {
            let offer: Offer =
                serde_json::from_str(&event.content).map_err(|_| Refused::Encoding)?;
            offer.validate()?;
            Status::Open(offer)
        }
        "withdrawn" => {
            let empty: serde_json::Map<String, serde_json::Value> =
                serde_json::from_str(&event.content).map_err(|_| Refused::Encoding)?;
            if !empty.is_empty() {
                return Err(Refused::Encoding);
            }
            Status::Withdrawn
        }
        _ => return Err(Refused::Destination),
    };
    Ok(Advert {
        public_key: event.pubkey.clone(),
        created_at: event.created_at,
        expires_at,
        region,
        status,
    })
}

/// The replay watermark of rule 3: per transport key, the newest
/// `created_at` seen. Anything not newer is refused, so a newer withdrawal
/// cannot be undone by an older open advert. Bounded and swept.
pub struct AdvertBook {
    entries: HashMap<String, (u64, Option<Advert>)>,
    capacity: usize,
}
impl AdvertBook {
    pub fn new(capacity: usize) -> Self {
        Self {
            entries: HashMap::new(),
            capacity: capacity.min(MAX_TRACKED),
        }
    }
    fn sweep(&mut self, now: u64) {
        // Once a watermark is MAX_LIFETIME old, every older event has
        // expired under rule 2, so forgetting it cannot admit a replay.
        self.entries
            .retain(|_, (created, _)| created.saturating_add(MAX_LIFETIME) > now);
    }
    pub fn accept(&mut self, event: &Event, now: u64) -> Result<Advert> {
        self.sweep(now);
        let advert = verify(event, now)?;
        match self.entries.get(&advert.public_key) {
            Some((newest, _)) if advert.created_at <= *newest => return Err(Refused::Replay),
            None if self.entries.len() >= self.capacity => return Err(Refused::Overload),
            _ => {}
        }
        let open = matches!(advert.status, Status::Open(_)).then(|| advert.clone());
        self.entries
            .insert(advert.public_key.clone(), (advert.created_at, open));
        Ok(advert)
    }
    pub fn watermark(&self, public_key: &str) -> Option<u64> {
        self.entries.get(public_key).map(|(newest, _)| *newest)
    }
    /// Unexpired open adverts. Ranking and the per-call limits are the client's.
    pub fn open(&self, now: u64) -> impl Iterator<Item = &Advert> {
        self.entries
            .values()
            .filter_map(|(_, advert)| advert.as_ref())
            .filter(move |advert| advert.expires_at > now)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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

    #[test]
    fn endpoint_and_turn_rules_refuse_unsafe_destinations() {
        assert!(offer().validate().is_ok());
        for endpoint in [
            "http://relay.example/v1/public/credentials",
            "https://relay.example:443/v1/public/credentials",
            "https://relay.example:8443/v1/public/credentials",
            "https://user@relay.example/v1/public/credentials",
            "https://relay.example/v1/public/credentials?x=1",
            "https://relay.example/v1/public/credentials#x",
            "https://relay.example/other",
            "https://192.0.2.1/v1/public/credentials",
            "https://[2001:db8::1]/v1/public/credentials",
            "https://localhost/v1/public/credentials",
            "https://relay.local/v1/public/credentials",
            "https://relay.example./v1/public/credentials",
            "https://RELAY.example/v1/public/credentials",
        ] {
            let mut offer = offer();
            offer.credentials = endpoint.into();
            assert!(offer.validate().is_err(), "{endpoint}");
        }
        for uri in [
            "turn:other.example:3478?transport=udp",
            "turns:relay.example:5349?transport=udp",
            "turn:relay.example:0",
            "turn:relay.example:3478?transport=udp&x=1",
            "stun:relay.example:3478",
            "turn:user@relay.example:3478",
        ] {
            let mut offer = offer();
            offer.urls = vec![uri.into()];
            assert!(offer.validate().is_err(), "{uri}");
        }
        let mut long = offer();
        long.note = Some("x".repeat(MAX_NOTE + 1));
        assert!(long.validate().is_err());
        let mut control = offer();
        control.note = Some("line\nbreak".into());
        assert!(control.validate().is_err());
        let mut many = offer();
        many.urls = vec![many.urls[0].clone(); MAX_URLS + 1];
        assert!(many.validate().is_err());
    }

    #[test]
    fn signed_adverts_verify_and_a_newer_withdrawal_wins() {
        let node = Identity::from_secret(&[3; 32]).unwrap();
        let now = 1_793_000_000;
        let event = open(&node, &offer(), Some("GB"), now).unwrap();
        assert!(event.tags.len() <= 8 && event.tags.iter().all(|tag| tag.len() <= 3));
        let advert = verify(&event, now).unwrap();
        assert_eq!(advert.status, Status::Open(offer()));
        assert_eq!(advert.region.as_deref(), Some("GB"));
        assert_eq!(advert.expires_at, now + MAX_LIFETIME);
        assert!(open(&node, &offer(), Some("gb"), now).is_err());
        assert_eq!(verify(&event, now + MAX_LIFETIME), Err(Refused::Expired));

        let mut book = AdvertBook::new(4);
        book.accept(&event, now).unwrap();
        assert_eq!(book.open(now).count(), 1);
        assert_eq!(book.accept(&event, now), Err(Refused::Replay));
        let gone = withdrawn(&node, now + 1).unwrap();
        assert_eq!(gone.content, "{}");
        assert!(gone.tag("g").is_err());
        assert_eq!(
            book.accept(&gone, now + 1).unwrap().status,
            Status::Withdrawn
        );
        assert_eq!(book.open(now + 1).count(), 0);
        assert_eq!(book.accept(&event, now + 1), Err(Refused::Replay));
        assert_eq!(book.watermark(&node.public_key()), Some(now + 1));

        let mut full = AdvertBook::new(1);
        full.accept(&event, now).unwrap();
        let other = open(
            &Identity::from_secret(&[4; 32]).unwrap(),
            &offer(),
            None,
            now,
        )
        .unwrap();
        assert_eq!(full.accept(&other, now), Err(Refused::Overload));
    }
}
