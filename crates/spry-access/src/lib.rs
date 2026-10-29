//! Owner-controlled pairing, scoped relay access and short-lived credentials.
//!
//! Hosts supply identity, endpoints, storage and scheduling. This library opens
//! no sockets, starts no runtime and never forwards media.
//! MIT, copyright 2026 TheCryptoDonkey.
#![forbid(unsafe_code)]

use base64::{
    Engine,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use hmac::{Hmac, Mac};
use secp256k1::{
    XOnlyPublicKey,
    schnorr::{self, Signature},
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha1::Sha1;
use sha2::{Digest, Sha256};
use std::{
    collections::{HashMap, HashSet},
    fs,
    io::Write,
    path::{Path, PathBuf},
};
use url::Url;

pub const MAX_BODY: usize = 8192;
pub const GRANT_TTL: u64 = 30 * 24 * 60 * 60;
/// Anonymous TURN credentials for an operator who opts in to public mode.
pub const PUBLIC_PATH: &str = "/v1/public/credentials";
/// One hour. The relay ends an allocation when its login expires and refuses
/// to refresh it after that, so this bounds a call on one public login.
pub const PUBLIC_TTL: u64 = 3600;
pub const PUBLIC_PER_MINUTE: u16 = 32;
pub const PUBLIC_PER_SOURCE: u16 = 6;
pub const PUBLIC_SOURCES: usize = 256;
/// Registered signing keys one room grant may hold.
pub const MAX_MEMBERS: usize = 64;
/// Registered signing keys across every grant on the node.
pub const MAX_NODE_MEMBERS: usize = 1024;
/// Registered signing keys the grants of one pairing may hold together:
/// half the node, so one pairing cannot fill it for every other.
pub const MAX_PAIRING_MEMBERS: usize = MAX_NODE_MEMBERS / 2;
/// Vouched keys one grant may hold at once.
pub const MAX_VOUCHED: usize = 8;
/// A vouched key lapses this long after the vouch and is never renewed by use.
pub const VOUCH_TTL: u64 = 24 * 60 * 60;
/// Largest state file `restore` reads, and so the largest `save` writes.
pub const MAX_STATE: usize = 131_072;
const MAX_REGISTRATION: usize = 32;
const MAX_VOUCH: usize = 4;
const SPONSOR_VOUCHES: usize = 8;
/// Sponsors one grant tracks at once, so churn on one grant cannot stop
/// vouching on another.
const SPONSORS: usize = MAX_MEMBERS;
const REVISION_WINDOW: u64 = 90;
const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;
const EXPIRED: &str = "Call access has expired.";
const BUSY: &str = "Spry is busy. Try again shortly.";
const DEVICE_LIMIT: &str = "This call has reached its device limit.";
pub type Result<T> = std::result::Result<T, Refused>;
#[derive(Debug)]
pub struct Refused(pub u16, pub &'static str);
/// One per-minute bucket in a table of at most 256, refusing with a generic
/// message. `reserved` callers are admitted even when the table is full.
fn count(
    table: &mut HashMap<String, (u64, u16)>,
    id: String,
    reserved: bool,
    now: u64,
) -> Result<()> {
    need(
        reserved || table.contains_key(&id) || table.len() < 256,
        429,
        "Spry is busy. Try again shortly.",
    )?;
    let entry = table.entry(id).or_insert((now + 60, 0));
    entry.1 = entry.1.saturating_add(1);
    need(entry.1 <= 120, 429, "Too many requests. Try again shortly.")
}
fn need(ok: bool, status: u16, message: &'static str) -> Result<()> {
    if ok {
        Ok(())
    } else {
        Err(Refused(status, message))
    }
}
pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
pub fn hash(bytes: impl AsRef<[u8]>) -> String {
    hex(&Sha256::digest(bytes.as_ref()))
}
fn unhex(value: &str) -> Result<Vec<u8>> {
    need(
        value.len() % 2 == 0 && value.bytes().all(|c| c.is_ascii_hexdigit()),
        401,
        "Approval required.",
    )?;
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            u8::from_str_radix(
                std::str::from_utf8(pair).map_err(|_| Refused(401, "Approval required."))?,
                16,
            )
            .map_err(|_| Refused(401, "Approval required."))
        })
        .collect()
}
fn is_key(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
/// A lowercase x-only public key that is a real curve point.
fn is_point(value: &str) -> bool {
    is_key(value)
        && unhex(value)
            .ok()
            .and_then(|bytes| <[u8; 32]>::try_from(bytes).ok())
            .is_some_and(|bytes| XOnlyPublicKey::from_byte_array(bytes).is_ok())
}
/// Equality whose time does not depend on where two equal-length values differ.
fn same(a: &str, b: &str) -> bool {
    a.len() == b.len()
        && a.bytes()
            .zip(b.bytes())
            .fold(0_u8, |acc, (x, y)| acc | (x ^ y))
            == 0
}
fn is_token(value: &str) -> bool {
    value.len() == 43
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}
fn token() -> Result<String> {
    let mut bytes = [0_u8; 32];
    getrandom::fill(&mut bytes).map_err(|_| Refused(503, "Spry is temporarily unavailable."))?;
    Ok(URL_SAFE_NO_PAD.encode(bytes))
}
fn text<'a>(body: &'a Value, key: &str) -> Result<&'a str> {
    body.get(key)
        .and_then(Value::as_str)
        .ok_or(Refused(400, "Invalid request."))
}
/// A version 1 body holding no field outside `allowed`.
fn shape(body: &Value, allowed: &[&str]) -> Result<()> {
    need(
        body.get("v") == Some(&json!(1))
            && body
                .as_object()
                .is_some_and(|fields| fields.keys().all(|name| allowed.contains(&name.as_str()))),
        400,
        "Invalid request.",
    )
}
/// An optional list of at most `max` distinct signing keys.
fn keys(body: &Value, name: &str, max: usize) -> Result<Vec<String>> {
    let Some(value) = body.get(name) else {
        return Ok(Vec::new());
    };
    let list = value.as_array().ok_or(Refused(400, "Invalid request."))?;
    need(list.len() <= max, 400, "Invalid request.")?;
    let mut found: Vec<String> = Vec::with_capacity(list.len());
    for item in list {
        let key = item.as_str().ok_or(Refused(400, "Invalid request."))?;
        need(
            is_point(key) && !found.iter().any(|seen| seen == key),
            400,
            "Invalid request.",
        )?;
        found.push(key.to_owned());
    }
    Ok(found)
}

/// When a room grant refuses signing keys its registrar has not listed.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Seal {
    /// A grant is enforced once its registrar asks for it to be sealed.
    #[default]
    Auto,
    /// Every grant is enforced, including grants created before the switch.
    Required,
    /// Registrations are stored but never enforced. For diagnosis and rollback.
    Off,
}
impl Seal {
    /// Exactly `auto`, `required` or `off`.
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "auto" => Some(Self::Auto),
            "required" => Some(Self::Required),
            "off" => Some(Self::Off),
            _ => None,
        }
    }
}

pub struct Config {
    pub endpoint: String,
    /// Optional routing descriptor supplied by a host transport adapter.
    /// HTTP request signatures remain bound to `endpoint`.
    pub transport_endpoint: Option<String>,
    /// Optional per-instance binding for HTTP proofs on private/local hostnames.
    pub audience: Option<String>,
    pub app: String,
    pub owners: HashSet<String>,
    pub origins: HashSet<String>,
    pub urls: Vec<String>,
    pub state_file: Option<PathBuf>,
    secret: Vec<u8>,
    pub ready: bool,
    pub readiness: &'static str,
    /// Public mode. Off unless the host explicitly turns it on.
    pub public: bool,
    /// Room-grant sealing. `Auto` unless the host chooses otherwise.
    pub seal: Seal,
}
impl Config {
    pub fn new(
        endpoint: &str,
        app: &str,
        owners: &str,
        secret: &[u8],
        state_file: Option<PathBuf>,
    ) -> Result<Self> {
        let endpoint_url =
            Url::parse(endpoint).map_err(|_| Refused(503, "Public access is not configured."))?;
        need(
            endpoint_url.scheme() == "https"
                && endpoint_url.username().is_empty()
                && endpoint_url.password().is_none()
                && endpoint_url.path() == "/"
                && endpoint_url.query().is_none()
                && endpoint_url.fragment().is_none(),
            503,
            "Public access is not configured.",
        )?;
        let app_url = Url::parse(app)
            .map_err(|_| Refused(503, "The pairing application is not configured."))?;
        need(
            app_url.scheme() == "https"
                && app_url.username().is_empty()
                && app_url.password().is_none()
                && app_url.query().is_none()
                && app_url.fragment().is_none(),
            503,
            "The pairing application is not configured.",
        )?;
        let owners: HashSet<String> = owners
            .split(',')
            .filter(|s| !s.is_empty())
            .map(str::to_owned)
            .collect();
        need(
            !owners.is_empty()
                && owners.len() <= 128
                && owners.iter().all(|s| is_key(s))
                && secret.len() >= 32,
            503,
            "Choose an owner identity before pairing Spry.",
        )?;
        let endpoint = endpoint_url.origin().ascii_serialization();
        let host = endpoint_url
            .host_str()
            .ok_or(Refused(503, "Public access is not configured."))?;
        let urls = vec![
            format!("turn:{host}:3478?transport=udp"),
            format!("turn:{host}:3478?transport=tcp"),
        ];
        let origins = HashSet::from([
            endpoint.clone(),
            format!("https://{host}"),
            app_url.origin().ascii_serialization(),
        ]);
        Ok(Self {
            endpoint,
            transport_endpoint: None,
            audience: None,
            app: app_url.to_string(),
            owners,
            origins,
            urls,
            state_file,
            secret: secret.to_vec(),
            ready: false,
            readiness: "Your node needs public access before Spry can connect calls.",
            public: false,
            seal: Seal::Auto,
        })
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Pairing {
    pub id: String,
    pub key: String,
    #[serde(rename = "createdAt")]
    pub created_at: u64,
}
#[derive(Serialize, Deserialize)]
struct Saved {
    version: u8,
    pairs: Vec<Pairing>,
    #[serde(default)]
    grants: Vec<Grant>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    transport_endpoint: Option<String>,
}
#[derive(Clone, Serialize, Deserialize)]
struct Grant {
    pair: String,
    scope: String,
    salt: String,
    #[serde(skip)]
    token: String,
    expires: u64,
    #[serde(skip)]
    devices: HashMap<String, u64>,
    /// Set once by the registrar and never cleared.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    sealed: bool,
    /// Registered signing keys: key, lease end and whether it was vouched.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    members: Vec<(String, u64, bool)>,
    /// Last redemption by each member since start, in memory only.
    #[serde(skip)]
    used: HashMap<String, u64>,
    /// Keys each sponsor vouched for, by hashed sponsor key: window end and
    /// count. In memory only, and gone with the grant.
    #[serde(skip)]
    sponsors: HashMap<String, (u64, usize)>,
}
impl Grant {
    fn member(&self, key: &str) -> Option<&(String, u64, bool)> {
        self.members.iter().find(|member| member.0 == key)
    }
    /// An unexpired entry, confirmed or vouched.
    fn admits(&self, key: &str, now: u64) -> bool {
        self.member(key).is_some_and(|member| member.1 > now)
    }
    /// An unexpired entry the registrar added. Only these may vouch.
    fn confirmed(&self, key: &str, now: u64) -> bool {
        self.member(key)
            .is_some_and(|member| !member.2 && member.1 > now)
    }
    fn vouched(&self) -> usize {
        self.members.iter().filter(|member| member.2).count()
    }
    fn forget(&mut self, key: &str) {
        self.members.retain(|member| member.0 != key);
        self.used.remove(key);
    }
}
pub struct Authority {
    pub config: Config,
    pairs: HashMap<String, Pairing>,
    pending: HashMap<String, u64>,
    grants: HashMap<String, Grant>,
    replays: HashMap<String, u64>,
    // Unauthenticated requests, keyed by source address.
    rates: HashMap<String, (u64, u16)>,
    // Authenticated requests, keyed by signing key. Kept apart from `rates`,
    // so callers spread over many addresses cannot fill the table that
    // owners and paired apps need after they authenticate.
    key_rates: HashMap<String, (u64, u16)>,
    // Kept apart from `rates`, so anonymous callers cannot exhaust the
    // limiter that paired apps and owners rely on.
    public_rates: HashMap<String, (u64, u16)>,
    public_window: (u64, u16),
    // The newest registration revision per grant, held for 90 seconds.
    revisions: HashMap<String, (u64, u64)>,
}
impl Authority {
    pub fn new(config: Config) -> Self {
        Self {
            config,
            pairs: HashMap::new(),
            pending: HashMap::new(),
            grants: HashMap::new(),
            replays: HashMap::new(),
            rates: HashMap::new(),
            key_rates: HashMap::new(),
            public_rates: HashMap::new(),
            public_window: (0, 0),
            revisions: HashMap::new(),
        }
    }

    pub fn advertised_endpoint(&self) -> &str {
        self.config
            .transport_endpoint
            .as_deref()
            .unwrap_or(&self.config.endpoint)
    }

    pub fn pairing_authorises(&self, pairing: &str, key: &str) -> bool {
        self.pairs.get(pairing).is_some_and(|pair| pair.key == key)
    }

    pub fn has_pairing(&self, pairing: &str) -> bool {
        self.pairs.contains_key(pairing)
    }

    /// Whether a grant refuses signing keys it does not list.
    fn enforced(&self, grant: &Grant) -> bool {
        match self.config.seal {
            Seal::Auto => grant.sealed,
            Seal::Required => true,
            Seal::Off => false,
        }
    }
    fn member_total(&self) -> usize {
        self.grants.values().map(|grant| grant.members.len()).sum()
    }
    fn pairing_total(&self, pairing: &str) -> usize {
        self.grants
            .values()
            .filter(|grant| grant.pair == pairing)
            .map(|grant| grant.members.len())
            .sum()
    }

    /// Transport configuration is an owner action. The adapter validates its URI profile.
    pub fn set_transport_endpoint(&mut self, owner: &str, endpoint: String) -> Result<()> {
        need(
            self.config.owners.contains(owner),
            403,
            "Choose one of this relay’s owner identities.",
        )?;
        need(
            !endpoint.is_empty() && endpoint.len() <= 2048,
            400,
            "Invalid transport address.",
        )?;
        let previous = self.config.transport_endpoint.replace(endpoint);
        if let Err(error) = self.save() {
            self.config.transport_endpoint = previous;
            return Err(error);
        }
        Ok(())
    }
    /// For a supervised node: trust the supervising app's signing key as the
    /// node's only pairing, in place of an owner-issued claim code. Call it
    /// after [`Authority::restore`]. The pairing id is derived from the node
    /// secret and the key, so a restart keeps the same id and with it every
    /// room grant. Any other pairing, its grants and any pending claim code
    /// are removed in the same saved write. Returns the pairing id.
    pub fn trust_pairing(&mut self, key: &str, now: u64) -> Result<String> {
        need(is_point(key), 400, "Invalid pairing key.")?;
        let mut mac = Hmac::<Sha256>::new_from_slice(&self.config.secret)
            .map_err(|_| Refused(503, "Unavailable."))?;
        mac.update(format!("spry-supervised-pairing-v1:{key}").as_bytes());
        let id = URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes());
        let held = self.pairs.get(&id).is_some_and(|pair| pair.key == key);
        if held && self.pairs.len() == 1 && self.pending.is_empty() {
            return Ok(id);
        }
        let created_at = self
            .pairs
            .get(&id)
            .filter(|_| held)
            .map_or(now, |pair| pair.created_at);
        let pairs = std::mem::take(&mut self.pairs);
        let pending = std::mem::take(&mut self.pending);
        let grants = std::mem::take(&mut self.grants);
        self.pairs.insert(
            id.clone(),
            Pairing {
                id: id.clone(),
                key: key.into(),
                created_at,
            },
        );
        self.grants = grants
            .iter()
            .filter(|(_, grant)| held && grant.pair == id)
            .map(|(token, grant)| (token.clone(), grant.clone()))
            .collect();
        if self.save().is_err() {
            self.pairs = pairs;
            self.pending = pending;
            self.grants = grants;
            return Err(Refused(503, "Pairing could not be saved."));
        }
        Ok(id)
    }
    fn grant_token(&self, pair: &str, scope: &str, salt: &str) -> Result<String> {
        let mut mac = Hmac::<Sha256>::new_from_slice(&self.config.secret)
            .map_err(|_| Refused(503, "Unavailable."))?;
        mac.update(format!("spry-grant-v1:{pair}:{scope}:{salt}").as_bytes());
        Ok(URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes()))
    }
    pub fn restore(&mut self) -> Result<()> {
        let Some(path) = &self.config.state_file else {
            return Ok(());
        };
        let info = match fs::symlink_metadata(path) {
            Ok(info) => info,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(_) => return Err(Refused(503, "Pairings could not be read.")),
        };
        need(
            info.is_file() && !info.file_type().is_symlink() && info.len() <= MAX_STATE as u64,
            503,
            "Pairings could not be read.",
        )?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            need(
                info.permissions().mode() & 0o077 == 0,
                503,
                "Pairings are not private.",
            )?;
        }
        let bytes = fs::read(path).map_err(|_| Refused(503, "Pairings could not be read."))?;
        let state: Saved = serde_json::from_slice(&bytes)
            .map_err(|_| Refused(503, "Pairings could not be read."))?;
        need(
            state.version == 1
                && state
                    .transport_endpoint
                    .as_ref()
                    .is_none_or(|endpoint| !endpoint.is_empty() && endpoint.len() <= 2048)
                && state.pairs.len() <= 16
                && state.grants.len() <= 64
                && state
                    .grants
                    .iter()
                    .all(|g| is_token(&g.pair) && is_key(&g.scope) && is_token(&g.salt))
                && state.grants.iter().all(|g| {
                    g.members.len() <= MAX_MEMBERS
                        && g.vouched() <= MAX_VOUCHED
                        && g.members.iter().enumerate().all(|(index, member)| {
                            is_point(&member.0)
                                && !g.members[..index].iter().any(|other| other.0 == member.0)
                        })
                })
                && state.grants.iter().map(|g| g.members.len()).sum::<usize>() <= MAX_NODE_MEMBERS
                && state.pairs.iter().all(|p| {
                    state
                        .grants
                        .iter()
                        .filter(|g| g.pair == p.id)
                        .map(|g| g.members.len())
                        .sum::<usize>()
                        <= MAX_PAIRING_MEMBERS
                })
                && state
                    .pairs
                    .iter()
                    .all(|p| is_token(&p.id) && is_key(&p.key)),
            503,
            "Pairings could not be read.",
        )?;
        self.config.transport_endpoint = state.transport_endpoint;
        self.pairs = state.pairs.into_iter().map(|p| (p.id.clone(), p)).collect();
        for mut grant in state.grants {
            if !self.pairs.contains_key(&grant.pair) {
                continue;
            }
            grant.token = self.grant_token(&grant.pair, &grant.scope, &grant.salt)?;
            self.grants.insert(hash(&grant.token), grant);
        }
        Ok(())
    }
    fn save(&self) -> Result<()> {
        let Some(path) = &self.config.state_file else {
            return Ok(());
        };
        let bytes = serde_json::to_vec(&Saved {
            version: 1,
            pairs: self.pairs.values().cloned().collect(),
            grants: self.grants.values().cloned().collect(),
            transport_endpoint: self.config.transport_endpoint.clone(),
        })
        .map_err(|_| Refused(503, "Pairing could not be saved."))?;
        // Never write a file that `restore` would refuse on the next start.
        need(bytes.len() <= MAX_STATE, 503, "Pairing could not be saved.")?;
        write_private(path, &bytes).map_err(|_| Refused(503, "Pairing could not be saved."))
    }
    pub fn sweep(&mut self, now: u64) {
        self.pending.retain(|_, until| *until > now);
        self.grants
            .retain(|_, grant| grant.expires > now && self.pairs.contains_key(&grant.pair));
        for grant in self.grants.values_mut() {
            grant.devices.retain(|_, until| *until > now);
            grant.members.retain(|member| member.1 > now);
            let members = &grant.members;
            grant
                .used
                .retain(|key, _| members.iter().any(|member| member.0 == *key));
            grant.sponsors.retain(|_, (until, _)| *until > now);
        }
        let grants = &self.grants;
        self.revisions
            .retain(|id, (_, until)| *until > now && grants.contains_key(id));
        self.replays.retain(|_, until| *until >= now);
        self.rates.retain(|_, (until, _)| *until > now);
        self.key_rates.retain(|_, (until, _)| *until > now);
        self.public_rates.retain(|_, (until, _)| *until > now);
        if self.public_window.0 <= now {
            self.public_window = (0, 0);
        }
    }
    /// Counts one request before authentication against its source address.
    pub fn rate(&mut self, address: &str, now: u64) -> Result<()> {
        self.sweep(now);
        count(&mut self.rates, hash(address), false, now)
    }
    /// Counts one authenticated request against its signing key. Owner and
    /// paired keys, at most a few dozen, always find room in the table, so
    /// requests signed by fresh keys cannot crowd them out; each still has
    /// the same per-minute cap.
    pub fn key_rate(&mut self, key: &str, now: u64) -> Result<()> {
        self.sweep(now);
        let known = self.known_key(key);
        count(&mut self.key_rates, hash(key), known, now)
    }
    /// An owner or a paired app.
    fn known_key(&self, key: &str) -> bool {
        self.config.owners.contains(key) || self.pairs.values().any(|pair| pair.key == key)
    }
    /// Counts one anonymous request against the public limits. The source is
    /// only held hashed, in memory, for at most a minute.
    pub fn public_rate(&mut self, source: &str, now: u64) -> Result<()> {
        need(self.config.public, 404, "Not found.")?;
        self.sweep(now);
        let id = hash(format!("public:{source}"));
        need(
            self.public_rates.contains_key(&id) || self.public_rates.len() < PUBLIC_SOURCES,
            429,
            "Spry is busy. Try again shortly.",
        )?;
        if self.public_window.0 == 0 {
            self.public_window = (now + 60, 0);
        }
        need(
            self.public_window.1 < PUBLIC_PER_MINUTE,
            429,
            "Spry is busy. Try again shortly.",
        )?;
        let entry = self.public_rates.entry(id).or_insert((now + 60, 0));
        need(
            entry.1 < PUBLIC_PER_SOURCE,
            429,
            "Spry is busy. Try again shortly.",
        )?;
        entry.1 += 1;
        self.public_window.1 += 1;
        Ok(())
    }
    /// Issues TURN credentials to anyone. The label is fresh randomness for
    /// each issue, unrelated to the caller, so issues cannot be linked by it.
    /// It grants relaying only: no pairing, grant, room or peer authority.
    pub fn public_credentials(&mut self, body: &Value, now: u64) -> Result<Value> {
        need(self.config.public, 404, "Not found.")?;
        need(
            body.as_object()
                .is_some_and(|body| body.len() == 1 && body.get("v") == Some(&json!(1))),
            400,
            "Invalid request.",
        )?;
        need(self.config.ready, 503, self.config.readiness)?;
        let mut label = [0_u8; 12];
        getrandom::fill(&mut label)
            .map_err(|_| Refused(503, "Spry is temporarily unavailable."))?;
        let expires = now + PUBLIC_TTL;
        let username = format!("{expires}:pub-{}", hex(&label));
        let mut mac = Hmac::<Sha1>::new_from_slice(&self.config.secret)
            .map_err(|_| Refused(503, "Spry is temporarily unavailable."))?;
        mac.update(username.as_bytes());
        Ok(
            json!({"urls":self.config.urls,"username":username,"credential":STANDARD.encode(mac.finalize().into_bytes()),"expiresAt":expires}),
        )
    }
    pub fn authenticate(
        &mut self,
        header: &str,
        path: &str,
        body: &[u8],
        now: u64,
    ) -> Result<String> {
        need(header.len() <= 4096, 401, "Approval required.")?;
        let bytes = STANDARD
            .decode(
                header
                    .strip_prefix("Nostr ")
                    .ok_or(Refused(401, "Approval required."))?,
            )
            .map_err(|_| Refused(401, "Approval required."))?;
        let event: AuthEvent =
            serde_json::from_slice(&bytes).map_err(|_| Refused(401, "Approval required."))?;
        need(
            event.kind == 27235
                && event.content.is_empty()
                && is_key(&event.pubkey)
                && event.created_at.abs_diff(now) <= 60
                && event.tags.len() <= 8
                && event
                    .tags
                    .iter()
                    .all(|t| t.len() == 2 && t.iter().all(|s| s.len() <= 512)),
            401,
            "Approval expired. Try again.",
        )?;
        let one = |name: &str| -> Option<&str> {
            let mut found = event.tags.iter().filter(|t| t[0] == name);
            let tag = found.next()?;
            if found.next().is_some() {
                None
            } else {
                Some(tag[1].as_str())
            }
        };
        need(
            one("u") == Some((self.config.endpoint.clone() + path).as_str())
                && one("method") == Some("POST")
                && one("payload") == Some(hash(body).as_str())
                && self
                    .config
                    .audience
                    .as_ref()
                    .is_none_or(|audience| one("aud") == Some(audience.as_str()))
                && one("nonce").is_some_and(is_token),
            401,
            "Approval required.",
        )?;
        let canonical = serde_json::to_vec(&json!([
            0,
            event.pubkey,
            event.created_at,
            event.kind,
            event.tags,
            event.content
        ]))
        .map_err(|_| Refused(401, "Approval required."))?;
        let id = Sha256::digest(&canonical);
        need(
            hex(&id) == event.id && !self.replays.contains_key(&event.id),
            401,
            "Approval expired. Try again.",
        )?;
        let key = XOnlyPublicKey::from_byte_array(
            unhex(&event.pubkey)?
                .try_into()
                .map_err(|_| Refused(401, "Approval required."))?,
        )
        .map_err(|_| Refused(401, "Approval required."))?;
        let signature = Signature::from_byte_array(
            unhex(&event.sig)?
                .try_into()
                .map_err(|_| Refused(401, "Approval required."))?,
        );
        schnorr::verify(&signature, &id, &key).map_err(|_| Refused(401, "Approval required."))?;
        // Known keys are few, so letting them past a full table stays bounded.
        need(
            self.replays.len() < 4096 || self.known_key(&event.pubkey),
            429,
            "Spry is busy. Try again shortly.",
        )?;
        self.replays.insert(event.id, event.created_at + 60);
        Ok(event.pubkey)
    }
    pub fn handle(&mut self, path: &str, key: &str, body: &Value, now: u64) -> Result<Value> {
        self.sweep(now);
        need(body.is_object(), 400, "Invalid request.")?;
        match path {
            "/v1/pairings" => {
                need(
                    self.config.owners.contains(key),
                    403,
                    "Choose one of this relay’s owner identities.",
                )?;
                need(self.config.ready, 503, self.config.readiness)?;
                need(
                    self.pending.len() < 16 && self.pairs.len() < 16,
                    429,
                    "Remove an old pairing first.",
                )?;
                let code = token()?;
                let expires = now + 300;
                self.pending.insert(hash(&code), expires);
                let payload = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&json!({"v":1,"endpoint":self.advertised_endpoint(),"code":code,"expiresAt":expires})).map_err(|_| Refused(503, "Pairing could not be prepared."))?);
                Ok(json!({"url":format!("{}#spry={payload}", self.config.app),"expiresAt":expires}))
            }
            "/v1/pairings/claim" => {
                let code = text(body, "code")?;
                need(
                    is_token(code)
                        && self.pending.get(&hash(code)).is_some_and(|e| *e > now)
                        && self.pairs.len() < 16,
                    401,
                    "This pairing link has expired. Open Spry and pair again.",
                )?;
                self.pending.remove(&hash(code));
                let pair = Pairing {
                    id: token()?,
                    key: key.into(),
                    created_at: now,
                };
                self.pairs.insert(pair.id.clone(), pair.clone());
                if self.save().is_err() {
                    self.pairs.remove(&pair.id);
                    return Err(Refused(503, "Pairing could not be saved. Pair again."));
                }
                Ok(json!({"version":1,"id":pair.id,"endpoint":self.advertised_endpoint()}))
            }
            "/v1/pairings/list" => {
                need(
                    self.config.owners.contains(key),
                    403,
                    "Node approval required.",
                )?;
                Ok(
                    json!({"pairings":self.pairs.values().map(|p| json!({"id":p.id,"createdAt":p.created_at})).collect::<Vec<_>>()}),
                )
            }
            "/v1/pairings/remove" | "/v1/pairings/remove-self" => {
                let id = text(body, "id")?;
                need(is_token(id), 400, "Invalid request.")?;
                let authorised = if path.ends_with("remove-self") {
                    self.pairs.get(id).is_some_and(|p| p.key == key)
                } else {
                    self.config.owners.contains(key)
                };
                need(authorised, 403, "Approval required.")?;
                let old = self.pairs.remove(id);
                // Its grants, and their registered keys, leave the saved
                // state in the same write.
                let grants = std::mem::take(&mut self.grants);
                let (dropped, kept) = grants.into_iter().partition(|(_, g)| g.pair == id);
                self.grants = kept;
                if self.save().is_err() {
                    if let Some(old) = old {
                        self.pairs.insert(id.into(), old);
                    }
                    self.grants.extend::<HashMap<String, Grant>>(dropped);
                    return Err(Refused(503, "The pairing could not be removed."));
                }
                self.sweep(now);
                Ok(json!({"removed":true}))
            }
            "/v1/grants" => {
                let pair = text(body, "pairing")?;
                let scope = text(body, "scope")?;
                need(
                    self.pairs.get(pair).is_some_and(|p| p.key == key),
                    403,
                    "Spry is no longer paired. Pair it again.",
                )?;
                need(is_key(scope), 400, "Invalid request.")?;
                if let Some(id) = self
                    .grants
                    .iter()
                    .find_map(|(id, g)| (g.pair == pair && g.scope == scope).then(|| id.clone()))
                {
                    let old = self.grants[&id].expires;
                    self.grants
                        .get_mut(&id)
                        .ok_or(Refused(503, "Unavailable."))?
                        .expires = now + GRANT_TTL;
                    if self.save().is_err() {
                        self.grants
                            .get_mut(&id)
                            .ok_or(Refused(503, "Unavailable."))?
                            .expires = old;
                        return Err(Refused(503, "Call access could not be saved."));
                    }
                    let grant = &self.grants[&id];
                    return Ok(
                        json!({"v":1,"endpoint":self.advertised_endpoint(),"token":grant.token,"expiresAt":grant.expires}),
                    );
                }
                need(
                    self.grants.len() < 64,
                    429,
                    "Spry is already helping too many calls.",
                )?;
                let salt = token()?;
                let token = self.grant_token(pair, scope, &salt)?;
                let id = hash(&token);
                let result = json!({"v":1,"endpoint":self.advertised_endpoint(),"token":token,"expiresAt":now + GRANT_TTL});
                self.grants.insert(
                    id.clone(),
                    Grant {
                        pair: pair.into(),
                        scope: scope.into(),
                        salt,
                        token,
                        expires: now + GRANT_TTL,
                        devices: HashMap::new(),
                        sealed: false,
                        members: Vec::new(),
                        used: HashMap::new(),
                        sponsors: HashMap::new(),
                    },
                );
                if self.save().is_err() {
                    self.grants.remove(&id);
                    return Err(Refused(503, "Call access could not be saved."));
                }
                Ok(result)
            }
            "/v1/grants/remove" => {
                let pair = text(body, "pairing")?;
                let token = text(body, "grant")?;
                need(
                    self.pairs.get(pair).is_some_and(|p| p.key == key),
                    403,
                    "Approval required.",
                )?;
                let id = hash(token);
                need(
                    self.grants.get(&id).is_none_or(|g| g.pair == pair),
                    403,
                    "Approval required.",
                )?;
                let old = self.grants.remove(&id);
                if self.save().is_err() {
                    if let Some(old) = old {
                        self.grants.insert(id, old);
                    }
                    return Err(Refused(503, "Call access could not be revoked."));
                }
                Ok(json!({"removed":true}))
            }
            "/v1/grants/devices" => self.register(key, body, now),
            "/v1/grants/vouch" => self.vouch(key, body, now),
            "/v1/credentials" => {
                need(self.config.ready, 503, self.config.readiness)?;
                let token = text(body, "grant")?;
                need(is_token(token), 403, EXPIRED)?;
                let id = hash(token);
                let enforced = self
                    .grants
                    .get(&id)
                    .is_some_and(|grant| self.enforced(grant));
                let grant = self.grants.get_mut(&id).ok_or(Refused(403, EXPIRED))?;
                need(
                    grant.expires > now && self.pairs.contains_key(&grant.pair),
                    403,
                    EXPIRED,
                )?;
                // Before the device limit, so an unlisted key on a sealed
                // grant gets the expired refusal and takes no slot.
                need(!enforced || grant.admits(key, now), 403, EXPIRED)?;
                need(
                    grant.devices.contains_key(key) || grant.devices.len() < 32,
                    429,
                    DEVICE_LIMIT,
                )?;
                grant.devices.insert(key.into(), now + 600);
                let old = grant.expires;
                if old - now < GRANT_TTL - 86400 {
                    grant.expires = now + GRANT_TTL;
                }
                // A confirmed entry renews like the grant, at most once a
                // day; a vouched entry never does.
                let mut old_lease = None;
                if let Some(member) = grant.members.iter_mut().find(|member| member.0 == key) {
                    if !member.2 && member.1 - now < GRANT_TTL - 86400 {
                        old_lease = Some(member.1);
                        member.1 = now + GRANT_TTL;
                    }
                    grant.used.insert(key.into(), now);
                }
                let access_expires = grant.expires;
                let expires = (now + 300).min(access_expires);
                if (old != access_expires || old_lease.is_some()) && self.save().is_err() {
                    let grant = self
                        .grants
                        .get_mut(&id)
                        .ok_or(Refused(503, "Unavailable."))?;
                    grant.expires = old;
                    if let (Some(lease), Some(member)) = (
                        old_lease,
                        grant.members.iter_mut().find(|member| member.0 == key),
                    ) {
                        member.1 = lease;
                    }
                    return Err(Refused(503, "Call access could not be renewed."));
                }
                let mut mac = Hmac::<Sha256>::new_from_slice(&self.config.secret)
                    .map_err(|_| Refused(503, "Spry is temporarily unavailable."))?;
                mac.update(format!("spry-device-v1:{token}:{key}").as_bytes());
                let label = hex(&mac.finalize().into_bytes());
                let username = format!("{expires}:{}", &label[..24]);
                let mut mac = Hmac::<Sha1>::new_from_slice(&self.config.secret)
                    .map_err(|_| Refused(503, "Spry is temporarily unavailable."))?;
                mac.update(username.as_bytes());
                Ok(
                    json!({"urls":self.config.urls,"username":username,"credential":STANDARD.encode(mac.finalize().into_bytes()),"expiresAt":expires,"accessExpiresAt":access_expires}),
                )
            }
            _ => Err(Refused(404, "Not found.")),
        }
    }

    /// `/v1/grants/devices`: the owning pairing adds and removes registered
    /// signing keys and may seal the grant. Changes apply all or nothing.
    fn register(&mut self, key: &str, body: &Value, now: u64) -> Result<Value> {
        shape(
            body,
            &["v", "pairing", "grant", "add", "remove", "seal", "revision"],
        )?;
        let pair = text(body, "pairing")?;
        let token = text(body, "grant")?;
        let revision = body
            .get("revision")
            .and_then(Value::as_u64)
            .filter(|revision| *revision <= MAX_SAFE_INTEGER)
            .ok_or(Refused(400, "Invalid request."))?;
        let add = keys(body, "add", MAX_REGISTRATION)?;
        let remove = keys(body, "remove", MAX_REGISTRATION)?;
        need(
            !add.iter().any(|key| remove.contains(key)),
            400,
            "Invalid request.",
        )?;
        let seal = match body.get("seal") {
            None => false,
            Some(Value::Bool(seal)) => *seal,
            Some(_) => return Err(Refused(400, "Invalid request.")),
        };
        // The signer's authority first, so a stranger learns nothing about
        // whether a token it holds is live.
        need(
            self.pairing_authorises(pair, key),
            403,
            "Approval required.",
        )?;
        need(is_token(token), 403, EXPIRED)?;
        let id = hash(token);
        let current = self
            .grants
            .get(&id)
            .filter(|grant| grant.expires > now)
            .ok_or(Refused(403, EXPIRED))?;
        need(same(&current.pair, pair), 403, "Approval required.")?;
        need(
            self.revisions
                .get(&id)
                .is_none_or(|(held, _)| revision > *held),
            409,
            "Out of date. Try again.",
        )?;
        let mut next = current.clone();
        for key in &remove {
            next.forget(key);
            // Frees its device slot at once; issued credentials still lapse
            // on their own within five minutes.
            next.devices.remove(key);
        }
        let lease = now + GRANT_TTL;
        for key in &add {
            if let Some(member) = next.members.iter_mut().find(|member| member.0 == *key) {
                *member = (key.clone(), lease, false);
                continue;
            }
            if next.members.len() >= MAX_MEMBERS {
                // The confirmed entry used least recently, never one with a
                // live device lease, a vouched one or one named here.
                let victim = next
                    .members
                    .iter()
                    .filter(|member| {
                        !member.2
                            && !add.contains(&member.0)
                            && !next.devices.contains_key(&member.0)
                    })
                    .min_by(|a, b| {
                        let used = |key: &String| next.used.get(key).copied().unwrap_or(0);
                        used(&a.0).cmp(&used(&b.0)).then_with(|| a.0.cmp(&b.0))
                    })
                    .map(|member| member.0.clone())
                    .ok_or(Refused(429, DEVICE_LIMIT))?;
                next.forget(&victim);
            }
            next.members.push((key.clone(), lease, false));
        }
        need(
            self.member_total() - current.members.len() + next.members.len() <= MAX_NODE_MEMBERS
                && self.pairing_total(pair) - current.members.len() + next.members.len()
                    <= MAX_PAIRING_MEMBERS,
            429,
            "Spry is already helping too many calls.",
        )?;
        if seal {
            next.sealed = true;
        }
        let old = self.grants.insert(id.clone(), next);
        if self.save().is_err() {
            if let Some(old) = old {
                self.grants.insert(id, old);
            }
            return Err(Refused(503, "Call access could not be saved."));
        }
        self.revisions
            .insert(id.clone(), (revision, now + REVISION_WINDOW));
        let grant = &self.grants[&id];
        Ok(
            json!({"v":1,"sealed":grant.sealed,"enforced":self.enforced(grant),"devices":grant.members.len()}),
        )
    }

    /// `/v1/grants/vouch`: a confirmed member admits a newcomer for a day.
    /// Vouched keys cannot vouch, and nothing here evicts or renews.
    fn vouch(&mut self, key: &str, body: &Value, now: u64) -> Result<Value> {
        shape(body, &["v", "grant", "add"])?;
        let token = text(body, "grant")?;
        let add = keys(body, "add", MAX_VOUCH)?;
        need(!add.is_empty(), 400, "Invalid request.")?;
        need(is_token(token), 403, EXPIRED)?;
        let id = hash(token);
        let grant = self
            .grants
            .get(&id)
            .filter(|grant| grant.expires > now && self.pairs.contains_key(&grant.pair))
            .ok_or(Refused(403, EXPIRED))?;
        // Indistinguishable from an expired grant to anyone else.
        need(grant.confirmed(key, now), 403, EXPIRED)?;
        // Every named key counts against every cap, listed already or not,
        // and the answer is the same either way, so vouching cannot be used
        // to learn which keys are registered. One message for every cap.
        let named = add.len();
        let sponsor = hash(key);
        let spent = grant.sponsors.get(&sponsor).map_or(0, |entry| entry.1);
        need(
            (grant.sponsors.contains_key(&sponsor) || grant.sponsors.len() < SPONSORS)
                && spent + named <= SPONSOR_VOUCHES
                && grant.vouched() + named <= MAX_VOUCHED
                && grant.members.len() + named <= MAX_MEMBERS
                && self.pairing_total(&grant.pair) + named <= MAX_PAIRING_MEMBERS
                && self.member_total() + named <= MAX_NODE_MEMBERS,
            429,
            BUSY,
        )?;
        let fresh: Vec<String> = add
            .into_iter()
            .filter(|key| grant.member(key).is_none())
            .collect();
        let grant = self
            .grants
            .get_mut(&id)
            .ok_or(Refused(503, "Unavailable."))?;
        let before = grant.members.len();
        for key in &fresh {
            grant.members.push((key.clone(), now + VOUCH_TTL, true));
        }
        if !fresh.is_empty() && self.save().is_err() {
            if let Some(grant) = self.grants.get_mut(&id) {
                grant.members.truncate(before);
            }
            return Err(Refused(503, "Call access could not be saved."));
        }
        let grant = self
            .grants
            .get_mut(&id)
            .ok_or(Refused(503, "Unavailable."))?;
        let entry = grant
            .sponsors
            .entry(sponsor)
            .or_insert((now + VOUCH_TTL, 0));
        entry.1 += named;
        Ok(json!({"v":1,"added":named}))
    }
}

#[derive(Deserialize)]
struct AuthEvent {
    kind: u32,
    created_at: u64,
    tags: Vec<Vec<String>>,
    content: String,
    pubkey: String,
    id: String,
    sig: String,
}

fn write_private(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let parent = path.parent().ok_or(std::io::ErrorKind::InvalidInput)?;
    if !parent.exists() {
        fs::create_dir_all(parent)?;
    }
    let info = fs::symlink_metadata(parent)?;
    if !info.is_dir() || info.file_type().is_symlink() {
        return Err(std::io::ErrorKind::PermissionDenied.into());
    }
    let suffix = token().map_err(|_| std::io::ErrorKind::Other)?;
    let temporary = parent.join(format!(".pairing-{suffix}.new"));
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let result = (|| {
        let mut file = options.open(&temporary)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        fs::rename(&temporary, path)?;
        fs::File::open(parent)?.sync_all()
    })();
    let _ = fs::remove_file(temporary);
    result
}
