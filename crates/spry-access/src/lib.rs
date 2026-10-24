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
use k256::schnorr::{Signature, VerifyingKey};
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
pub type Result<T> = std::result::Result<T, Refused>;
#[derive(Debug)]
pub struct Refused(pub u16, pub &'static str);
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

pub struct Config {
    pub endpoint: String,
    pub app: String,
    pub owners: HashSet<String>,
    pub origins: HashSet<String>,
    pub urls: Vec<String>,
    pub state_file: Option<PathBuf>,
    secret: Vec<u8>,
    pub ready: bool,
    pub readiness: &'static str,
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
            app: app_url.to_string(),
            owners,
            origins,
            urls,
            state_file,
            secret: secret.to_vec(),
            ready: false,
            readiness: "Your node needs public access before Spry can connect calls.",
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
}
pub struct Authority {
    pub config: Config,
    pairs: HashMap<String, Pairing>,
    pending: HashMap<String, u64>,
    grants: HashMap<String, Grant>,
    replays: HashMap<String, u64>,
    rates: HashMap<String, (u64, u16)>,
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
        }
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
            info.is_file() && !info.file_type().is_symlink() && info.len() <= 131_072,
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
                && state.pairs.len() <= 16
                && state.grants.len() <= 64
                && state
                    .grants
                    .iter()
                    .all(|g| is_token(&g.pair) && is_key(&g.scope) && is_token(&g.salt))
                && state
                    .pairs
                    .iter()
                    .all(|p| is_token(&p.id) && is_key(&p.key)),
            503,
            "Pairings could not be read.",
        )?;
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
        })
        .map_err(|_| Refused(503, "Pairing could not be saved."))?;
        write_private(path, &bytes).map_err(|_| Refused(503, "Pairing could not be saved."))
    }
    pub fn sweep(&mut self, now: u64) {
        self.pending.retain(|_, until| *until > now);
        self.grants
            .retain(|_, grant| grant.expires > now && self.pairs.contains_key(&grant.pair));
        for grant in self.grants.values_mut() {
            grant.devices.retain(|_, until| *until > now);
        }
        self.replays.retain(|_, until| *until >= now);
        self.rates.retain(|_, (until, _)| *until > now);
    }
    pub fn rate(&mut self, address: &str, now: u64) -> Result<()> {
        self.sweep(now);
        let id = hash(address);
        need(
            self.rates.contains_key(&id) || self.rates.len() < 256,
            429,
            "Spry is busy. Try again shortly.",
        )?;
        let entry = self.rates.entry(id).or_insert((now + 60, 0));
        entry.1 = entry.1.saturating_add(1);
        need(entry.1 <= 120, 429, "Too many requests. Try again shortly.")
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
        let key = VerifyingKey::from_bytes(&unhex(&event.pubkey)?)
            .map_err(|_| Refused(401, "Approval required."))?;
        let sig = Signature::try_from(unhex(&event.sig)?.as_slice())
            .map_err(|_| Refused(401, "Approval required."))?;
        key.verify_raw(&id, &sig)
            .map_err(|_| Refused(401, "Approval required."))?;
        need(
            self.replays.len() < 4096,
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
                let payload = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&json!({"v":1,"endpoint":self.config.endpoint,"code":code,"expiresAt":expires})).map_err(|_| Refused(503, "Pairing could not be prepared."))?);
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
                Ok(json!({"version":1,"id":pair.id,"endpoint":self.config.endpoint}))
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
                if self.save().is_err() {
                    if let Some(old) = old {
                        self.pairs.insert(id.into(), old);
                    }
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
                        json!({"v":1,"endpoint":self.config.endpoint,"token":grant.token,"expiresAt":grant.expires}),
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
                let result = json!({"v":1,"endpoint":self.config.endpoint,"token":token,"expiresAt":now + GRANT_TTL});
                self.grants.insert(
                    id.clone(),
                    Grant {
                        pair: pair.into(),
                        scope: scope.into(),
                        salt,
                        token,
                        expires: now + GRANT_TTL,
                        devices: HashMap::new(),
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
            "/v1/credentials" => {
                let token = text(body, "grant")?;
                need(is_token(token), 403, "Call access has expired.")?;
                let id = hash(token);
                let grant = self
                    .grants
                    .get_mut(&id)
                    .ok_or(Refused(403, "Call access has expired."))?;
                need(
                    grant.expires > now && self.pairs.contains_key(&grant.pair),
                    403,
                    "Call access has expired.",
                )?;
                need(
                    grant.devices.contains_key(key) || grant.devices.len() < 32,
                    429,
                    "This call has reached its device limit.",
                )?;
                grant.devices.insert(key.into(), now + 600);
                let old = grant.expires;
                if old - now < GRANT_TTL - 86400 {
                    grant.expires = now + GRANT_TTL;
                }
                let access_expires = grant.expires;
                let expires = (now + 300).min(access_expires);
                if old != access_expires && self.save().is_err() {
                    self.grants
                        .get_mut(&id)
                        .ok_or(Refused(503, "Unavailable."))?
                        .expires = old;
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
