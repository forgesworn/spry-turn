//! Strict standard profile for a keeper-controlled node. The HTTP authority
//! and packet loop share a live username allowlist; no polling file or room
//! key crosses into the packet relay.
use crate::node::ServiceState;
use serde_json::{Value, json};
use spry_access::{Authority, Refused, Result};
use spry_turn::turn::{CredentialAuthorizer, Server};
use std::{
    collections::HashMap,
    sync::{
        Arc, Mutex, RwLock,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

const MAX_ISSUED: usize = 16_384;
pub(crate) const LEASE_SECONDS: u64 = 15;
struct Issued {
    token: String,
    device: String,
    expires: u64,
}
#[derive(Default)]
struct View {
    lease: Option<Instant>,
    users: HashMap<String, u64>,
    limits: HashMap<(String, String), u64>,
}

pub(crate) struct Policy {
    pairing: String,
    view: Arc<RwLock<View>>,
    issued: Mutex<HashMap<String, Issued>>,
    healthy: Arc<AtomicBool>,
    pub allocations: AtomicU64,
    pub forwarded_bytes: AtomicU64,
}

impl Policy {
    pub fn deadline(&self, key: &str, body: &Value, now: u64) -> Result<u64> {
        let token = body["grant"]
            .as_str()
            .ok_or(Refused(403, "Call access has expired."))?;
        self.view
            .read()
            .map_err(|_| Refused(503, "Unavailable."))?
            .limits
            .get(&(token.into(), key.into()))
            .copied()
            .filter(|end| *end > now)
            .ok_or(Refused(403, "Call access has expired."))
    }
    pub fn new(pairing: String) -> Self {
        Self {
            pairing,
            view: Arc::new(RwLock::new(View::default())),
            issued: Mutex::new(HashMap::new()),
            healthy: Arc::new(AtomicBool::new(true)),
            allocations: AtomicU64::new(0),
            forwarded_bytes: AtomicU64::new(0),
        }
    }
    fn live(&self) -> bool {
        self.view
            .read()
            .is_ok_and(|view| view.lease.is_some_and(|until| until > Instant::now()))
    }
    pub fn status(&self, ready: bool) -> Value {
        json!({"v":1,"ready":ready,"leaseActive":self.live(),
            "allocations":self.allocations.load(Ordering::Relaxed),
            "forwardedBytes":self.forwarded_bytes.load(Ordering::Relaxed)})
    }
    pub fn authorizer(&self) -> CredentialAuthorizer {
        let view = self.view.clone();
        let healthy = self.healthy.clone();
        Arc::new(move |username| {
            healthy.load(Ordering::Acquire)
                && view.read().is_ok_and(|view| {
                    view.lease.is_some_and(|until| until > Instant::now())
                        && view
                            .users
                            .get(username)
                            .is_some_and(|expires| *expires > crate::now())
                })
        })
    }
    pub fn before(
        &self,
        authority: &Authority,
        key: &str,
        path: &str,
        body: &Value,
        now: u64,
    ) -> Result<Option<Value>> {
        match path {
            "/v1/credentials" => {
                if !self.live() {
                    return Err(Refused(503, "The room's node is reconnecting."));
                }
                Ok(None)
            }
            "/v1/grants" | "/v1/grants/devices" | "/v1/grants/remove" | "/v1/node/lease"
            | "/v1/node/status" => {
                if !authority.pairing_authorises(&self.pairing, key)
                    || body.get("pairing").and_then(Value::as_str) != Some(self.pairing.as_str())
                {
                    return Err(Refused(403, "Approval required."));
                }
                if path == "/v1/grants/devices" {
                    let adds = body["add"].as_array().is_some_and(|keys| !keys.is_empty());
                    if (adds || body.get("expiration").is_some())
                        && body["expiration"]
                            .as_u64()
                            .is_none_or(|end| end <= now || end > now.saturating_add(90 * 86400))
                    {
                        return Err(Refused(
                            400,
                            "A node registration needs its signed grant expiration.",
                        ));
                    }
                }
                if path == "/v1/node/lease" || path == "/v1/node/status" {
                    if body.as_object().is_none_or(|body| body.len() != 2)
                        || body.get("v") != Some(&json!(1))
                    {
                        return Err(Refused(400, "Invalid request."));
                    }
                    if path == "/v1/node/lease" {
                        let mut view = self
                            .view
                            .write()
                            .map_err(|_| Refused(503, "Unavailable."))?;
                        // A restarted desk must reconcile before its first lease.
                        // An old elapsed lease never brings old usernames back.
                        if view.lease.is_none_or(|until| until <= Instant::now()) {
                            view.users.clear();
                            self.issued
                                .lock()
                                .map_err(|_| Refused(503, "Unavailable."))?
                                .clear();
                        }
                        view.lease = Some(Instant::now() + Duration::from_secs(LEASE_SECONDS));
                        return Ok(Some(json!({"v":1,"leaseSeconds":LEASE_SECONDS})));
                    }
                    return Ok(Some(self.status(authority.config.ready)));
                }
                Ok(None)
            }
            _ => Err(Refused(403, "This node is controlled by its keeper.")),
        }
    }
    pub fn synchronise(
        &self,
        authority: &Authority,
        key: &str,
        path: &str,
        body: &Value,
        answer: &Value,
        now: u64,
    ) -> Result<()> {
        let mut issued = self.issued.lock().map_err(|_| {
            self.healthy.store(false, Ordering::Release);
            Refused(503, "Unavailable.")
        })?;
        let mut view = self
            .view
            .write()
            .map_err(|_| Refused(503, "Unavailable."))?;
        if path == "/v1/grants/devices" {
            let token = body["grant"]
                .as_str()
                .ok_or(Refused(400, "Invalid request."))?;
            if let Some(keys) = body["add"].as_array() {
                for key in keys {
                    let device = key.as_str().ok_or(Refused(400, "Invalid request."))?;
                    let expiration = body["expiration"]
                        .as_u64()
                        .ok_or(Refused(400, "Invalid request."))?;
                    view.limits
                        .insert((token.into(), device.into()), expiration);
                }
            }
        }
        view.limits.retain(|(token, device), end| {
            *end > now && authority.credential_access(token, device, now)
        });
        issued.retain(|_, entry| {
            entry.expires > now
                && view
                    .limits
                    .get(&(entry.token.clone(), entry.device.clone()))
                    .is_some_and(|end| *end > now)
        });
        if path == "/v1/credentials" {
            let username = answer["username"]
                .as_str()
                .ok_or(Refused(503, "Unavailable."))?;
            if issued.len() >= MAX_ISSUED && !issued.contains_key(username) {
                return Err(Refused(429, "Too many active logins."));
            }
            issued.insert(
                username.into(),
                Issued {
                    token: body["grant"]
                        .as_str()
                        .ok_or(Refused(400, "Invalid request."))?
                        .into(),
                    device: key.into(),
                    expires: answer["expiresAt"]
                        .as_u64()
                        .ok_or(Refused(503, "Unavailable."))?,
                },
            );
        }
        view.users = issued
            .iter()
            .filter_map(|(username, entry)| {
                view.limits
                    .get(&(entry.token.clone(), entry.device.clone()))
                    .map(|end| (username.clone(), entry.expires.min(*end)))
            })
            .collect();
        self.healthy.store(true, Ordering::Release);
        Ok(())
    }
}

pub(crate) struct Relay {
    running: Arc<AtomicBool>,
    thread: Option<thread::JoinHandle<()>>,
}
impl Relay {
    pub fn start(
        mut config: spry_turn::turn::Config,
        state: Arc<ServiceState>,
        policy: Arc<Policy>,
    ) -> std::io::Result<Self> {
        config.credential_authorizer = Some(policy.authorizer());
        let mut server = Server::bind(config)?;
        state
            .lock()
            .map_err(|_| std::io::Error::other("Authority unavailable"))?
            .config
            .ready = true;
        let failed = state.clone();
        let running = Arc::new(AtomicBool::new(true));
        let active = running.clone();
        let thread = thread::Builder::new()
            .name("spry-node-turn".into())
            .spawn(move || {
                while active.load(Ordering::Acquire) {
                    if server.poll_once(Duration::from_millis(50)).is_err() {
                        break;
                    }
                    policy
                        .allocations
                        .store(server.allocation_count() as u64, Ordering::Relaxed);
                    policy
                        .forwarded_bytes
                        .store(server.stats().forwarded_bytes, Ordering::Relaxed);
                }
                if let Ok(mut authority) = state.lock() {
                    authority.config.ready = false;
                }
            })
            .inspect_err(|_| {
                if let Ok(mut authority) = failed.lock() {
                    authority.config.ready = false;
                }
            })?;
        Ok(Self {
            running,
            thread: Some(thread),
        })
    }
}
impl Drop for Relay {
    fn drop(&mut self) {
        self.running.store(false, Ordering::Release);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use spry_access::{Config, Seal};
    use spry_link::identity::Identity;

    fn key(seed: u8) -> String {
        Identity::derive(&[seed; 32]).unwrap().public_key()
    }
    fn fixture() -> (ServiceState, String, String) {
        let keeper = key(1);
        let mut config = Config::new(
            "https://relay.example",
            "https://calls.example/j/",
            &keeper,
            b"synthetic-test-secret-not-for-deployment",
            None,
        )
        .unwrap();
        config.ready = true;
        config.seal = Seal::Required;
        let mut authority = Authority::new(config);
        authority.set_vouching(false);
        let pairing = authority.trust_pairing(&keeper, crate::now()).unwrap();
        (
            ServiceState::node(authority, pairing.clone()),
            pairing,
            keeper,
        )
    }
    fn grant(state: &ServiceState, pairing: &str, keeper: &str, scope: u8, device: &str) -> String {
        let offer = state
            .api(
                keeper,
                "/v1/grants",
                &json!({"pairing":pairing,"scope":format!("{scope:02x}").repeat(32)}),
                crate::now(),
            )
            .unwrap();
        let token = offer["token"].as_str().unwrap().to_owned();
        state.api(keeper, "/v1/grants/devices", &json!({"v":1,"pairing":pairing,"grant":token,"revision":1,"add":[device],"remove":[],"seal":true,"expiration":crate::now()+3600}), crate::now()).unwrap();
        token
    }
    fn lease(state: &ServiceState, pairing: &str, keeper: &str) {
        state
            .api(
                keeper,
                "/v1/node/lease",
                &json!({"v":1,"pairing":pairing}),
                crate::now(),
            )
            .unwrap();
    }

    #[test]
    fn cached_credentials_are_revoked_per_room_and_unlisted_devices_stay_out() {
        let (state, pairing, keeper) = fixture();
        let device = key(2);
        let first = grant(&state, &pairing, &keeper, 1, &device);
        let second = grant(&state, &pairing, &keeper, 2, &device);
        assert_eq!(
            state
                .api(
                    &device,
                    "/v1/credentials",
                    &json!({"grant":first}),
                    crate::now()
                )
                .unwrap_err()
                .0,
            503
        );
        lease(&state, &pairing, &keeper);
        assert_eq!(
            state
                .api(
                    &key(3),
                    "/v1/credentials",
                    &json!({"grant":first}),
                    crate::now()
                )
                .unwrap_err()
                .0,
            403
        );
        let a = state
            .api(
                &device,
                "/v1/credentials",
                &json!({"grant":first}),
                crate::now(),
            )
            .unwrap();
        let b = state
            .api(
                &device,
                "/v1/credentials",
                &json!({"grant":second}),
                crate::now(),
            )
            .unwrap();
        let allow = state.node_policy.as_ref().unwrap().authorizer();
        assert!(allow(a["username"].as_str().unwrap()));
        assert!(allow(b["username"].as_str().unwrap()));
        state.api(&keeper, "/v1/grants/devices", &json!({"v":1,"pairing":pairing,"grant":first,"revision":2,"add":[],"remove":[device],"seal":true}), crate::now()).unwrap();
        assert!(!allow(a["username"].as_str().unwrap()));
        assert!(allow(b["username"].as_str().unwrap()));
        assert_eq!(
            state
                .api(
                    &device,
                    "/v1/credentials",
                    &json!({"grant":first}),
                    crate::now()
                )
                .unwrap_err()
                .0,
            403
        );
        state
            .api(
                &keeper,
                "/v1/grants/remove",
                &json!({"pairing":pairing,"grant":second}),
                crate::now(),
            )
            .unwrap();
        assert!(!allow(b["username"].as_str().unwrap()));
    }

    #[test]
    fn node_refuses_vouching_and_new_pairings_and_status_has_only_counts() {
        let (state, pairing, keeper) = fixture();
        for path in [
            "/v1/grants/vouch",
            "/v1/pairings",
            "/v1/pairings/claim",
            "/v1/pairings/remove",
        ] {
            assert_eq!(
                state
                    .api(&keeper, path, &json!({}), crate::now())
                    .unwrap_err()
                    .0,
                403
            );
        }
        for path in ["/v1/node/lease", "/v1/node/status"] {
            assert_eq!(
                state
                    .api(
                        &key(3),
                        path,
                        &json!({"v":1,"pairing":pairing}),
                        crate::now()
                    )
                    .unwrap_err()
                    .0,
                403
            );
        }
        let status = state
            .api(
                &keeper,
                "/v1/node/status",
                &json!({"v":1,"pairing":pairing}),
                crate::now(),
            )
            .unwrap();
        assert_eq!(
            status,
            json!({"v":1,"ready":true,"leaseActive":false,"allocations":0,"forwardedBytes":0})
        );
    }

    #[test]
    fn a_lapsed_desk_lease_cannot_resurrect_cached_credentials() {
        let (state, pairing, keeper) = fixture();
        let device = key(2);
        let token = grant(&state, &pairing, &keeper, 1, &device);
        lease(&state, &pairing, &keeper);
        let answer = state
            .api(
                &device,
                "/v1/credentials",
                &json!({"grant":token}),
                crate::now(),
            )
            .unwrap();
        let policy = state.node_policy.as_ref().unwrap();
        let allow = policy.authorizer();
        let username = answer["username"].as_str().unwrap();
        assert!(allow(username));
        policy.view.write().unwrap().lease = Some(Instant::now() - Duration::from_secs(1));
        assert!(!allow(username));
        lease(&state, &pairing, &keeper);
        assert!(!allow(username));
        // A reconciliation request must not repopulate the old issuance map.
        state
            .api(
                &keeper,
                "/v1/grants",
                &json!({"pairing":pairing,"scope":"01".repeat(32)}),
                crate::now(),
            )
            .unwrap();
        assert!(!allow(username));
        let fresh = state
            .api(
                &device,
                "/v1/credentials",
                &json!({"grant":token}),
                crate::now(),
            )
            .unwrap();
        assert_ne!(fresh["username"], answer["username"]);
        assert!(!allow(username));
        assert!(allow(fresh["username"].as_str().unwrap()));
    }

    #[test]
    fn credential_lifetime_never_outlives_the_signed_device_grant() {
        let (state, pairing, keeper) = fixture();
        let device = key(2);
        let token = grant(&state, &pairing, &keeper, 1, &device);
        let at = crate::now();
        let expiration = at + 30;
        state.api(&keeper,"/v1/grants/devices",&json!({"v":1,"pairing":pairing,"grant":token,"revision":2,"add":[device],"remove":[],"seal":true,"expiration":expiration}),at).unwrap();
        lease(&state, &pairing, &keeper);
        let answer = state
            .api(&device, "/v1/credentials", &json!({"grant":token}), at)
            .unwrap();
        assert_eq!(answer["expiresAt"], expiration);
        assert_eq!(answer["accessExpiresAt"], expiration);
        assert!(
            answer["username"]
                .as_str()
                .unwrap()
                .starts_with(&format!("{expiration}:"))
        );
        assert_eq!(
            state
                .api(
                    &device,
                    "/v1/credentials",
                    &json!({"grant":token}),
                    expiration
                )
                .unwrap_err()
                .0,
            403
        );
    }
}
