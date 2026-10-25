//! Optional public mode: anonymous relay credentials and a Nostr advert.
//!
//! Off unless the operator sets `SPRY_PUBLIC=true`. There is no default
//! relay list, region or note, and nothing here reports to anyone: adverts
//! go only to the relays the operator names, and failures are retried on the
//! next cycle without being logged.
use crate::signalling::{self, RelayOptions};
use spry_link::{
    advert::{self, Offer},
    control::{ControlEndpoint, RelayPolicy},
    identity::{Event, Identity},
};
use std::{
    env, fmt,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};
use tokio::{task::JoinSet, time::timeout};

pub const REPUBLISH: Duration = Duration::from_secs(30 * 60);
pub const WITHDRAW_WAIT: Duration = Duration::from_secs(5);
const PUBLISH_WAIT: Duration = Duration::from_secs(20);
/// How often the publisher checks readiness.
const POLL: Duration = Duration::from_secs(1);

/// A configuration refusal that is safe to print: it names a setting, never
/// its value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SetupError(pub &'static str);
impl fmt::Display for SetupError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.0)
    }
}
impl std::error::Error for SetupError {}

pub const PRIVATE_PROFILE: SetupError = SetupError(
    "SPRY_PUBLIC=true needs the standard profile. The private-node profile relays only over peer links, so it cannot offer public relaying",
);
const RELAYS: SetupError =
    SetupError("SPRY_PUBLIC_RELAYS must be a JSON array of one to four distinct wss:// relay URLs");
const REGION: SetupError =
    SetupError("SPRY_PUBLIC_REGION must be two uppercase letters, such as GB");
const NOTE: SetupError =
    SetupError("SPRY_PUBLIC_NOTE must be at most 140 bytes with no control characters");
pub const ADVERT_ENDPOINT: SetupError = SetupError(
    "A public advert needs SPRY_PUBLIC_URL to be an https DNS hostname without a port or path",
);

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PublicSettings {
    pub enabled: bool,
    /// Empty: public but unlisted, or nothing to withdraw.
    pub relays: Vec<String>,
    pub region: Option<String>,
    pub note: Option<String>,
}
impl PublicSettings {
    /// Validates the raw values. Empty strings count as unset. Relays follow
    /// the same rules as `SPRY_CONTROL_RELAYS`.
    pub fn parse(
        public: Option<&str>,
        relays: Option<&str>,
        region: Option<&str>,
        note: Option<&str>,
        public_key: &str,
        policy: RelayPolicy,
    ) -> Result<Self, SetupError> {
        let set = |value: Option<&str>| value.filter(|value| !value.is_empty()).map(str::to_owned);
        let relays = match set(relays) {
            None => Vec::new(),
            Some(relays) => {
                let relays: Vec<String> = serde_json::from_str(&relays).map_err(|_| RELAYS)?;
                ControlEndpoint::new(public_key.into(), relays, policy)
                    .map_err(|_| RELAYS)?
                    .relays
            }
        };
        let region = set(region);
        if region
            .as_deref()
            .is_some_and(|region| !advert::region_valid(region))
        {
            return Err(REGION);
        }
        let note = set(note);
        if note
            .as_deref()
            .is_some_and(|note| !advert::note_valid(note))
        {
            return Err(NOTE);
        }
        Ok(Self {
            enabled: public == Some("true"),
            relays,
            region,
            note,
        })
    }
    pub fn from_environment(public_key: &str, policy: RelayPolicy) -> Result<Self, SetupError> {
        let read = |name: &str| env::var(name).ok();
        Self::parse(
            read("SPRY_PUBLIC").as_deref(),
            read("SPRY_PUBLIC_RELAYS").as_deref(),
            read("SPRY_PUBLIC_REGION").as_deref(),
            read("SPRY_PUBLIC_NOTE").as_deref(),
            public_key,
            policy,
        )
    }
}

/// Supplies the current offer, or `None` while the relay is not ready.
pub trait AdvertSource: Send + Sync + 'static {
    fn offer(&self) -> Option<Offer>;
}
impl<F: Fn() -> Option<Offer> + Send + Sync + 'static> AdvertSource for F {
    fn offer(&self) -> Option<Offer> {
        self()
    }
}

/// Each advert must be strictly newer than the last, or readers keeping the
/// replay watermark would ignore it. This matters for a withdrawal sent in
/// the same second as an open advert.
pub fn next_created_at(now: u64, last: u64) -> u64 {
    now.max(last.saturating_add(1))
}

async fn publish_all(
    relays: &[String],
    options: &RelayOptions,
    identity: &Arc<Identity>,
    event: &Event,
) {
    let mut tasks = JoinSet::new();
    for relay in relays {
        let (relay, options, identity, event) = (
            relay.clone(),
            options.clone(),
            identity.clone(),
            event.clone(),
        );
        tasks.spawn(async move {
            let _ = timeout(
                PUBLISH_WAIT,
                signalling::publish(&relay, &options, &identity, &event),
            )
            .await;
        });
    }
    while tasks.join_next().await.is_some() {}
}

/// Publishes a withdrawal, bounded by `wait`. Failures are not reported.
pub async fn withdraw(
    identity: Arc<Identity>,
    relays: &[String],
    options: &RelayOptions,
    created_at: u64,
    wait: Duration,
) -> Option<Event> {
    let event = advert::withdrawn(&identity, created_at).ok()?;
    let _ = timeout(wait, publish_all(relays, options, &identity, &event)).await;
    Some(event)
}

pub struct Publisher {
    identity: Arc<Identity>,
    relays: Vec<String>,
    options: RelayOptions,
    last: Arc<AtomicU64>,
    task: tokio::task::JoinHandle<()>,
}
impl Publisher {
    /// Publishes an open advert once the source is ready, then every
    /// [`REPUBLISH`], each time with a fresh `created_at` and `expiration`.
    /// If the source stops being ready, it publishes a newer withdrawal
    /// within [`WITHDRAW_WAIT`], then a fresh open advert once ready again.
    pub fn start(
        identity: Arc<Identity>,
        relays: Vec<String>,
        region: Option<String>,
        options: RelayOptions,
        source: Arc<dyn AdvertSource>,
    ) -> Self {
        let last = Arc::new(AtomicU64::new(0));
        let task = tokio::spawn({
            let (identity, relays, options, last) = (
                identity.clone(),
                relays.clone(),
                options.clone(),
                last.clone(),
            );
            async move {
                // When the open advert out there was published, if one is.
                let mut advertised: Option<tokio::time::Instant> = None;
                loop {
                    let Some(offer) = source.offer() else {
                        if advertised.take().is_some() {
                            let created_at =
                                next_created_at(crate::now(), last.load(Ordering::Acquire));
                            last.store(created_at, Ordering::Release);
                            withdraw(
                                identity.clone(),
                                &relays,
                                &options,
                                created_at,
                                WITHDRAW_WAIT,
                            )
                            .await;
                        }
                        tokio::time::sleep(POLL).await;
                        continue;
                    };
                    if advertised.is_some_and(|at| at.elapsed() < REPUBLISH) {
                        tokio::time::sleep(POLL).await;
                        continue;
                    }
                    let created_at = next_created_at(crate::now(), last.load(Ordering::Acquire));
                    // Recorded before sending, so a withdrawal is always newer.
                    last.store(created_at, Ordering::Release);
                    advertised = Some(tokio::time::Instant::now());
                    if let Ok(event) =
                        advert::open(&identity, &offer, region.as_deref(), created_at)
                    {
                        publish_all(&relays, &options, &identity, &event).await;
                    }
                }
            }
        });
        Self {
            identity,
            relays,
            options,
            last,
            task,
        }
    }
    /// Stops republishing, then publishes a newer withdrawal within `wait`.
    pub async fn shutdown(self, wait: Duration) -> Option<Event> {
        self.task.abort();
        let _ = self.task.await;
        let created_at = next_created_at(crate::now(), self.last.load(Ordering::Acquire));
        withdraw(self.identity, &self.relays, &self.options, created_at, wait).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> String {
        Identity::from_secret(&[1; 32]).unwrap().public_key()
    }

    fn parse(
        public: Option<&str>,
        relays: Option<&str>,
        region: Option<&str>,
        note: Option<&str>,
    ) -> Result<PublicSettings, SetupError> {
        PublicSettings::parse(public, relays, region, note, &key(), RelayPolicy::Public)
    }

    #[test]
    fn public_mode_is_off_without_an_exact_opt_in_and_has_no_defaults() {
        assert_eq!(parse(None, None, None, None), Ok(PublicSettings::default()));
        for value in ["", "1", "TRUE", "yes", "true "] {
            assert!(!parse(Some(value), None, None, None).unwrap().enabled);
        }
        let on = parse(Some("true"), None, None, None).unwrap();
        assert!(on.enabled && on.relays.is_empty() && on.region.is_none() && on.note.is_none());
        let empty = parse(Some("true"), Some(""), Some(""), Some("")).unwrap();
        assert_eq!(empty, on);
    }

    #[test]
    fn public_settings_use_the_control_relay_rules_and_bound_operator_text() {
        let full = parse(
            Some("true"),
            Some(r#"["wss://relay-b.example/","wss://relay-a.example/"]"#),
            Some("GB"),
            Some("Synthetic operator note"),
        )
        .unwrap();
        assert_eq!(
            full.relays,
            ["wss://relay-a.example/", "wss://relay-b.example/"]
        );
        assert_eq!(full.region.as_deref(), Some("GB"));
        for relays in [
            "[]",
            "wss://relay.example/",
            r#"["ws://relay.example/"]"#,
            r#"["wss://192.0.2.1/"]"#,
            r#"["wss://relay.local/"]"#,
            r#"["wss://user@relay.example/"]"#,
            r#"["wss://relay.example/?x=1"]"#,
            r#"["wss://relay.example/","wss://relay.example/"]"#,
            r#"["wss://a.example/","wss://b.example/","wss://c.example/","wss://d.example/","wss://e.example/"]"#,
        ] {
            assert_eq!(
                parse(Some("true"), Some(relays), None, None),
                Err(RELAYS),
                "{relays}"
            );
        }
        for region in ["gb", "G", "GBR", "G1", "É"] {
            assert_eq!(
                parse(Some("true"), None, Some(region), None),
                Err(REGION),
                "{region}"
            );
        }
        assert!(parse(None, None, None, Some(&"n".repeat(140))).is_ok());
        for note in [
            "n".repeat(141),
            "tab\there".into(),
            "bell\u{7}".into(),
            "\u{85}".into(),
        ] {
            assert_eq!(parse(Some("true"), None, None, Some(&note)), Err(NOTE));
        }
        let local = PublicSettings::parse(
            Some("true"),
            Some(r#"["ws://127.0.0.1:7000/"]"#),
            None,
            None,
            &key(),
            RelayPolicy::LocalFixture,
        );
        assert!(local.is_ok());
    }

    #[test]
    fn every_advert_is_strictly_newer_than_the_last() {
        assert_eq!(next_created_at(100, 0), 100);
        assert_eq!(next_created_at(100, 100), 101);
        assert_eq!(next_created_at(100, 150), 151);
        assert_eq!(next_created_at(200, 150), 200);
    }
}
