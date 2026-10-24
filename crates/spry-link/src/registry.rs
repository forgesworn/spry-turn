//! Expiring, scope-owned peer authorisation; callers supply already-authorised scopes.
use crate::{
    Refused, Result,
    identity::Event,
    peer::{MAX_PEERS, PeerCard, relay_alias},
};
use std::collections::{HashMap, HashSet};

#[derive(Clone)]
pub struct PeerRegistry {
    own: String,
    cards: HashMap<String, PeerCard>,
    scopes: HashMap<String, (u64, Vec<String>)>,
    revisions: HashMap<String, (u64, u64)>,
}
impl PeerRegistry {
    pub fn new(own: String) -> Result<Self> {
        relay_alias(&own)?;
        Ok(Self {
            own,
            cards: HashMap::new(),
            scopes: HashMap::new(),
            revisions: HashMap::new(),
        })
    }
    /// Apply a complete scope update atomically. Failed input preserves current authority.
    pub fn update(&mut self, scope: &str, events: &[Event], now: u64) -> Result<()> {
        if scope.is_empty()
            || scope.len() > 128
            || !scope
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b":_-".contains(&byte))
            || events.len() > MAX_PEERS
        {
            return Err(Refused::Size);
        }
        let mut next = self.clone();
        next.sweep(now);
        if events.is_empty() {
            next.scopes.remove(scope);
            *self = next;
            return Ok(());
        }
        if next.scopes.len() >= 64 && !next.scopes.contains_key(scope) {
            return Err(Refused::Overload);
        }
        let mut keys = Vec::new();
        let mut expiry = 0;
        for event in events {
            let card = PeerCard::verify(event.clone(), now)?;
            if card.event.pubkey == self.own || keys.contains(&card.event.pubkey) {
                return Err(Refused::Destination);
            }
            if let Some(previous) = next.cards.get(&card.event.pubkey) {
                if (&card.event.created_at, &card.event.id)
                    < (&previous.event.created_at, &previous.event.id)
                {
                    return Err(Refused::Replay);
                }
            } else if next.cards.len() >= 64 {
                return Err(Refused::Overload);
            }
            expiry = expiry.max(card.expires_at);
            keys.push(card.event.pubkey.clone());
            next.cards.insert(card.event.pubkey.clone(), card);
        }
        next.scopes.insert(scope.into(), (expiry, keys));
        let active = next.active(now);
        if active.len() > MAX_PEERS {
            return Err(Refused::Overload);
        }
        let mut aliases = HashSet::from([relay_alias(&self.own)?]);
        for card in active {
            if !aliases.insert(card.alias) {
                return Err(Refused::Collision);
            }
        }
        *self = next;
        Ok(())
    }
    /// Remember withdrawals beyond the control-event replay window. An old
    /// in-flight update cannot restore a scope after a newer empty update.
    pub fn update_revision(
        &mut self,
        scope: &str,
        revision: u64,
        events: &[Event],
        now: u64,
    ) -> Result<()> {
        let mut next = self.clone();
        next.sweep(now);
        if revision > 9_007_199_254_740_991
            || next
                .revisions
                .get(scope)
                .is_some_and(|(held, _)| revision <= *held)
        {
            return Err(Refused::Replay);
        }
        if next.revisions.len() >= 64 && !next.revisions.contains_key(scope) {
            return Err(Refused::Overload);
        }
        next.update(scope, events, now)?;
        next.revisions
            .insert(scope.into(), (revision, now.saturating_add(90)));
        *self = next;
        Ok(())
    }
    pub fn sweep(&mut self, now: u64) {
        self.revisions.retain(|_, (_, expiry)| *expiry > now);
        self.cards.retain(|_, card| card.expires_at > now);
        self.scopes.retain(|_, (expiry, _)| *expiry > now);
    }
    pub fn retain_scopes(&mut self, mut allowed: impl FnMut(&str) -> bool) {
        self.scopes.retain(|scope, _| allowed(scope));
    }
    pub fn active(&self, now: u64) -> Vec<PeerCard> {
        let keys: HashSet<&str> = self
            .scopes
            .values()
            .filter(|(expiry, _)| *expiry > now)
            .flat_map(|(_, keys)| keys.iter().map(String::as_str))
            .collect();
        let mut cards: Vec<_> = keys
            .into_iter()
            .filter_map(|key| self.cards.get(key))
            .filter(|card| card.expires_at > now)
            .cloned()
            .collect();
        cards.sort_by(|a, b| a.event.pubkey.cmp(&b.event.pubkey));
        cards
    }
}
