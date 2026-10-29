//! Signed `spry-standard-v1` node cards for standard-profile nodes reached
//! through the `spry:` control channel.
//!
//! A standard card proves only that the control key answering a room grant
//! belongs to a standard-profile node. It carries no address: the node's TURN
//! URLs travel in the encrypted credential answer, never in a card a client
//! might copy into a room descriptor. It is never a private mesh route;
//! [`crate::peer::PeerCard::verify`] refuses it, and [`StandardCard::verify`]
//! refuses a peer card.
use crate::{
    Refused, Result,
    identity::{Event, Identity},
    peer::CARD_KIND,
};

pub const PROFILE: &str = "spry-standard-v1";
/// A card lives ten minutes, as a peer card does.
pub const CARD_TTL: u64 = 600;

#[derive(Clone, Debug)]
pub struct StandardCard {
    pub event: Event,
    pub expires_at: u64,
}
impl StandardCard {
    fn content() -> String {
        serde_json::json!({"v":1,"profile":PROFILE}).to_string()
    }
    fn tags(now: u64) -> Vec<Vec<String>> {
        vec![vec![
            "expiration".into(),
            now.saturating_add(CARD_TTL).to_string(),
        ]]
    }
    pub fn sign(identity: &Identity, now: u64) -> Result<Self> {
        Self::verify(
            identity.sign(CARD_KIND, Self::tags(now), Self::content(), now)?,
            now,
        )
    }
    /// Reproducible signing for synthetic vectors only.
    pub fn sign_with_aux(identity: &Identity, now: u64, auxiliary: &[u8; 32]) -> Result<Self> {
        Self::verify(
            identity.sign_with_aux(CARD_KIND, Self::tags(now), Self::content(), now, auxiliary)?,
            now,
        )
    }
    /// Kind 24183, signed, unexpired, content exactly
    /// `{"v":1,"profile":"spry-standard-v1"}` and one expiration tag.
    pub fn verify(event: Event, now: u64) -> Result<Self> {
        if event.kind != CARD_KIND
            || event.created_at > now.saturating_add(60)
            || event.content.len() > 256
            || event.tags.len() != 1
        {
            return Err(Refused::Destination);
        }
        event.verify()?;
        let expires_at: u64 = event
            .tag("expiration")?
            .parse()
            .map_err(|_| Refused::Expired)?;
        if expires_at <= now
            || expires_at > now.saturating_add(CARD_TTL + 60)
            || expires_at > event.created_at.saturating_add(CARD_TTL)
        {
            return Err(Refused::Expired);
        }
        let content: serde_json::Value =
            serde_json::from_str(&event.content).map_err(|_| Refused::Encoding)?;
        let fields = content.as_object().ok_or(Refused::Encoding)?;
        if fields.len() != 2 || content["v"] != 1 || content["profile"] != PROFILE {
            return Err(Refused::Encoding);
        }
        Ok(Self { event, expires_at })
    }
}
