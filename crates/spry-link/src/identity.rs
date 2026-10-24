use crate::{MAX_EVENT, Refused, Result, hex, unhex};
use hmac::{Hmac, Mac};
use secp256k1::{
    Keypair, PublicKey, SecretKey, XOnlyPublicKey,
    ecdh::shared_secret_point,
    schnorr::{self, Signature},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// A transport identity separate from the operator's signing key.
pub struct Identity(Keypair);
impl Identity {
    pub fn from_secret(bytes: &[u8; 32]) -> Result<Self> {
        let secret = SecretKey::from_secret_bytes(*bytes).map_err(|_| Refused::Key)?;
        Ok(Self(Keypair::from_secret_key(&secret)))
    }
    pub fn derive(master: &[u8]) -> Result<Self> {
        if master.len() < 32 {
            return Err(Refused::Key);
        }
        let mut mac = Hmac::<Sha256>::new_from_slice(master).map_err(|_| Refused::Key)?;
        mac.update(b"spry-link-identity-v1");
        Self::from_secret(&mac.finalize().into_bytes().into())
    }
    pub fn public_key(&self) -> String {
        hex(&self.0.x_only_public_key().0.to_byte_array())
    }
    /// Unhashed ECDH x coordinate, as required by NIP-44.
    pub fn shared_secret(&self, other: &str) -> Result<[u8; 32]> {
        let x = unhex::<32>(other)?;
        let mut encoded = [0_u8; 33];
        encoded[0] = 2;
        encoded[1..].copy_from_slice(&x);
        let public = PublicKey::from_byte_array_compressed(encoded).map_err(|_| Refused::Key)?;
        let shared = shared_secret_point(&public, &self.0.secret_key());
        shared[..32].try_into().map_err(|_| Refused::Key)
    }
    pub fn sign(
        &self,
        kind: u16,
        tags: Vec<Vec<String>>,
        content: String,
        now: u64,
    ) -> Result<Event> {
        let mut event = Event {
            id: String::new(),
            pubkey: self.public_key(),
            created_at: now,
            kind,
            tags,
            content,
            sig: String::new(),
        };
        event.validate_shape()?;
        let digest = event.digest()?;
        let mut auxiliary = [0_u8; 32];
        getrandom::fill(&mut auxiliary).map_err(|_| Refused::Key)?;
        event.id = hex(&digest);
        event.sig = hex(&schnorr::sign_with_aux_rand(&digest, &self.0, &auxiliary).to_byte_array());
        Ok(event)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Event {
    pub id: String,
    pub pubkey: String,
    pub created_at: u64,
    pub kind: u16,
    pub tags: Vec<Vec<String>>,
    pub content: String,
    pub sig: String,
}
impl Event {
    fn validate_shape(&self) -> Result<()> {
        if self.content.len() > MAX_EVENT - 1024
            || self.tags.len() > 8
            || self.tags.iter().any(|tag| {
                tag.is_empty() || tag.len() > 3 || tag.iter().any(|value| value.len() > 256)
            })
        {
            return Err(Refused::Size);
        }
        Ok(())
    }
    fn digest(&self) -> Result<[u8; 32]> {
        let canonical = serde_json::to_vec(&serde_json::json!([
            0,
            self.pubkey,
            self.created_at,
            self.kind,
            self.tags,
            self.content
        ]))
        .map_err(|_| Refused::Encoding)?;
        Ok(Sha256::digest(canonical).into())
    }
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > MAX_EVENT {
            return Err(Refused::Size);
        }
        let event: Self = serde_json::from_slice(bytes).map_err(|_| Refused::Encoding)?;
        event.verify()?;
        Ok(event)
    }
    pub fn verify(&self) -> Result<()> {
        self.validate_shape()?;
        let digest = self.digest()?;
        if unhex::<32>(&self.id)? != digest {
            return Err(Refused::Authentication);
        }
        let key = XOnlyPublicKey::from_byte_array(unhex::<32>(&self.pubkey)?)
            .map_err(|_| Refused::Key)?;
        let signature = Signature::from_byte_array(unhex::<64>(&self.sig)?);
        schnorr::verify(&signature, &digest, &key).map_err(|_| Refused::Authentication)
    }
    pub fn tag(&self, name: &str) -> Result<&str> {
        let mut matches = self
            .tags
            .iter()
            .filter(|tag| tag.first().is_some_and(|value| value == name));
        let tag = matches.next().ok_or(Refused::Destination)?;
        if tag.len() != 2 || matches.next().is_some() {
            return Err(Refused::Destination);
        }
        Ok(&tag[1])
    }
    pub fn addressed_to(&self, recipient: &str, kind: u16, now: u64) -> Result<()> {
        if self.kind != kind || self.tag("p")? != recipient {
            return Err(Refused::Destination);
        }
        let expiry: u64 = self
            .tag("expiration")?
            .parse()
            .map_err(|_| Refused::Expired)?;
        if self.created_at.abs_diff(now) > 60
            || expiry <= now
            || expiry > now.saturating_add(90)
            || expiry > self.created_at.saturating_add(30)
        {
            return Err(Refused::Expired);
        }
        self.verify()
    }
}
