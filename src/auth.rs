//! TURN REST credentials and stateless, address-bound server nonces.
use base64::{
    Engine,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use hmac::{Hmac, Mac};
use md5::{Digest, Md5};
use sha1::Sha1;
use std::net::IpAddr;

type HmacSha1 = Hmac<Sha1>;

pub fn credential(secret: &[u8], username: &str) -> String {
    let mut mac = HmacSha1::new_from_slice(secret).expect("HMAC accepts any key length");
    mac.update(username.as_bytes());
    STANDARD.encode(mac.finalize().into_bytes())
}

pub fn key(username: &str, realm: &str, password: &str) -> [u8; 16] {
    let mut hash = Md5::new();
    hash.update(username.as_bytes());
    hash.update(b":");
    hash.update(realm.as_bytes());
    hash.update(b":");
    hash.update(password.as_bytes());
    hash.finalize().into()
}

pub fn expires(username: &str) -> Option<u64> {
    let (expiry, label) = username.split_once(':')?;
    if label.is_empty() || username.len() > 256 {
        return None;
    }
    expiry.parse().ok()
}

pub struct Nonces {
    key: [u8; 32],
}

impl Nonces {
    /// The embedding host supplies cryptographically random key material.
    pub fn from_key(key: [u8; 32]) -> Self {
        Self { key }
    }

    #[cfg(feature = "runtime")]
    pub fn new() -> Result<Self, getrandom::Error> {
        let mut key = [0; 32];
        getrandom::fill(&mut key)?;
        Ok(Self { key })
    }

    fn mac(&self, timestamp: &[u8], ip: IpAddr, realm: &str) -> HmacSha1 {
        let mut mac = HmacSha1::new_from_slice(&self.key).expect("fixed HMAC key");
        mac.update(timestamp);
        match ip {
            IpAddr::V4(ip) => mac.update(&ip.octets()),
            IpAddr::V6(ip) => mac.update(&ip.octets()),
        }
        mac.update(realm.as_bytes());
        mac
    }

    pub fn issue(&self, now: u64, ip: IpAddr, realm: &str) -> String {
        let mut bytes = [0u8; 28];
        bytes[..8].copy_from_slice(&now.to_be_bytes());
        let tag = self.mac(&bytes[..8], ip, realm).finalize().into_bytes();
        bytes[8..].copy_from_slice(&tag);
        URL_SAFE_NO_PAD.encode(bytes)
    }

    pub fn valid(&self, nonce: &[u8], now: u64, ip: IpAddr, realm: &str) -> bool {
        let mut bytes = [0u8; 28];
        if URL_SAFE_NO_PAD.decode_slice(nonce, &mut bytes).ok() != Some(28) {
            return false;
        }
        let issued = u64::from_be_bytes(bytes[..8].try_into().expect("fixed slice"));
        issued <= now
            && now - issued <= 600
            && self
                .mac(&bytes[..8], ip, realm)
                .verify_slice(&bytes[8..])
                .is_ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn nonces_expire_and_bind_to_address_and_realm() {
        let nonces = Nonces::from_key([1; 32]);
        let ip = "127.0.0.1".parse().unwrap();
        let value = nonces.issue(1000, ip, "test");
        assert!(nonces.valid(value.as_bytes(), 1600, ip, "test"));
        assert!(!nonces.valid(value.as_bytes(), 1601, ip, "test"));
        assert!(!nonces.valid(value.as_bytes(), 999, ip, "test"));
        assert!(!nonces.valid(value.as_bytes(), 1000, "127.0.0.2".parse().unwrap(), "test"));
        assert!(!nonces.valid(value.as_bytes(), 1000, ip, "other"));
    }
}
