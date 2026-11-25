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

/// Seconds a nonce stays acceptable after it is issued.
const NONCE_LIFETIME: u64 = 600;
/// Issued time (4 bytes), keyed check (8) and truncated HMAC tag (12).
const NONCE_BYTES: usize = 24;
/// Characters in the unpadded base64url form of `NONCE_BYTES`.
const NONCE_CHARS: usize = NONCE_BYTES / 3 * 4;
const CHECK_OFFSET: usize = 4;
const TAG_OFFSET: usize = 12;

/// SipHash-2-4 with a 64-bit output (Aumasson and Bernstein), over the
/// concatenation of the bytes written. It is used only as a cheap keyed
/// pre-check that selects a request budget; the HMAC tag is what validates a
/// nonce. Tests pin it to the published reference vectors.
struct SipHash24 {
    v: [u64; 4],
    tail: u64,
    filled: u32,
    length: u64,
}

impl SipHash24 {
    fn new(k0: u64, k1: u64) -> Self {
        Self {
            v: [
                k0 ^ 0x736f_6d65_7073_6575,
                k1 ^ 0x646f_7261_6e64_6f6d,
                k0 ^ 0x6c79_6765_6e65_7261,
                k1 ^ 0x7465_6462_7974_6573,
            ],
            tail: 0,
            filled: 0,
            length: 0,
        }
    }

    fn rounds(&mut self, count: usize) {
        let [mut v0, mut v1, mut v2, mut v3] = self.v;
        for _ in 0..count {
            v0 = v0.wrapping_add(v1);
            v1 = v1.rotate_left(13) ^ v0;
            v0 = v0.rotate_left(32);
            v2 = v2.wrapping_add(v3);
            v3 = v3.rotate_left(16) ^ v2;
            v0 = v0.wrapping_add(v3);
            v3 = v3.rotate_left(21) ^ v0;
            v2 = v2.wrapping_add(v1);
            v1 = v1.rotate_left(17) ^ v2;
            v2 = v2.rotate_left(32);
        }
        self.v = [v0, v1, v2, v3];
    }

    fn block(&mut self, word: u64) {
        self.v[3] ^= word;
        self.rounds(2);
        self.v[0] ^= word;
    }

    fn write(&mut self, mut bytes: &[u8]) {
        self.length = self.length.wrapping_add(bytes.len() as u64);
        while !bytes.is_empty() {
            if self.filled == 0 && bytes.len() >= 8 {
                let (word, rest) = bytes.split_at(8);
                self.block(u64::from_le_bytes(word.try_into().expect("8 bytes")));
                bytes = rest;
                continue;
            }
            self.tail |= u64::from(bytes[0]) << (8 * self.filled);
            self.filled += 1;
            bytes = &bytes[1..];
            if self.filled == 8 {
                let word = self.tail;
                self.tail = 0;
                self.filled = 0;
                self.block(word);
            }
        }
    }

    fn finish(mut self) -> u64 {
        self.block(self.tail | (self.length << 56));
        self.v[2] ^= 0xff;
        self.rounds(4);
        self.v[0] ^ self.v[1] ^ self.v[2] ^ self.v[3]
    }
}

/// SipHash-2-4 of the concatenated `parts`.
fn siphash24(keys: (u64, u64), parts: &[&[u8]]) -> u64 {
    let mut hash = SipHash24::new(keys.0, keys.1);
    for part in parts {
        hash.write(part);
    }
    hash.finish()
}

/// Nonces are 24 bytes, 32 characters: the issue time, a short keyed check
/// that a holder of the server key can verify in a few tens of nanoseconds,
/// and a truncated HMAC-SHA1 tag. The check lets a caller tell a nonce this
/// server issued for an address from any other value without computing an
/// HMAC; only `valid` is authoritative.
pub struct Nonces {
    mac: HmacSha1,
    check_keys: (u64, u64),
}

impl Nonces {
    /// The embedding host supplies cryptographically random key material.
    pub fn from_key(key: [u8; 32]) -> Self {
        let mac = HmacSha1::new_from_slice(&key).expect("fixed HMAC key");
        let mut derive = mac.clone();
        derive.update(b"spry-turn nonce check");
        let derived = derive.finalize().into_bytes();
        let word = |at: usize| u64::from_le_bytes(derived[at..at + 8].try_into().expect("8 bytes"));
        Self {
            mac,
            check_keys: (word(0), word(8)),
        }
    }

    #[cfg(feature = "runtime")]
    pub fn new() -> Result<Self, getrandom::Error> {
        let mut key = [0; 32];
        getrandom::fill(&mut key)?;
        Ok(Self::from_key(key))
    }

    fn input(ip: IpAddr) -> ([u8; 16], usize) {
        let mut octets = [0; 16];
        match ip {
            IpAddr::V4(ip) => {
                octets[..4].copy_from_slice(&ip.octets());
                (octets, 4)
            }
            IpAddr::V6(ip) => (ip.octets(), 16),
        }
    }

    fn check_value(&self, issued: &[u8], ip: IpAddr, realm: &str) -> u64 {
        let (octets, length) = Self::input(ip);
        siphash24(
            self.check_keys,
            &[issued, &octets[..length], realm.as_bytes()],
        )
    }

    fn mac(&self, issued: &[u8], ip: IpAddr, realm: &str) -> HmacSha1 {
        let (octets, length) = Self::input(ip);
        let mut mac = self.mac.clone();
        mac.update(issued);
        mac.update(&octets[..length]);
        mac.update(realm.as_bytes());
        mac
    }

    pub fn issue(&self, now: u64, ip: IpAddr, realm: &str) -> String {
        let issued = u32::try_from(now).unwrap_or(u32::MAX).to_be_bytes();
        let mut bytes = [0u8; NONCE_BYTES];
        bytes[..CHECK_OFFSET].copy_from_slice(&issued);
        bytes[CHECK_OFFSET..TAG_OFFSET]
            .copy_from_slice(&self.check_value(&issued, ip, realm).to_be_bytes());
        let tag = self.mac(&issued, ip, realm).finalize().into_bytes();
        bytes[TAG_OFFSET..].copy_from_slice(&tag[..NONCE_BYTES - TAG_OFFSET]);
        URL_SAFE_NO_PAD.encode(bytes)
    }

    /// Decodes `nonce` and accepts it if it is within its lifetime and its
    /// keyed check matches this address and realm. No HMAC is computed.
    fn decode(&self, nonce: &[u8], now: u64, ip: IpAddr, realm: &str) -> Option<[u8; NONCE_BYTES]> {
        let mut bytes = [0u8; NONCE_BYTES];
        if nonce.len() != NONCE_CHARS
            || URL_SAFE_NO_PAD.decode_slice(nonce, &mut bytes).ok() != Some(NONCE_BYTES)
        {
            return None;
        }
        let issued = u64::from(u32::from_be_bytes(
            bytes[..CHECK_OFFSET].try_into().expect("fixed slice"),
        ));
        let check = u64::from_be_bytes(
            bytes[CHECK_OFFSET..TAG_OFFSET]
                .try_into()
                .expect("fixed slice"),
        );
        (issued <= now
            && now - issued <= NONCE_LIFETIME
            && check == self.check_value(&bytes[..CHECK_OFFSET], ip, realm))
        .then_some(bytes)
    }

    /// Whether `nonce` looks like one this server issued for `ip` and
    /// `realm` and has not expired. A cheap keyed check with no HMAC, for
    /// classifying a request before it is admitted. It is not
    /// authentication: use `valid` for that.
    pub fn check(&self, nonce: &[u8], now: u64, ip: IpAddr, realm: &str) -> bool {
        self.decode(nonce, now, ip, realm).is_some()
    }

    pub fn valid(&self, nonce: &[u8], now: u64, ip: IpAddr, realm: &str) -> bool {
        self.decode(nonce, now, ip, realm).is_some_and(|bytes| {
            self.mac(&bytes[..CHECK_OFFSET], ip, realm)
                .verify_truncated_left(&bytes[TAG_OFFSET..])
                .is_ok()
        })
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

    /// SipHash-2-4 reference outputs for key 00..0f and the message
    /// 00..(n-1), as little-endian words. They are entries `n` of
    /// `vectors_sip64` in the reference implementation (`vectors.h` in
    /// github.com/veorq/SipHash). Entry 15 is also the paper's Appendix A
    /// vector.
    const SIPHASH_VECTORS: [(usize, u64); 8] = [
        (0, 0x726f_db47_dd0e_0e31),
        (1, 0x74f8_39c5_93dc_67fd),
        (7, 0xab02_00f5_8b01_d137),
        (8, 0x93f5_f579_9a93_2462),
        (15, 0xa129_ca61_49be_45e5),
        (16, 0x3f2a_cc7f_57c2_9bdb),
        (31, 0x32d8_92fa_d841_c342),
        (63, 0x958a_324c_eb06_4572),
    ];

    #[test]
    fn siphash_matches_the_reference_vectors() {
        let key: Vec<u8> = (0..16).collect();
        let keys = (
            u64::from_le_bytes(key[..8].try_into().unwrap()),
            u64::from_le_bytes(key[8..].try_into().unwrap()),
        );
        let message: Vec<u8> = (0..64).collect();
        for (length, expected) in SIPHASH_VECTORS {
            assert_eq!(siphash24(keys, &[&message[..length]]), expected, "{length}");
            // However the input is split between writes, the result is the same.
            for split in 0..=length {
                assert_eq!(
                    siphash24(keys, &[&message[..split], &[], &message[split..length]]),
                    expected,
                    "{length} split at {split}"
                );
            }
        }
    }

    #[test]
    fn nonce_check_agrees_with_validation() {
        let nonces = Nonces::from_key([7; 32]);
        let ip: IpAddr = "203.0.113.20".parse().unwrap();
        let other: IpAddr = "203.0.113.21".parse().unwrap();
        let value = nonces.issue(5000, ip, "realm");
        assert_eq!(value.len(), 32);
        assert!(nonces.check(value.as_bytes(), 5000, ip, "realm"));
        assert!(nonces.valid(value.as_bytes(), 5000, ip, "realm"));

        let flip = |index: usize| {
            let mut bytes = URL_SAFE_NO_PAD.decode(&value).unwrap();
            bytes[index] ^= 1;
            URL_SAFE_NO_PAD.encode(bytes)
        };
        // A changed check value fails both; a changed tag fails only `valid`.
        for index in CHECK_OFFSET..TAG_OFFSET {
            let altered = flip(index);
            assert!(!nonces.check(altered.as_bytes(), 5000, ip, "realm"));
            assert!(!nonces.valid(altered.as_bytes(), 5000, ip, "realm"));
        }
        for index in TAG_OFFSET..NONCE_BYTES {
            let altered = flip(index);
            assert!(nonces.check(altered.as_bytes(), 5000, ip, "realm"));
            assert!(!nonces.valid(altered.as_bytes(), 5000, ip, "realm"));
        }
        // Another address, realm or key, an expired or future nonce, and
        // the wrong length fail both.
        for (nonce, now, ip, realm) in [
            (value.as_str(), 5000, other, "realm"),
            (value.as_str(), 5000, ip, "other"),
            (value.as_str(), 5601, ip, "realm"),
            (value.as_str(), 4999, ip, "realm"),
            (&value[1..], 5000, ip, "realm"),
            ("", 5000, ip, "realm"),
        ] {
            assert!(!nonces.check(nonce.as_bytes(), now, ip, realm));
            assert!(!nonces.valid(nonce.as_bytes(), now, ip, realm));
        }
        assert!(nonces.check(value.as_bytes(), 5600, ip, "realm"));
        let other_key = Nonces::from_key([8; 32]);
        assert!(!other_key.check(value.as_bytes(), 5000, ip, "realm"));
        assert!(!other_key.valid(value.as_bytes(), 5000, ip, "realm"));
        // IPv6 addresses are bound in full.
        let v6: IpAddr = "2001:db8::1".parse().unwrap();
        let issued = nonces.issue(5000, v6, "realm");
        assert!(nonces.valid(issued.as_bytes(), 5000, v6, "realm"));
        assert!(!nonces.check(
            issued.as_bytes(),
            5000,
            "2001:db8::2".parse().unwrap(),
            "realm"
        ));
    }
}
