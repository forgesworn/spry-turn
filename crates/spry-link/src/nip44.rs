//! Bounded NIP-44 v2 protocol glue over RustCrypto primitives.
use crate::{MAX_PLAINTEXT, Refused, Result, identity::Identity};
use base64::{Engine, engine::general_purpose::STANDARD};
use chacha20::{
    ChaCha20,
    cipher::{KeyIvInit, StreamCipher},
};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::Sha256;

pub fn conversation_key(identity: &Identity, peer: &str) -> Result<[u8; 32]> {
    let (key, _) = Hkdf::<Sha256>::extract(Some(b"nip44-v2"), &identity.shared_secret(peer)?);
    Ok(key.into())
}
fn keys(key: &[u8; 32], nonce: &[u8; 32]) -> Result<[u8; 76]> {
    let mut keys = [0; 76];
    Hkdf::<Sha256>::from_prk(key)
        .map_err(|_| Refused::Key)?
        .expand(nonce, &mut keys)
        .map_err(|_| Refused::Key)?;
    Ok(keys)
}
pub fn padded_len(length: usize) -> Result<usize> {
    if !(1..=MAX_PLAINTEXT).contains(&length) {
        return Err(Refused::Size);
    }
    if length <= 32 {
        return Ok(32);
    }
    let next = length.next_power_of_two();
    let chunk = if next <= 256 { 32 } else { next / 8 };
    Ok(length.div_ceil(chunk) * chunk)
}
pub fn encrypt(plaintext: &str, key: &[u8; 32]) -> Result<String> {
    let mut nonce = [0; 32];
    getrandom::fill(&mut nonce).map_err(|_| Refused::Key)?;
    encrypt_with_nonce(plaintext, key, &nonce)
}
/// Deterministic codec entry point for vectors. Live callers use `encrypt`.
pub fn encrypt_with_nonce(plaintext: &str, key: &[u8; 32], nonce: &[u8; 32]) -> Result<String> {
    Ok(STANDARD.encode(seal(plaintext.as_bytes(), key, nonce)?))
}
/// Raw sealed bytes for the Spry peer protocol; Nostr uses the UTF-8/base64 wrappers.
pub(crate) fn seal(plaintext: &[u8], key: &[u8; 32], nonce: &[u8; 32]) -> Result<Vec<u8>> {
    let padded = padded_len(plaintext.len())?;
    let mut ciphertext = vec![0; padded + 2];
    ciphertext[..2].copy_from_slice(&(plaintext.len() as u16).to_be_bytes());
    ciphertext[2..2 + plaintext.len()].copy_from_slice(plaintext);
    let keys = keys(key, nonce)?;
    ChaCha20::new_from_slices(&keys[..32], &keys[32..44])
        .map_err(|_| Refused::Key)?
        .apply_keystream(&mut ciphertext);
    let mut mac = Hmac::<Sha256>::new_from_slice(&keys[44..]).map_err(|_| Refused::Key)?;
    mac.update(nonce);
    mac.update(&ciphertext);
    let mut payload = Vec::with_capacity(65 + ciphertext.len());
    payload.push(2);
    payload.extend_from_slice(nonce);
    payload.extend_from_slice(&ciphertext);
    payload.extend_from_slice(&mac.finalize().into_bytes());
    Ok(payload)
}
pub fn decrypt(payload: &str, key: &[u8; 32]) -> Result<String> {
    let maximum = (MAX_PLAINTEXT + 67).div_ceil(3) * 4;
    if !(132..=maximum).contains(&payload.len()) {
        return Err(Refused::Size);
    }
    let bytes = STANDARD.decode(payload).map_err(|_| Refused::Encoding)?;
    String::from_utf8(open(&bytes, key)?).map_err(|_| Refused::Encoding)
}
pub(crate) fn open(bytes: &[u8], key: &[u8; 32]) -> Result<Vec<u8>> {
    if bytes.len() > MAX_PLAINTEXT + 67 {
        return Err(Refused::Size);
    }
    if bytes.len() < 99 || bytes[0] != 2 {
        return Err(Refused::Encoding);
    }
    let nonce: &[u8; 32] = bytes[1..33].try_into().map_err(|_| Refused::Encoding)?;
    let keys = keys(key, nonce)?;
    let ciphertext = &bytes[33..bytes.len() - 32];
    let mut mac = Hmac::<Sha256>::new_from_slice(&keys[44..]).map_err(|_| Refused::Key)?;
    mac.update(nonce);
    mac.update(ciphertext);
    mac.verify_slice(&bytes[bytes.len() - 32..])
        .map_err(|_| Refused::Authentication)?;
    let mut plaintext = ciphertext.to_vec();
    ChaCha20::new_from_slices(&keys[..32], &keys[32..44])
        .map_err(|_| Refused::Key)?
        .apply_keystream(&mut plaintext);
    let length = usize::from(u16::from_be_bytes([plaintext[0], plaintext[1]]));
    if padded_len(length)? + 2 != plaintext.len() || length + 2 > plaintext.len() {
        return Err(Refused::Encoding);
    }
    Ok(plaintext[2..2 + length].to_vec())
}
