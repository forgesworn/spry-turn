//! Bounded, host-independent Spry link messages. No sockets or runtime.
#![forbid(unsafe_code)]

pub mod advert;
pub mod control;
pub mod identity;
pub mod nip44;
pub mod peer;
pub mod registry;
pub mod standard;

pub const MAX_PLAINTEXT: usize = 16_384;
pub const MAX_EVENT: usize = 24_576;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refused {
    Key,
    Size,
    Encoding,
    Authentication,
    Expired,
    Destination,
    Overload,
    Collision,
    Replay,
}
pub type Result<T> = std::result::Result<T, Refused>;

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
pub fn unhex<const N: usize>(value: &str) -> Result<[u8; N]> {
    if value.len() != N * 2
        || !value
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
    {
        return Err(Refused::Encoding);
    }
    let mut result = [0; N];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        result[index] = u8::from_str_radix(
            std::str::from_utf8(pair).map_err(|_| Refused::Encoding)?,
            16,
        )
        .map_err(|_| Refused::Encoding)?;
    }
    Ok(result)
}
