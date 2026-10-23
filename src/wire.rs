//! Borrowed STUN/TURN framing. Media payloads are never decoded.
use hmac::{Hmac, Mac};
use sha1::Sha1;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

pub const COOKIE: u32 = 0x2112_a442;
pub const USERNAME: u16 = 0x0006;
pub const INTEGRITY: u16 = 0x0008;
pub const ERROR: u16 = 0x0009;
pub const UNKNOWN: u16 = 0x000a;
pub const CHANNEL: u16 = 0x000c;
pub const LIFETIME: u16 = 0x000d;
pub const PEER: u16 = 0x0012;
pub const DATA: u16 = 0x0013;
pub const REALM: u16 = 0x0014;
pub const NONCE: u16 = 0x0015;
pub const RELAYED: u16 = 0x0016;
pub const FAMILY: u16 = 0x0017;
pub const TRANSPORT: u16 = 0x0019;
pub const MAPPED: u16 = 0x0020;
pub const SOFTWARE: u16 = 0x8022;
pub const FINGERPRINT: u16 = 0x8028;
pub const BINDING: u16 = 1;
pub const ALLOCATE: u16 = 3;
pub const REFRESH: u16 = 4;
pub const SEND: u16 = 6;
pub const DATA_METHOD: u16 = 7;
pub const PERMISSION: u16 = 8;
pub const CHANNEL_BIND: u16 = 9;

fn u16_at(bytes: &[u8], index: usize) -> u16 {
    u16::from_be_bytes([bytes[index], bytes[index + 1]])
}

pub fn message_type(method: u16, class: u8) -> u16 {
    (method & 0x000f)
        | ((method & 0x0070) << 1)
        | ((method & 0x0f80) << 2)
        | (u16::from(class & 1) << 4)
        | (u16::from(class & 2) << 7)
}

#[derive(Clone, Copy, Debug)]
pub struct Message<'a> {
    bytes: &'a [u8],
    attributes_end: usize,
    integrity: Option<usize>,
    pub method: u16,
    /// Request 0, indication 1, success 2, error 3.
    pub class: u8,
    pub transaction: [u8; 12],
}

impl<'a> Message<'a> {
    pub fn parse(bytes: &'a [u8]) -> Option<Self> {
        if bytes.len() < 20 || bytes[0] & 0xc0 != 0 || bytes[4..8] != COOKIE.to_be_bytes() {
            return None;
        }
        let body = usize::from(u16_at(bytes, 2));
        if body % 4 != 0 || body + 20 != bytes.len() {
            return None;
        }
        let typ = u16_at(bytes, 0);
        let mut integrity = None;
        let mut offset = 20;
        let mut count = 0;
        while offset < bytes.len() {
            count += 1;
            if count > 128 || offset + 4 > bytes.len() {
                return None;
            }
            let typ = u16_at(bytes, offset);
            let len = usize::from(u16_at(bytes, offset + 2));
            let end = offset.checked_add(4 + ((len + 3) & !3))?;
            if end > bytes.len() {
                return None;
            }
            if typ == INTEGRITY && integrity.is_none() {
                if len != 20 {
                    return None;
                }
                integrity = Some(offset);
            }
            if typ == FINGERPRINT {
                if len != 4 || end != bytes.len() {
                    return None;
                }
                let expected = crc32fast::hash(&bytes[..offset]) ^ 0x5354_554e;
                if bytes[offset + 4..end] != expected.to_be_bytes() {
                    return None;
                }
            }
            offset = end;
        }
        Some(Self {
            bytes,
            attributes_end: integrity.unwrap_or(bytes.len()),
            integrity,
            method: (typ & 0xf) | ((typ & 0xe0) >> 1) | ((typ & 0x3e00) >> 2),
            class: (((typ >> 4) & 1) | ((typ >> 7) & 2)) as u8,
            transaction: bytes[8..20].try_into().ok()?,
        })
    }

    pub fn attributes(&self) -> Attributes<'a> {
        Attributes {
            remaining: &self.bytes[20..self.attributes_end],
        }
    }
    pub fn attr(&self, typ: u16) -> Option<&'a [u8]> {
        self.attributes()
            .find_map(|(kind, value)| (kind == typ).then_some(value))
    }
    pub fn number(&self, typ: u16) -> Option<u32> {
        Some(u32::from_be_bytes(self.attr(typ)?.try_into().ok()?))
    }
    pub fn verify(&self, key: &[u8]) -> bool {
        let Some(offset) = self.integrity else {
            return false;
        };
        let mut header: [u8; 20] = self.bytes[..20].try_into().expect("parsed header");
        header[2..4].copy_from_slice(&((offset + 4) as u16).to_be_bytes());
        let mut mac = Hmac::<Sha1>::new_from_slice(key).expect("HMAC accepts any key");
        mac.update(&header);
        mac.update(&self.bytes[20..offset]);
        mac.verify_slice(&self.bytes[offset + 4..offset + 24])
            .is_ok()
    }
    pub fn address(&self, typ: u16) -> Option<SocketAddr> {
        decode_address(self.attr(typ)?, &self.transaction)
    }
}

pub struct Attributes<'a> {
    remaining: &'a [u8],
}
impl<'a> Iterator for Attributes<'a> {
    type Item = (u16, &'a [u8]);
    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining.is_empty() {
            return None;
        }
        let typ = u16_at(self.remaining, 0);
        let len = usize::from(u16_at(self.remaining, 2));
        let value = &self.remaining[4..4 + len];
        self.remaining = &self.remaining[4 + ((len + 3) & !3)..];
        Some((typ, value))
    }
}

pub fn decode_address(value: &[u8], transaction: &[u8; 12]) -> Option<SocketAddr> {
    if value.len() < 4 || value[0] != 0 {
        return None;
    }
    let port = u16_at(value, 2) ^ (COOKIE >> 16) as u16;
    let mut mask = [0; 16];
    mask[..4].copy_from_slice(&COOKIE.to_be_bytes());
    mask[4..].copy_from_slice(transaction);
    let ip = match (value[1], value.len()) {
        (1, 8) => {
            let mut ip = [0; 4];
            for i in 0..4 {
                ip[i] = value[4 + i] ^ mask[i];
            }
            IpAddr::V4(Ipv4Addr::from(ip))
        }
        (2, 20) => {
            let mut ip = [0; 16];
            for i in 0..16 {
                ip[i] = value[4 + i] ^ mask[i];
            }
            IpAddr::V6(Ipv6Addr::from(ip))
        }
        _ => return None,
    };
    Some(SocketAddr::new(ip, port))
}

pub fn address_value(address: SocketAddr, transaction: &[u8; 12]) -> ([u8; 20], usize) {
    let mut bytes = [0; 20];
    bytes[2..4].copy_from_slice(&(address.port() ^ (COOKIE >> 16) as u16).to_be_bytes());
    let mut mask = [0; 16];
    mask[..4].copy_from_slice(&COOKIE.to_be_bytes());
    mask[4..].copy_from_slice(transaction);
    let len = match address.ip() {
        IpAddr::V4(ip) => {
            bytes[1] = 1;
            for (i, b) in ip.octets().iter().enumerate() {
                bytes[i + 4] = b ^ mask[i];
            }
            8
        }
        IpAddr::V6(ip) => {
            bytes[1] = 2;
            for (i, b) in ip.octets().iter().enumerate() {
                bytes[i + 4] = b ^ mask[i];
            }
            20
        }
    };
    (bytes, len)
}

/// Control messages allocate; steady-state UDP ChannelData forwarding does not.
pub struct Builder {
    bytes: Vec<u8>,
}
impl Builder {
    pub fn new(method: u16, class: u8, transaction: [u8; 12]) -> Self {
        let mut bytes = Vec::with_capacity(256);
        bytes.extend_from_slice(&message_type(method, class).to_be_bytes());
        bytes.extend_from_slice(&[0, 0]);
        bytes.extend_from_slice(&COOKIE.to_be_bytes());
        bytes.extend_from_slice(&transaction);
        Self { bytes }
    }
    pub fn attr(&mut self, typ: u16, value: &[u8]) -> &mut Self {
        assert!(value.len() <= u16::MAX as usize);
        self.bytes.extend_from_slice(&typ.to_be_bytes());
        self.bytes
            .extend_from_slice(&(value.len() as u16).to_be_bytes());
        self.bytes.extend_from_slice(value);
        self.bytes.resize((self.bytes.len() + 3) & !3, 0);
        self
    }
    pub fn number(&mut self, typ: u16, value: u32) -> &mut Self {
        self.attr(typ, &value.to_be_bytes())
    }
    pub fn address(&mut self, typ: u16, address: SocketAddr) -> &mut Self {
        let transaction = self.bytes[8..20].try_into().expect("header");
        let (value, len) = address_value(address, &transaction);
        self.attr(typ, &value[..len])
    }
    fn length(&mut self, extra: usize) {
        let len = (self.bytes.len() + extra - 20) as u16;
        self.bytes[2..4].copy_from_slice(&len.to_be_bytes());
    }
    pub fn finish(mut self, key: Option<&[u8]>) -> Vec<u8> {
        if let Some(key) = key {
            self.length(24);
            let mut mac = Hmac::<Sha1>::new_from_slice(key).expect("HMAC accepts any key");
            mac.update(&self.bytes);
            self.attr(INTEGRITY, &mac.finalize().into_bytes());
        }
        self.length(8);
        let fingerprint = crc32fast::hash(&self.bytes) ^ 0x5354_554e;
        self.number(FINGERPRINT, fingerprint);
        self.bytes
    }
}

pub fn channel(bytes: &[u8]) -> Option<(u16, &[u8])> {
    if bytes.len() < 4 {
        return None;
    }
    let number = u16_at(bytes, 0);
    let len = usize::from(u16_at(bytes, 2));
    if !(0x4000..=0x4fff).contains(&number)
        || len > bytes.len() - 4
        || bytes.len() > 4 + ((len + 3) & !3)
    {
        return None;
    }
    Some((number, &bytes[4..4 + len]))
}

/// Length of a TURN frame on TCP, including mandatory ChannelData padding.
pub fn frame_len(bytes: &[u8]) -> Option<usize> {
    if bytes.len() < 4 {
        return None;
    }
    let len = usize::from(u16_at(bytes, 2));
    match bytes[0] >> 6 {
        0 => Some(20 + len),
        1 => Some(4 + ((len + 3) & !3)),
        _ => Some(0),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn signed_messages_round_trip_and_detect_tampering() {
        let mut b = Builder::new(ALLOCATE, 0, [7; 12]);
        b.attr(USERNAME, b"user")
            .address(PEER, "[2001:db8::1]:12345".parse().unwrap());
        let mut bytes = b.finish(Some(b"key"));
        let m = Message::parse(&bytes).unwrap();
        assert!(m.verify(b"key"));
        assert!(!m.verify(b"wrong"));
        assert_eq!(
            m.address(PEER),
            Some("[2001:db8::1]:12345".parse().unwrap())
        );
        bytes[24] ^= 1;
        assert!(Message::parse(&bytes).is_none());
    }
    #[test]
    fn unsigned_attributes_after_integrity_are_ignored() {
        let b = Builder::new(ALLOCATE, 0, [0; 12]);
        let mut bytes = b.finish(Some(b"key"));
        bytes.truncate(bytes.len() - 8);
        bytes.extend_from_slice(&[0, 6, 0, 4, b'e', b'v', b'i', b'l']);
        let len = (bytes.len() - 20) as u16;
        bytes[2..4].copy_from_slice(&len.to_be_bytes());
        let m = Message::parse(&bytes).unwrap();
        assert!(m.verify(b"key"));
        assert!(m.attr(USERNAME).is_none());
    }
    #[test]
    fn malformed_inputs_never_panic() {
        let mut x = 0xdead_beef_u64;
        for len in 0..512 {
            let mut bytes = vec![0; len];
            for b in &mut bytes {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                *b = x as u8;
            }
            let _ = Message::parse(&bytes);
            let _ = channel(&bytes);
            let _ = frame_len(&bytes);
        }
    }
    #[test]
    fn rfc5769_request_integrity_and_fingerprint() {
        // Published protocol test data, RFC 5769 section 2.1; see NOTICE.
        let hex = "000100582112a442b7e7a701bc34d686fa87dfae802200105354554e207465737420636c69656e74002400046e0001ff80290008932ff9b151263b36000600096576746a3a68367659202020000800149aeaa70cbfd8cb56781ef2b5b2d3f249c1b571a280280004e57a3bcf";
        let bytes: Vec<u8> = hex
            .as_bytes()
            .chunks_exact(2)
            .map(|p| u8::from_str_radix(std::str::from_utf8(p).unwrap(), 16).unwrap())
            .collect();
        let message = Message::parse(&bytes).unwrap();
        assert!(message.verify(b"VOkJxbRl1RmTxUk/WvJxBt"));
        assert_eq!(message.attr(USERNAME), Some(b"evtj:h6vY".as_slice()));
    }
}
