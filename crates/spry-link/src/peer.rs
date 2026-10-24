//! Signed peer cards, challenge proofs and bounded encrypted datagram frames.
use crate::{
    Refused, Result, hex,
    identity::{Event, Identity},
    nip44, unhex,
};
use hkdf::Hkdf;
use sha2::{Digest, Sha256};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV6};

pub const LINK_PORT: u16 = 3745;
pub const FIRST_RELAY: u16 = 49160;
pub const LAST_RELAY: u16 = 49191;
pub const MAX_PEERS: usize = 8;
pub const MAX_DATAGRAM: usize = 4096;
pub const MAX_WIRE_PACKET: usize = 8192;
pub const CARD_KIND: u16 = 24183;
pub const HELLO_KIND: u16 = 24184;

pub fn relay_alias(key: &str) -> Result<Ipv4Addr> {
    let digest = Sha256::digest(unhex::<32>(key)?);
    Ok(Ipv4Addr::new(
        127,
        64 | (digest[0] & 63),
        digest[1],
        digest[2],
    ))
}
pub fn relay_port(port: u16) -> bool {
    (FIRST_RELAY..=LAST_RELAY).contains(&port)
}

/// A bounded DNS name, without a URL, port, IP literal or empty labels.
pub fn valid_name(name: &str) -> bool {
    name.len() <= 128
        && name.contains('.')
        && name.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        })
}

#[derive(Clone, Debug)]
pub struct PeerCard {
    pub event: Event,
    pub address: SocketAddrV6,
    pub name: Option<String>,
    pub alias: Ipv4Addr,
    pub expires_at: u64,
}
impl PeerCard {
    pub fn sign(identity: &Identity, address: SocketAddrV6, now: u64) -> Result<Self> {
        Self::sign_named(identity, address, None, now)
    }
    /// Optional host-resolver hint; resolution never replaces the signed ULA.
    pub fn sign_named(
        identity: &Identity,
        address: SocketAddrV6,
        name: Option<&str>,
        now: u64,
    ) -> Result<Self> {
        let mut value =
            serde_json::json!({"v":1,"profile":"spry-peer-v1","address":address.to_string()});
        if let Some(name) = name {
            if !valid_name(name) {
                return Err(Refused::Destination);
            }
            value["name"] = name.into();
        }
        let content = value.to_string();
        let event = identity.sign(
            CARD_KIND,
            vec![vec![
                "expiration".into(),
                now.saturating_add(600).to_string(),
            ]],
            content,
            now,
        )?;
        Self::verify(event, now)
    }
    pub fn verify(event: Event, now: u64) -> Result<Self> {
        if event.kind != CARD_KIND
            || event.created_at > now.saturating_add(60)
            || event.content.len() > 256
        {
            return Err(Refused::Destination);
        }
        event.verify()?;
        let expires_at: u64 = event
            .tag("expiration")?
            .parse()
            .map_err(|_| Refused::Expired)?;
        if expires_at <= now
            || expires_at > now.saturating_add(660)
            || expires_at > event.created_at.saturating_add(600)
        {
            return Err(Refused::Expired);
        }
        let content: serde_json::Value =
            serde_json::from_str(&event.content).map_err(|_| Refused::Encoding)?;
        if content["v"] != 1 || content["profile"] != "spry-peer-v1" {
            return Err(Refused::Encoding);
        }
        let name = match content.get("name") {
            Some(value) => Some(
                value
                    .as_str()
                    .filter(|name| valid_name(name))
                    .ok_or(Refused::Destination)?
                    .to_owned(),
            ),
            None => None,
        };
        let address: SocketAddr = content["address"]
            .as_str()
            .ok_or(Refused::Destination)?
            .parse()
            .map_err(|_| Refused::Destination)?;
        let SocketAddr::V6(address) = address else {
            return Err(Refused::Destination);
        };
        if address.port() != LINK_PORT
            || address.ip().octets()[0] & 0xfe != 0xfc
            || address.scope_id() != 0
            || address.flowinfo() != 0
        {
            return Err(Refused::Destination);
        }
        let alias = relay_alias(&event.pubkey)?;
        Ok(Self {
            event,
            address,
            name,
            alias,
            expires_at,
        })
    }
}

pub fn hello(
    identity: &Identity,
    peer: &str,
    server_nonce: &[u8; 32],
    client_nonce: &[u8; 32],
    now: u64,
) -> Result<Event> {
    identity.sign(
        HELLO_KIND,
        vec![
            vec!["p".into(), peer.into()],
            vec!["challenge".into(), hex(server_nonce)],
            vec!["nonce".into(), hex(client_nonce)],
            vec!["expiration".into(), now.saturating_add(30).to_string()],
        ],
        "spry-peer-v1".into(),
        now,
    )
}
pub fn verify_hello(
    event: &Event,
    peer: &str,
    own: &str,
    server_nonce: &[u8; 32],
    client_nonce: &[u8; 32],
    now: u64,
) -> Result<()> {
    event.addressed_to(own, HELLO_KIND, now)?;
    if event.pubkey != peer
        || event.content != "spry-peer-v1"
        || event.tag("challenge")? != hex(server_nonce)
        || event.tag("nonce")? != hex(client_nonce)
    {
        return Err(Refused::Authentication);
    }
    Ok(())
}

#[derive(Debug, PartialEq, Eq)]
pub struct Datagram {
    pub source_port: u16,
    pub destination_port: u16,
    pub bytes: Vec<u8>,
}

/// Each connection has independent keys in each direction and strict sequence checks.
pub struct PacketSession {
    sender: PacketSender,
    receiver: PacketReceiver,
}
pub struct PacketSender {
    key: [u8; 32],
    sequence: u64,
}
pub struct PacketReceiver {
    key: [u8; 32],
    sequence: u64,
}
impl PacketSession {
    pub fn new(
        identity: &Identity,
        peer: &str,
        server_nonce: &[u8; 32],
        client_nonce: &[u8; 32],
        initiator: bool,
    ) -> Result<Self> {
        let mut salt = [0_u8; 64];
        salt[..32].copy_from_slice(server_nonce);
        salt[32..].copy_from_slice(client_nonce);
        let hkdf = Hkdf::<Sha256>::new(Some(&salt), &identity.shared_secret(peer)?);
        let mut keys = [0_u8; 64];
        hkdf.expand(b"spry-peer-v1/directions", &mut keys)
            .map_err(|_| Refused::Key)?;
        let first = keys[..32].try_into().map_err(|_| Refused::Key)?;
        let second = keys[32..].try_into().map_err(|_| Refused::Key)?;
        let (send, receive) = if initiator {
            (first, second)
        } else {
            (second, first)
        };
        Ok(Self {
            sender: PacketSender {
                key: send,
                sequence: 0,
            },
            receiver: PacketReceiver {
                key: receive,
                sequence: 0,
            },
        })
    }
    pub fn into_directions(self) -> (PacketSender, PacketReceiver) {
        (self.sender, self.receiver)
    }
    pub fn seal(&mut self, packet: Option<&Datagram>) -> Result<Vec<u8>> {
        self.sender.seal(packet)
    }
    pub fn open(&mut self, sealed: &[u8]) -> Result<Option<Datagram>> {
        self.receiver.open(sealed)
    }
}
impl PacketSender {
    pub fn seal(&mut self, packet: Option<&Datagram>) -> Result<Vec<u8>> {
        let mut bytes = self.sequence.to_be_bytes().to_vec();
        match packet {
            Some(packet) => {
                if !relay_port(packet.source_port)
                    || !relay_port(packet.destination_port)
                    || packet.bytes.is_empty()
                    || packet.bytes.len() > MAX_DATAGRAM
                {
                    return Err(Refused::Size);
                }
                bytes.extend_from_slice(&packet.source_port.to_be_bytes());
                bytes.extend_from_slice(&packet.destination_port.to_be_bytes());
                bytes.extend_from_slice(&packet.bytes);
            }
            None => bytes.extend_from_slice(&[0; 4]),
        }
        let mut nonce = [0; 32];
        getrandom::fill(&mut nonce).map_err(|_| Refused::Key)?;
        let sealed = nip44::seal(&bytes, &self.key, &nonce)?;
        self.sequence = self.sequence.checked_add(1).ok_or(Refused::Expired)?;
        Ok(sealed)
    }
}
impl PacketReceiver {
    pub fn open(&mut self, sealed: &[u8]) -> Result<Option<Datagram>> {
        if sealed.len() > MAX_WIRE_PACKET {
            return Err(Refused::Size);
        }
        let bytes = nip44::open(sealed, &self.key)?;
        if !(12..=12 + MAX_DATAGRAM).contains(&bytes.len()) {
            return Err(Refused::Size);
        }
        let sequence = u64::from_be_bytes(bytes[..8].try_into().map_err(|_| Refused::Encoding)?);
        if sequence != self.sequence {
            return Err(Refused::Authentication);
        }
        let source_port = u16::from_be_bytes([bytes[8], bytes[9]]);
        let destination_port = u16::from_be_bytes([bytes[10], bytes[11]]);
        let packet = if source_port == 0 && destination_port == 0 && bytes.len() == 12 {
            None
        } else {
            if !relay_port(source_port) || !relay_port(destination_port) || bytes.len() == 12 {
                return Err(Refused::Destination);
            }
            Some(Datagram {
                source_port,
                destination_port,
                bytes: bytes[12..].to_vec(),
            })
        };
        self.sequence = self.sequence.checked_add(1).ok_or(Refused::Expired)?;
        Ok(packet)
    }
}
