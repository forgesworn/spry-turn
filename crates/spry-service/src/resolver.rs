//! Optional host DNS adapter for private routes that need identity discovery.
//! No mesh SDK: the host supplies the resolver, private zone and signed hint.
use spry_link::peer::{PeerCard, valid_name};
use std::{
    io,
    net::{Ipv6Addr, SocketAddr},
    time::Duration,
};
use tokio::{net::UdpSocket, time::timeout};

#[derive(Clone)]
pub struct PeerResolver {
    server: SocketAddr,
    zone: String,
}
fn refused() -> io::Error {
    io::Error::other("Private peer route is unavailable")
}
impl PeerResolver {
    /// The configured local resolver owns this zone. Never use public DNS for hints.
    pub fn new(server: SocketAddr, zone: String) -> io::Result<Self> {
        if !server.ip().is_loopback()
            || server.port() == 0
            || zone.len() > 63
            || !valid_name(&format!("node.{zone}"))
        {
            return Err(refused());
        }
        Ok(Self { server, zone })
    }
    pub fn accepts(&self, name: &str) -> bool {
        valid_name(name) && name.ends_with(&format!(".{}", self.zone))
    }
    pub async fn prepare(&self, card: &PeerCard) -> io::Result<()> {
        let name = card
            .name
            .as_deref()
            .filter(|name| self.accepts(name))
            .ok_or_else(refused)?;
        let mut id = [0; 2];
        getrandom::fill(&mut id).map_err(|_| refused())?;
        let request = question(id, name)?;
        let socket = UdpSocket::bind(if self.server.is_ipv6() {
            "[::1]:0"
        } else {
            "127.0.0.1:0"
        })
        .await?;
        socket.connect(self.server).await?;
        socket.send(&request).await?;
        let mut response = [0; 4096];
        let length = timeout(Duration::from_secs(8), socket.recv(&mut response))
            .await
            .map_err(|_| refused())??;
        answer(&request, &response[..length], *card.address.ip())
    }
}
fn question(id: [u8; 2], name: &str) -> io::Result<Vec<u8>> {
    if !valid_name(name) {
        return Err(refused());
    }
    let mut bytes = vec![id[0], id[1], 1, 0, 0, 1, 0, 0, 0, 0, 0, 0];
    for label in name.split('.') {
        bytes.push(label.len() as u8);
        bytes.extend_from_slice(label.as_bytes());
    }
    bytes.extend_from_slice(&[0, 0, 28, 0, 1]);
    Ok(bytes)
}
fn short(bytes: &[u8], offset: usize) -> io::Result<u16> {
    Ok(u16::from_be_bytes(
        bytes
            .get(offset..offset + 2)
            .ok_or_else(refused)?
            .try_into()
            .map_err(|_| refused())?,
    ))
}
fn skip_name(bytes: &[u8], mut cursor: usize) -> io::Result<usize> {
    for _ in 0..128 {
        let value = *bytes.get(cursor).ok_or_else(refused)?;
        if value == 0 {
            return Ok(cursor + 1);
        }
        if value & 0xc0 == 0xc0 {
            let pointer = usize::from(short(bytes, cursor)? & 0x3fff);
            if pointer >= cursor {
                return Err(refused());
            }
            return Ok(cursor + 2);
        }
        if value > 63 {
            return Err(refused());
        }
        cursor = cursor
            .checked_add(1 + usize::from(value))
            .filter(|end| *end <= bytes.len())
            .ok_or_else(refused)?;
    }
    Err(refused())
}
fn answer(request: &[u8], response: &[u8], target: Ipv6Addr) -> io::Result<()> {
    if response.len() < request.len()
        || response[..2] != request[..2]
        || short(response, 2)? & 0xfa0f != 0x8000
        || short(response, 4)? != 1
        || response.get(12..request.len()) != request.get(12..)
    {
        return Err(refused());
    }
    let count = short(response, 6)?;
    if count == 0 || count > 16 {
        return Err(refused());
    }
    let mut cursor = request.len();
    let mut matched = false;
    for _ in 0..count {
        cursor = skip_name(response, cursor)?;
        let kind = short(response, cursor)?;
        let class = short(response, cursor + 2)?;
        let length = usize::from(short(response, cursor + 8)?);
        let start = cursor.checked_add(10).ok_or_else(refused)?;
        cursor = start.checked_add(length).ok_or_else(refused)?;
        let data = response.get(start..cursor).ok_or_else(refused)?;
        if kind == 28 && class == 1 && data == target.octets() {
            matched = true;
        }
    }
    if matched { Ok(()) } else { Err(refused()) }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn dns_answers_bind_question_identity_and_signed_ula_and_bound_parsing() {
        let question = question([1, 2], "node.private").unwrap();
        let target = "fd12::2".parse().unwrap();
        let mut reply = question.clone();
        reply[2] = 0x81;
        reply[3] = 0x80;
        reply[7] = 1;
        reply.extend_from_slice(&[0xc0, 12, 0, 28, 0, 1, 0, 0, 0, 1, 0, 16]);
        reply.extend_from_slice(&Ipv6Addr::octets(&target));
        assert!(answer(&question, &reply, target).is_ok());
        for length in 0..reply.len() {
            assert!(answer(&question, &reply[..length], target).is_err());
        }
        let mut wrong = reply.clone();
        wrong[0] ^= 1;
        assert!(answer(&question, &wrong, target).is_err());
        assert!(answer(&question, &reply, "fd12::3".parse().unwrap()).is_err());
        let mut wrong = reply.clone();
        wrong[12] ^= 1;
        assert!(answer(&question, &wrong, target).is_err());
        let mut wrong = reply.clone();
        wrong[question.len() + 1] = 255;
        assert!(answer(&question, &wrong, target).is_err());
        assert!(
            PeerResolver::new("127.0.0.1:5354".parse().unwrap(), "private".into())
                .unwrap()
                .accepts("node.private")
        );
        assert!(
            !PeerResolver::new("127.0.0.1:5354".parse().unwrap(), "private".into())
                .unwrap()
                .accepts("node.public")
        );
        assert!(PeerResolver::new("192.0.2.1:53".parse().unwrap(), "private".into()).is_err());
    }
}
