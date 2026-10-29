//! PCP (RFC 6887), MAP opcode only, IPv4 only.

use crate::udp::{self, MAX_DATAGRAM, Verdict};
use crate::{Error, Method, Protocol};
use std::net::{Ipv4Addr, SocketAddrV4};
use std::time::Duration;

pub const VERSION: u8 = 2;
pub const OPCODE_MAP: u8 = 1;
const RESPONSE: u8 = 0x80;
const HEADER: usize = 24;
/// Header plus MAP opcode body; the size of every MAP request.
pub const MAP_SIZE: usize = HEADER + 36;

/// One MAP request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MapRequest {
    pub nonce: [u8; 12],
    pub protocol: Protocol,
    pub internal_port: u16,
    /// Suggested external address and port; unspecified and 0 mean any.
    pub suggested: SocketAddrV4,
    /// Requested lifetime in seconds; 0 deletes.
    pub lifetime: u32,
    /// The client's own address, as the gateway sees it.
    pub client: Ipv4Addr,
}

/// A decoded MAP response.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MapResponse {
    pub result: u8,
    pub lifetime: u32,
    pub epoch: u32,
    pub nonce: [u8; 12],
    pub protocol: u8,
    pub internal_port: u16,
    /// Assigned external address and port. Meaningful only on success.
    pub external: SocketAddrV4,
}

/// What a datagram from the PCP port turned out to be.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Decoded {
    Map(MapResponse),
    /// A response in another protocol version, such as a NAT-PMP gateway's
    /// version 0 "unsupported version" answer.
    OtherVersion {
        version: u8,
    },
}

fn mapped(address: Ipv4Addr) -> [u8; 16] {
    address.to_ipv6_mapped().octets()
}

/// Encode a MAP request.
pub fn encode_map(request: &MapRequest) -> [u8; MAP_SIZE] {
    let mut out = [0u8; MAP_SIZE];
    out[0] = VERSION;
    out[1] = OPCODE_MAP;
    out[4..8].copy_from_slice(&request.lifetime.to_be_bytes());
    out[8..24].copy_from_slice(&mapped(request.client));
    out[24..36].copy_from_slice(&request.nonce);
    out[36] = request.protocol.number();
    out[40..42].copy_from_slice(&request.internal_port.to_be_bytes());
    out[42..44].copy_from_slice(&request.suggested.port().to_be_bytes());
    out[44..60].copy_from_slice(&mapped(*request.suggested.ip()));
    out
}

fn u16_at(bytes: &[u8], at: usize) -> u16 {
    u16::from_be_bytes([bytes[at], bytes[at + 1]])
}
fn u32_at(bytes: &[u8], at: usize) -> u32 {
    u32::from_be_bytes([bytes[at], bytes[at + 1], bytes[at + 2], bytes[at + 3]])
}

/// Decode a datagram received from the gateway's PCP port.
pub fn decode(bytes: &[u8]) -> Result<Decoded, &'static str> {
    if bytes.len() > MAX_DATAGRAM {
        return Err("oversized");
    }
    if bytes.len() < 4 {
        return Err("truncated");
    }
    if bytes[0] != VERSION {
        if bytes[1] & RESPONSE == 0 {
            return Err("not a response");
        }
        return Ok(Decoded::OtherVersion { version: bytes[0] });
    }
    if bytes.len() < MAP_SIZE {
        return Err("truncated");
    }
    if bytes.len() % 4 != 0 {
        return Err("misaligned");
    }
    if bytes[1] != RESPONSE | OPCODE_MAP {
        return Err("not a MAP response");
    }
    // Options must tile the rest of the message exactly.
    let mut at = MAP_SIZE;
    while at < bytes.len() {
        if bytes.len() - at < 4 {
            return Err("malformed option");
        }
        let length = usize::from(u16_at(bytes, at + 2));
        let padded = (length + 3) & !3;
        at += 4;
        if bytes.len() - at < padded {
            return Err("malformed option");
        }
        at += padded;
    }
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&bytes[24..36]);
    let mut ip = [0u8; 16];
    ip.copy_from_slice(&bytes[44..60]);
    let external_ip = std::net::Ipv6Addr::from(ip)
        .to_ipv4_mapped()
        .unwrap_or(Ipv4Addr::UNSPECIFIED);
    let result = bytes[3];
    if result == 0 && std::net::Ipv6Addr::from(ip).to_ipv4_mapped().is_none() {
        return Err("external address is not IPv4");
    }
    Ok(Decoded::Map(MapResponse {
        result,
        lifetime: u32_at(bytes, 4),
        epoch: u32_at(bytes, 8),
        nonce,
        protocol: bytes[36],
        internal_port: u16_at(bytes, 40),
        external: SocketAddrV4::new(external_ip, u16_at(bytes, 42)),
    }))
}

/// Words for a PCP result code (RFC 6887 section 7.4).
pub const fn reason(code: u8) -> &'static str {
    match code {
        1 => "unsupported version",
        2 => "not authorised",
        3 => "malformed request",
        4 => "unsupported opcode",
        5 => "unsupported option",
        6 => "malformed option",
        7 => "network failure",
        8 => "no resources",
        9 => "unsupported protocol",
        10 => "user quota exceeded",
        11 => "cannot provide external port",
        12 => "address mismatch",
        13 => "excessive remote peers",
        _ => "unknown result",
    }
}

/// A successful MAP answer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Grant {
    pub external: SocketAddrV4,
    pub lifetime: u32,
    pub epoch: u32,
}

/// Judge one datagram against `request`.
pub(crate) fn judge(request: &MapRequest, bytes: &[u8]) -> Verdict<Grant> {
    let response = match decode(bytes) {
        Ok(Decoded::Map(response)) => response,
        Ok(Decoded::OtherVersion { .. }) => return Verdict::Fail(Error::UnsupportedVersion),
        Err(reason) => return Verdict::Ignore(reason),
    };
    // Only the nonce, protocol and port of this request identify its answer;
    // anything else is stale or forged and is ignored, not obeyed.
    if response.nonce != request.nonce
        || response.protocol != request.protocol.number()
        || response.internal_port != request.internal_port
    {
        return Verdict::Ignore("reply for another mapping");
    }
    if response.result == 1 {
        return Verdict::Fail(Error::UnsupportedVersion);
    }
    if response.result != 0 {
        return Verdict::Fail(Error::Refused {
            method: Method::Pcp,
            code: u16::from(response.result),
            reason: reason(response.result),
        });
    }
    if request.lifetime > 0 {
        if response.lifetime == 0 {
            return Verdict::Ignore("zero lifetime");
        }
        if response.external.port() == 0 || response.external.ip().is_unspecified() {
            return Verdict::Ignore("no external endpoint");
        }
    }
    Verdict::Done(Grant {
        external: response.external,
        lifetime: response.lifetime,
        epoch: response.epoch,
    })
}

/// Send one MAP request to `gateway` and wait for its answer. The client
/// address field is filled from the socket's own local address.
pub(crate) fn send(
    gateway: SocketAddrV4,
    mut request: MapRequest,
    budget: Duration,
) -> Result<Grant, Error> {
    let (socket, local) = udp::connect(gateway)?;
    request.client = local;
    let bytes = encode_map(&request);
    udp::exchange(&socket, &bytes, budget, |reply| judge(&request, reply))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request() -> MapRequest {
        MapRequest {
            nonce: *b"nonce-012345",
            protocol: Protocol::Udp,
            internal_port: 3478,
            suggested: SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 3478),
            lifetime: 7200,
            client: Ipv4Addr::new(192, 168, 1, 20),
        }
    }

    fn response(result: u8, nonce: &[u8; 12], port: u16) -> Vec<u8> {
        let mut out = vec![0u8; MAP_SIZE];
        out[0] = 2;
        out[1] = 0x81;
        out[3] = result;
        out[4..8].copy_from_slice(&3600u32.to_be_bytes());
        out[8..12].copy_from_slice(&77u32.to_be_bytes());
        out[24..36].copy_from_slice(nonce);
        out[36] = 17;
        out[40..42].copy_from_slice(&3478u16.to_be_bytes());
        out[42..44].copy_from_slice(&port.to_be_bytes());
        out[44..60].copy_from_slice(&Ipv4Addr::new(198, 51, 100, 7).to_ipv6_mapped().octets());
        out
    }

    #[test]
    fn map_request_is_byte_exact() {
        let bytes = encode_map(&request());
        let mut expected = vec![2u8, 1, 0, 0, 0, 0, 0x1c, 0x20];
        expected.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 192, 168, 1, 20]);
        expected.extend_from_slice(b"nonce-012345");
        expected.extend_from_slice(&[17, 0, 0, 0, 0x0d, 0x96, 0x0d, 0x96]);
        expected.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0, 0, 0, 0]);
        assert_eq!(bytes.to_vec(), expected);
    }

    #[test]
    fn decodes_a_translated_grant() {
        let bytes = response(0, b"nonce-012345", 40000);
        let Verdict::Done(grant) = judge(&request(), &bytes) else {
            panic!("expected a grant");
        };
        assert_eq!(grant.external, "198.51.100.7:40000".parse().unwrap());
        assert_eq!(grant.lifetime, 3600);
        assert_eq!(grant.epoch, 77);
    }

    #[test]
    fn ignores_wrong_nonce_protocol_and_port() {
        let wrong_nonce = response(0, b"nonce-999999", 3478);
        assert!(matches!(
            judge(&request(), &wrong_nonce),
            Verdict::Ignore(_)
        ));
        let mut wrong_protocol = response(0, b"nonce-012345", 3478);
        wrong_protocol[36] = 6;
        assert!(matches!(
            judge(&request(), &wrong_protocol),
            Verdict::Ignore(_)
        ));
        let mut wrong_port = response(0, b"nonce-012345", 3478);
        wrong_port[40] = 0;
        assert!(matches!(judge(&request(), &wrong_port), Verdict::Ignore(_)));
        // A refusal for another mapping is not this request's refusal.
        let foreign_refusal = response(2, b"nonce-999999", 3478);
        assert!(matches!(
            judge(&request(), &foreign_refusal),
            Verdict::Ignore(_)
        ));
    }

    #[test]
    fn refusal_and_version_answers() {
        let refused = response(2, b"nonce-012345", 0);
        assert!(matches!(
            judge(&request(), &refused),
            Verdict::Fail(Error::Refused { code: 2, .. })
        ));
        // NAT-PMP-only gateway: version 0, opcode 128 + 1, result 1, epoch.
        let natpmp = [0u8, 0x81, 0, 1, 0, 0, 0, 9];
        assert_eq!(decode(&natpmp), Ok(Decoded::OtherVersion { version: 0 }));
        assert!(matches!(
            judge(&request(), &natpmp),
            Verdict::Fail(Error::UnsupportedVersion)
        ));
    }

    #[test]
    fn refuses_truncated_misaligned_oversized_and_bad_options() {
        let good = response(0, b"nonce-012345", 3478);
        assert_eq!(decode(&good[..59]), Err("truncated"));
        assert_eq!(decode(&good[..3]), Err("truncated"));
        let mut misaligned = good.clone();
        misaligned.push(0);
        assert_eq!(decode(&misaligned), Err("misaligned"));
        assert_eq!(decode(&vec![2u8; MAX_DATAGRAM + 1]), Err("oversized"));
        let mut option = good.clone();
        option.extend_from_slice(&[1, 0, 0, 8, 0, 0, 0, 0]);
        assert_eq!(decode(&option), Err("malformed option"));
        let mut fitted = good.clone();
        fitted.extend_from_slice(&[1, 0, 0, 3, 9, 9, 9, 0]);
        assert!(decode(&fitted).is_ok());
        let mut request_echo = good.clone();
        request_echo[1] = 1;
        assert_eq!(decode(&request_echo), Err("not a MAP response"));
        let mut v6 = good;
        v6[54] = 0;
        assert_eq!(decode(&v6), Err("external address is not IPv4"));
    }

    #[test]
    fn grant_without_lifetime_or_port_is_not_trusted() {
        let mut zero_lifetime = response(0, b"nonce-012345", 3478);
        zero_lifetime[4..8].copy_from_slice(&[0; 4]);
        assert!(matches!(
            judge(&request(), &zero_lifetime),
            Verdict::Ignore(_)
        ));
        let zero_port = response(0, b"nonce-012345", 0);
        assert!(matches!(judge(&request(), &zero_port), Verdict::Ignore(_)));
    }
}
