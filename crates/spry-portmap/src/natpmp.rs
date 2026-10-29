//! NAT-PMP (RFC 6886).

use crate::udp::{self, Verdict};
use crate::{Error, Method, Protocol};
use std::net::{Ipv4Addr, SocketAddrV4};
use std::time::Duration;

const VERSION: u8 = 0;
const RESPONSE: u8 = 128;
pub const OP_EXTERNAL: u8 = 0;
/// Largest valid NAT-PMP response (a mapping answer).
const MAX_RESPONSE: usize = 16;

pub const fn opcode(protocol: Protocol) -> u8 {
    match protocol {
        Protocol::Udp => 1,
        Protocol::Tcp => 2,
    }
}

/// The external address request.
pub const EXTERNAL_REQUEST: [u8; 2] = [VERSION, OP_EXTERNAL];

/// Encode a mapping request. Lifetime 0 with external port 0 deletes.
pub fn encode_map(
    protocol: Protocol,
    internal_port: u16,
    external_port: u16,
    lifetime: u32,
) -> [u8; 12] {
    let mut out = [0u8; 12];
    out[0] = VERSION;
    out[1] = opcode(protocol);
    out[4..6].copy_from_slice(&internal_port.to_be_bytes());
    out[6..8].copy_from_slice(&external_port.to_be_bytes());
    out[8..12].copy_from_slice(&lifetime.to_be_bytes());
    out
}

/// A decoded NAT-PMP response.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Response {
    External {
        epoch: u32,
        address: Ipv4Addr,
    },
    Map {
        opcode: u8,
        epoch: u32,
        internal_port: u16,
        external_port: u16,
        lifetime: u32,
    },
    /// A non-zero result code. The other fields are undefined (RFC 6886 3.5).
    Error {
        opcode: u8,
        result: u16,
    },
}

fn u16_at(bytes: &[u8], at: usize) -> u16 {
    u16::from_be_bytes([bytes[at], bytes[at + 1]])
}
fn u32_at(bytes: &[u8], at: usize) -> u32 {
    u32::from_be_bytes([bytes[at], bytes[at + 1], bytes[at + 2], bytes[at + 3]])
}

/// Decode a datagram from the gateway's NAT-PMP port.
pub fn decode(bytes: &[u8]) -> Result<Response, &'static str> {
    if bytes.len() > MAX_RESPONSE {
        return Err("oversized");
    }
    if bytes.len() < 4 {
        return Err("truncated");
    }
    if bytes[0] != VERSION {
        return Err("wrong version");
    }
    if bytes[1] & RESPONSE == 0 {
        return Err("not a response");
    }
    let opcode = bytes[1] & !RESPONSE;
    let result = u16_at(bytes, 2);
    if result != 0 {
        return Ok(Response::Error { opcode, result });
    }
    match (opcode, bytes.len()) {
        (OP_EXTERNAL, 12) => Ok(Response::External {
            epoch: u32_at(bytes, 4),
            address: Ipv4Addr::new(bytes[8], bytes[9], bytes[10], bytes[11]),
        }),
        (1 | 2, 16) => Ok(Response::Map {
            opcode,
            epoch: u32_at(bytes, 4),
            internal_port: u16_at(bytes, 8),
            external_port: u16_at(bytes, 10),
            lifetime: u32_at(bytes, 12),
        }),
        (OP_EXTERNAL | 1 | 2, _) => Err("wrong length"),
        _ => Err("unknown opcode"),
    }
}

/// Words for a NAT-PMP result code (RFC 6886 3.5).
pub const fn reason(code: u16) -> &'static str {
    match code {
        1 => "unsupported version",
        2 => "not authorised or refused",
        3 => "network failure",
        4 => "out of resources",
        5 => "unsupported opcode",
        _ => "unknown result",
    }
}

fn refusal(result: u16) -> Error {
    if result == 1 {
        Error::UnsupportedVersion
    } else {
        Error::Refused {
            method: Method::NatPmp,
            code: result,
            reason: reason(result),
        }
    }
}

/// A successful mapping answer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Grant {
    pub external_port: u16,
    pub lifetime: u32,
    pub epoch: u32,
}

/// Ask `gateway` for its external address. Returns the address and epoch.
pub(crate) fn external(gateway: SocketAddrV4, budget: Duration) -> Result<(Ipv4Addr, u32), Error> {
    let (socket, _) = udp::connect(gateway)?;
    udp::exchange(&socket, &EXTERNAL_REQUEST, budget, |bytes| {
        match decode(bytes) {
            Ok(Response::External { epoch, address }) => Verdict::Done((address, epoch)),
            Ok(Response::Error {
                opcode: OP_EXTERNAL,
                result,
            }) => Verdict::Fail(refusal(result)),
            Ok(_) => Verdict::Ignore("reply for another request"),
            Err(reason) => Verdict::Ignore(reason),
        }
    })
}

/// Request, renew (same values again) or delete (lifetime 0, external 0) a
/// mapping.
pub(crate) fn map(
    gateway: SocketAddrV4,
    protocol: Protocol,
    internal_port: u16,
    external_port: u16,
    lifetime: u32,
    budget: Duration,
) -> Result<Grant, Error> {
    let (socket, _) = udp::connect(gateway)?;
    let request = encode_map(protocol, internal_port, external_port, lifetime);
    let wanted = opcode(protocol);
    udp::exchange(&socket, &request, budget, |bytes| {
        judge(bytes, wanted, internal_port, lifetime)
    })
}

pub(crate) fn judge(bytes: &[u8], wanted: u8, internal_port: u16, lifetime: u32) -> Verdict<Grant> {
    match decode(bytes) {
        Ok(Response::Map {
            opcode,
            epoch,
            internal_port: port,
            external_port,
            lifetime: granted,
        }) if opcode == wanted && port == internal_port => {
            if lifetime > 0 && (granted == 0 || external_port == 0) {
                return Verdict::Ignore("grant without lifetime or port");
            }
            Verdict::Done(Grant {
                external_port,
                lifetime: granted,
                epoch,
            })
        }
        Ok(Response::Error { opcode, result }) if opcode == wanted => {
            Verdict::Fail(refusal(result))
        }
        Ok(_) => Verdict::Ignore("reply for another request"),
        Err(reason) => Verdict::Ignore(reason),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requests_are_byte_exact() {
        assert_eq!(EXTERNAL_REQUEST, [0, 0]);
        assert_eq!(
            encode_map(Protocol::Tcp, 3478, 3478, 7200),
            [0, 2, 0, 0, 0x0d, 0x96, 0x0d, 0x96, 0, 0, 0x1c, 0x20]
        );
        assert_eq!(
            encode_map(Protocol::Udp, 50000, 0, 0),
            [0, 1, 0, 0, 0xc3, 0x50, 0, 0, 0, 0, 0, 0]
        );
    }

    #[test]
    fn decodes_external_and_translated_mapping() {
        let external = [0, 128, 0, 0, 0, 0, 1, 0, 198, 51, 100, 7];
        assert_eq!(
            decode(&external),
            Ok(Response::External {
                epoch: 256,
                address: Ipv4Addr::new(198, 51, 100, 7)
            })
        );
        let map = [
            0, 129, 0, 0, 0, 0, 0, 5, 0x0d, 0x96, 0x9c, 0x40, 0, 0, 0x0e, 0x10,
        ];
        let Verdict::Done(grant) = judge(&map, 1, 3478, 7200) else {
            panic!("expected a grant");
        };
        assert_eq!(
            grant,
            Grant {
                external_port: 40000,
                lifetime: 3600,
                epoch: 5
            }
        );
    }

    #[test]
    fn refuses_bad_shapes() {
        assert_eq!(decode(&[0, 128, 0]), Err("truncated"));
        assert_eq!(decode(&[0; 17]), Err("oversized"));
        assert_eq!(decode(&[1, 128, 0, 0]), Err("wrong version"));
        assert_eq!(decode(&[0, 1, 0, 0]), Err("not a response"));
        assert_eq!(decode(&[0, 128, 0, 0, 0, 0, 0, 0]), Err("wrong length"));
        assert_eq!(decode(&[0, 131, 0, 0, 0, 0, 0, 0]), Err("unknown opcode"));
        // A TCP answer to a UDP request, or for another port, is ignored.
        let tcp = [
            0, 130, 0, 0, 0, 0, 0, 5, 0x0d, 0x96, 0x0d, 0x96, 0, 0, 0x0e, 0x10,
        ];
        assert!(matches!(judge(&tcp, 1, 3478, 7200), Verdict::Ignore(_)));
        assert!(matches!(judge(&tcp, 2, 3479, 7200), Verdict::Ignore(_)));
        let zero = [0, 130, 0, 0, 0, 0, 0, 5, 0x0d, 0x96, 0, 0, 0, 0, 0x0e, 0x10];
        assert!(matches!(judge(&zero, 2, 3478, 7200), Verdict::Ignore(_)));
        // The same shape is the expected answer to a delete.
        assert!(matches!(judge(&zero, 2, 3478, 0), Verdict::Done(_)));
    }

    #[test]
    fn refusals_carry_the_code() {
        let refused = [0, 129, 0, 2];
        assert!(matches!(
            judge(&refused, 1, 3478, 7200),
            Verdict::Fail(Error::Refused { code: 2, .. })
        ));
        let version = [0, 129, 0, 1, 0, 0, 0, 0];
        assert!(matches!(
            judge(&version, 1, 3478, 7200),
            Verdict::Fail(Error::UnsupportedVersion)
        ));
    }
}
