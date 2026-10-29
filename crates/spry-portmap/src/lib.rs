#![forbid(unsafe_code)]
//! In-house router port mapping for a self-hosted Spry relay.
//!
//! [`PortMapper`] asks the default gateway for inbound mappings with PCP
//! (RFC 6887), then NAT-PMP (RFC 6886), then UPnP IGD, and keeps to the first
//! protocol that grants a mapping. It renews, removes and reports the
//! external address. [`record::Ledger`] remembers the mappings a process
//! created so that a later launch can remove what a crashed run left behind.
//!
//! Everything a router sends is parsed with fixed size limits and deadlines.
//! The API is blocking and uses only the standard library sockets; an async
//! host runs it on a blocking thread. No request ever leaves the local
//! network: PCP and NAT-PMP go only to the default gateway, and UPnP
//! descriptions and control URLs are followed only when they name the
//! gateway itself.

mod address;
pub mod check;
mod error;
pub mod http;
mod mapper;
pub mod natpmp;
pub mod pcp;
pub mod record;
pub mod route;
mod udp;
pub mod upnp;
pub mod xml;

#[cfg(feature = "testing")]
pub mod fake;

pub use address::{AddressKind, classify};
pub use error::Error;
pub use mapper::{
    Attempt, Cleanup, Clock, Mapping, Options, Owner, PortMapper, Renewal, Request,
    epoch_consistent,
};

/// Transport protocol of a mapping.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Protocol {
    Udp,
    Tcp,
}

impl Protocol {
    /// IANA protocol number, as PCP carries it.
    pub const fn number(self) -> u8 {
        match self {
            Self::Udp => 17,
            Self::Tcp => 6,
        }
    }
    /// Upper-case name, as UPnP carries it.
    pub const fn name(self) -> &'static str {
        match self {
            Self::Udp => "UDP",
            Self::Tcp => "TCP",
        }
    }
    /// Parse `udp` or `tcp`, any case.
    pub fn parse(value: &str) -> Option<Self> {
        if value.eq_ignore_ascii_case("udp") {
            Some(Self::Udp)
        } else if value.eq_ignore_ascii_case("tcp") {
            Some(Self::Tcp)
        } else {
            None
        }
    }
}

/// Mapping protocol, in the order they are tried.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Method {
    Pcp,
    NatPmp,
    Upnp,
}

impl Method {
    /// Default fallback order: PCP, then NAT-PMP, then UPnP IGD.
    pub const ORDER: [Method; 3] = [Method::Pcp, Method::NatPmp, Method::Upnp];

    pub const fn name(self) -> &'static str {
        match self {
            Self::Pcp => "PCP",
            Self::NatPmp => "NAT-PMP",
            Self::Upnp => "UPnP IGD",
        }
    }
    /// Short token used in the record file.
    pub const fn token(self) -> &'static str {
        match self {
            Self::Pcp => "pcp",
            Self::NatPmp => "natpmp",
            Self::Upnp => "upnp",
        }
    }
    pub fn from_token(value: &str) -> Option<Self> {
        Self::ORDER
            .into_iter()
            .find(|method| method.token() == value)
    }
}

impl std::fmt::Display for Method {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}

impl std::fmt::Display for Protocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}
