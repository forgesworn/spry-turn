//! Which connections the HTTP service accepts, and whose forwarded client
//! address it believes.
//!
//! By default the service listens on loopback only and the reverse proxy
//! sits beside it. An operator whose proxy is on another container or host
//! can instead bind a named non-loopback address, but only with an explicit
//! list of the proxy addresses allowed to connect. Peers outside that list
//! are closed before any HTTP is read, and only listed peers are believed
//! when they name the client in `X-Forwarded-For`.
use crate::public::SetupError;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

const PROXIES_REQUIRED: SetupError = SetupError(
    "SPRY_HTTP_BIND beyond loopback needs SPRY_HTTP_TRUSTED_PROXIES naming the reverse proxy addresses",
);
const PROXIES_LOOPBACK: SetupError =
    SetupError("SPRY_HTTP_TRUSTED_PROXIES applies only to a SPRY_HTTP_BIND beyond loopback");
const PROXIES_INVALID: SetupError = SetupError(
    "SPRY_HTTP_TRUSTED_PROXIES must list IP addresses or CIDR ranges separated by commas",
);
const PROXIES_BROAD: SetupError = SetupError(
    "SPRY_HTTP_TRUSTED_PROXIES must name proxies, not whole networks: ranges need at least /8 for IPv4 or /32 for IPv6",
);

/// Smallest accepted prefix lengths: wide enough for a container network,
/// too narrow to be a "trust everyone" setting.
const MIN_V4_PREFIX: u8 = 8;
const MIN_V6_PREFIX: u8 = 32;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Network {
    address: IpAddr,
    prefix: u8,
}
impl Network {
    fn parse(entry: &str) -> Result<Self, SetupError> {
        let (address, prefix) = match entry.split_once('/') {
            Some((address, prefix)) => (address, Some(prefix)),
            None => (entry, None),
        };
        let address: IpAddr = address.parse().map_err(|_| PROXIES_INVALID)?;
        let (width, minimum) = match address {
            IpAddr::V4(_) => (32, MIN_V4_PREFIX),
            IpAddr::V6(ip) if ip.to_ipv4_mapped().is_some() => return Err(PROXIES_INVALID),
            IpAddr::V6(_) => (128, MIN_V6_PREFIX),
        };
        let prefix = match prefix {
            None => width,
            Some(prefix) => {
                if prefix.is_empty() || !prefix.bytes().all(|b| b.is_ascii_digit()) {
                    return Err(PROXIES_INVALID);
                }
                let prefix: u8 = prefix.parse().map_err(|_| PROXIES_INVALID)?;
                if prefix > width {
                    return Err(PROXIES_INVALID);
                }
                if prefix < minimum {
                    return Err(PROXIES_BROAD);
                }
                prefix
            }
        };
        if address.is_unspecified() || address.is_multicast() {
            return Err(PROXIES_INVALID);
        }
        Ok(Self {
            address: mask(address, prefix),
            prefix,
        })
    }
    fn contains(&self, ip: IpAddr) -> bool {
        match (self.address, ip) {
            (IpAddr::V4(_), IpAddr::V4(_)) | (IpAddr::V6(_), IpAddr::V6(_)) => {
                mask(ip, self.prefix) == self.address
            }
            _ => false,
        }
    }
}
fn mask(ip: IpAddr, prefix: u8) -> IpAddr {
    match ip {
        IpAddr::V4(ip) => {
            let bits = u32::from(ip) & u32::MAX.checked_shl(32 - u32::from(prefix)).unwrap_or(0);
            IpAddr::V4(Ipv4Addr::from(bits))
        }
        IpAddr::V6(ip) => {
            let bits = u128::from(ip) & u128::MAX.checked_shl(128 - u32::from(prefix)).unwrap_or(0);
            IpAddr::V6(Ipv6Addr::from(bits))
        }
    }
}

/// How the HTTP listener treats its peers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum ProxyPolicy {
    /// The default: loopback only, with the proxy beside the service. A
    /// loopback peer is the proxy.
    Loopback,
    /// A bind beyond loopback: only these peers connect, and only they are
    /// believed about the client.
    Trusted(Vec<Network>),
}
impl ProxyPolicy {
    /// Decide the policy from the bind address and `SPRY_HTTP_TRUSTED_PROXIES`.
    pub(crate) fn configure(bind: IpAddr, trusted: Option<&str>) -> Result<Self, SetupError> {
        match (bind.is_loopback(), trusted) {
            (true, None) => Ok(Self::Loopback),
            (true, Some(_)) => Err(PROXIES_LOOPBACK),
            (false, None) => Err(PROXIES_REQUIRED),
            (false, Some(list)) => {
                let networks = list
                    .split(',')
                    .map(|entry| Network::parse(entry.trim()))
                    .collect::<Result<Vec<_>, _>>()?;
                Ok(Self::Trusted(networks))
            }
        }
    }
    /// Whether a connection from `peer` is served at all.
    pub(crate) fn admits(&self, peer: IpAddr) -> bool {
        match self {
            Self::Loopback => true,
            Self::Trusted(_) => self.trusts(peer),
        }
    }
    /// Whether `peer` is a proxy whose forwarded client address is believed.
    pub(crate) fn trusts(&self, peer: IpAddr) -> bool {
        match self {
            Self::Loopback => peer.is_loopback(),
            Self::Trusted(networks) => {
                let peer = match peer {
                    IpAddr::V6(ip) => ip.to_ipv4_mapped().map_or(peer, IpAddr::V4),
                    peer => peer,
                };
                networks.iter().any(|network| network.contains(peer))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(text: &str) -> IpAddr {
        text.parse().unwrap()
    }

    #[test]
    fn nothing_set_means_loopback_only() {
        let policy = ProxyPolicy::configure(ip("127.0.0.1"), None).unwrap();
        assert_eq!(policy, ProxyPolicy::Loopback);
        assert!(policy.trusts(ip("127.0.0.1")));
        assert!(!policy.trusts(ip("192.0.2.1")));
    }

    #[test]
    fn a_bind_beyond_loopback_needs_a_trusted_list() {
        for bind in ["192.0.2.10", "0.0.0.0", "2001:db8::10", "::"] {
            assert_eq!(
                ProxyPolicy::configure(ip(bind), None),
                Err(PROXIES_REQUIRED),
                "{bind}"
            );
            for empty in ["", " ", ","] {
                assert!(
                    ProxyPolicy::configure(ip(bind), Some(empty)).is_err(),
                    "{empty:?}"
                );
            }
        }
    }

    #[test]
    fn a_list_on_a_loopback_bind_is_refused() {
        assert_eq!(
            ProxyPolicy::configure(ip("127.0.0.1"), Some("192.0.2.1")),
            Err(PROXIES_LOOPBACK)
        );
    }

    #[test]
    fn wildcard_and_near_wildcard_trust_is_refused() {
        for entry in [
            "0.0.0.0/0",
            "::/0",
            "0.0.0.0",
            "::",
            "128.0.0.0/1",
            "192.0.2.0/7",
            "2001:db8::/31",
            "8000::/1",
            "192.0.2.1,0.0.0.0/0",
        ] {
            assert!(
                ProxyPolicy::configure(ip("192.0.2.10"), Some(entry)).is_err(),
                "{entry}"
            );
        }
    }

    #[test]
    fn malformed_entries_are_refused() {
        for entry in [
            "proxy.example",
            "192.0.2.1/",
            "192.0.2.1/33",
            "192.0.2.1/+24",
            "192.0.2.1/-1",
            "192.0.2.0/24/1",
            "2001:db8::/129",
            "::ffff:192.0.2.1",
            "224.0.0.1",
            "192.0.2.1,,192.0.2.2",
        ] {
            assert!(
                ProxyPolicy::configure(ip("192.0.2.10"), Some(entry)).is_err(),
                "{entry}"
            );
        }
    }

    #[test]
    fn only_listed_peers_are_admitted_and_trusted() {
        let policy = ProxyPolicy::configure(
            ip("0.0.0.0"),
            Some("192.0.2.7, 198.51.100.0/24 ,2001:db8:1::/48"),
        )
        .unwrap();
        for peer in [
            "192.0.2.7",
            "198.51.100.0",
            "198.51.100.255",
            "2001:db8:1:ffff::1",
            "::ffff:192.0.2.7",
        ] {
            assert!(policy.admits(ip(peer)) && policy.trusts(ip(peer)), "{peer}");
        }
        for peer in [
            "127.0.0.1",
            "192.0.2.8",
            "198.51.101.1",
            "203.0.113.5",
            "2001:db8:2::1",
            "::1",
            "::ffff:203.0.113.5",
        ] {
            assert!(
                !policy.admits(ip(peer)) && !policy.trusts(ip(peer)),
                "{peer}"
            );
        }
    }
}
