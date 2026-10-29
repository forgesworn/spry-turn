use std::net::Ipv4Addr;

/// What an external address reported by a router says about the network.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AddressKind {
    /// A public address: hosting may be possible.
    Public,
    /// 100.64.0.0/10: the provider shares one address between customers.
    CarrierGradeNat,
    /// RFC 1918: there is a second router between this one and the internet.
    Private,
    /// Unspecified, loopback, link-local, multicast, documentation or
    /// otherwise reserved: the router's answer cannot be used.
    Unusable,
}

/// Classify a router's reported external address (design 2.4). This is the
/// router's own claim; it is not compared with any outside answer here.
pub fn classify(address: Ipv4Addr) -> AddressKind {
    let [a, b, c, _] = address.octets();
    if a == 100 && (64..128).contains(&b) {
        return AddressKind::CarrierGradeNat;
    }
    if address.is_private() {
        return AddressKind::Private;
    }
    let reserved = address.is_unspecified()
        || address.is_loopback()
        || address.is_link_local()
        || address.is_multicast()
        || address.is_broadcast()
        || address.is_documentation()
        || a == 0
        || a >= 240
        || (a == 192 && b == 0 && c == 0)
        || (a == 198 && (b == 18 || b == 19));
    if reserved {
        AddressKind::Unusable
    } else {
        AddressKind::Public
    }
}

impl AddressKind {
    /// Plain words for a diagnostic.
    pub const fn describe(self) -> &'static str {
        match self {
            Self::Public => "public address",
            Self::CarrierGradeNat => {
                "shared provider address (carrier-grade NAT): nothing outside can reach this computer"
            }
            Self::Private => {
                "private address: a second router sits between this one and the internet"
            }
            Self::Unusable => "not a usable internet address",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_the_design_cases() {
        let cases = [
            ("203.0.113.9", AddressKind::Unusable),
            ("128.66.0.1", AddressKind::Public),
            ("100.64.0.1", AddressKind::CarrierGradeNat),
            ("100.127.255.254", AddressKind::CarrierGradeNat),
            ("100.128.0.1", AddressKind::Public),
            ("10.1.2.3", AddressKind::Private),
            ("172.16.0.1", AddressKind::Private),
            ("192.168.0.1", AddressKind::Private),
            ("0.0.0.0", AddressKind::Unusable),
            ("127.0.0.1", AddressKind::Unusable),
            ("169.254.1.1", AddressKind::Unusable),
            ("224.0.0.1", AddressKind::Unusable),
            ("255.255.255.255", AddressKind::Unusable),
            ("198.18.0.1", AddressKind::Unusable),
            ("192.0.0.8", AddressKind::Unusable),
        ];
        for (address, kind) in cases {
            assert_eq!(classify(address.parse().unwrap()), kind, "{address}");
        }
    }
}
