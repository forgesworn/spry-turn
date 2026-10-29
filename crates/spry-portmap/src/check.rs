//! `spry-node portmap check`: map a test port, report what worked, remove it.
//! No relay is started and nothing listens on the port.

use crate::{
    AddressKind, Attempt, Error, Mapping, Method, Options, PortMapper, Protocol, Request, classify,
};
use std::fmt;
use std::net::Ipv4Addr;
use std::time::Duration;

/// What to check.
#[derive(Clone, Debug)]
pub struct CheckOptions {
    pub mapper: Options,
    /// Port to map; `None` picks a random port from 49152 to 65535.
    pub port: Option<u16>,
    pub protocols: Vec<Protocol>,
    /// Lease asked for; short, so a crash leaves little behind.
    pub lifetime: Duration,
}

impl Default for CheckOptions {
    fn default() -> Self {
        Self {
            mapper: Options::default(),
            port: None,
            protocols: vec![Protocol::Udp, Protocol::Tcp],
            lifetime: Duration::from_secs(120),
        }
    }
}

/// One protocol's result.
#[derive(Clone, Debug)]
pub struct Outcome {
    pub protocol: Protocol,
    pub mapping: Result<Mapping, Error>,
    /// Removal result, when a mapping was granted.
    pub removed: Option<Result<(), Error>>,
}

/// Everything the check found.
#[derive(Clone, Debug, Default)]
pub struct Report {
    pub setup: Option<Error>,
    pub gateway: Option<Ipv4Addr>,
    pub interface: Option<String>,
    pub tunnel: bool,
    pub local: Option<Ipv4Addr>,
    pub port: u16,
    pub attempts: Vec<Attempt>,
    pub method: Option<Method>,
    pub external: Option<Ipv4Addr>,
    pub outcomes: Vec<Outcome>,
}

impl Report {
    /// At least one mapping was granted and every granted mapping removed.
    pub fn succeeded(&self) -> bool {
        self.outcomes.iter().any(|outcome| outcome.mapping.is_ok())
            && self
                .outcomes
                .iter()
                .all(|outcome| outcome.removed.as_ref().is_none_or(Result::is_ok))
    }
}

fn random_port() -> u16 {
    let mut bytes = [0u8; 2];
    let _ = getrandom::fill(&mut bytes);
    49152 + u16::from_be_bytes(bytes) % 16384
}

/// Run the check.
pub fn run(options: CheckOptions) -> Report {
    let port = options.port.unwrap_or_else(random_port);
    let mut report = Report {
        port,
        ..Report::default()
    };
    let mut mapper = match PortMapper::new(options.mapper) {
        Ok(mapper) => mapper,
        Err(error) => {
            report.setup = Some(error);
            return report;
        }
    };
    report.gateway = Some(mapper.gateway());
    report.local = Some(mapper.local());
    report.interface = mapper.interface().map(str::to_owned);
    report.tunnel = crate::route::Route {
        gateway: mapper.gateway(),
        interface: report.interface.clone(),
    }
    .looks_like_tunnel();
    for protocol in options.protocols {
        let result = mapper.map(Request::new(protocol, port, options.lifetime));
        if report.method.is_none() {
            report.attempts = mapper.attempts().to_vec();
        }
        report.method = mapper.method();
        let removed = result.as_ref().ok().map(|mapping| mapper.remove(mapping));
        if let Ok(mapping) = &result {
            report.external = Some(*mapping.external.ip());
        }
        // When no protocol answered at all, another transport will not
        // fare better; stop rather than repeat every timeout.
        let nothing_granted = matches!(result, Err(Error::NoMethod(_)));
        report.outcomes.push(Outcome {
            protocol,
            mapping: result,
            removed,
        });
        if nothing_granted {
            break;
        }
    }
    report
}

impl fmt::Display for Report {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(error) = &self.setup {
            writeln!(f, "Could not start: {error}.")?;
            return writeln!(
                f,
                "No default gateway was found. Connect to your home network and try again."
            );
        }
        if let Some(gateway) = self.gateway {
            match &self.interface {
                Some(interface) => writeln!(f, "Gateway: {gateway} (via {interface})")?,
                None => writeln!(f, "Gateway: {gateway}")?,
            }
        }
        if let Some(local) = self.local {
            writeln!(f, "This computer: {local}")?;
        }
        writeln!(f, "Test port: {}", self.port)?;
        for (method, error) in &self.attempts {
            writeln!(f, "{method}: {error}")?;
        }
        if let Some(method) = self.method {
            writeln!(f, "{method}: granted")?;
        }
        if let Some(external) = self.external {
            writeln!(
                f,
                "External address: {external} ({})",
                classify(external).describe()
            )?;
        }
        for outcome in &self.outcomes {
            match &outcome.mapping {
                Ok(mapping) => {
                    let lease = match mapping.lifetime {
                        Some(lifetime) => format!("lease {} s", lifetime.as_secs()),
                        None => "permanent lease".to_owned(),
                    };
                    let translated = if mapping.translated() {
                        " (translated)"
                    } else {
                        ""
                    };
                    writeln!(
                        f,
                        "{} {}: external port {}{translated}, {lease}",
                        outcome.protocol,
                        self.port,
                        mapping.external.port()
                    )?;
                }
                Err(Error::NoMethod(_)) => {
                    writeln!(f, "{} {}: not granted", outcome.protocol, self.port)?
                }
                Err(error) => writeln!(
                    f,
                    "{} {}: not granted ({error})",
                    outcome.protocol, self.port
                )?,
            }
            match &outcome.removed {
                Some(Ok(())) => writeln!(f, "{} {}: removed", outcome.protocol, self.port)?,
                Some(Err(error)) => writeln!(
                    f,
                    "{} {}: NOT removed ({error}); it ends when its lease does, or remove it in the router's settings",
                    outcome.protocol, self.port
                )?,
                None => {}
            }
        }
        if self
            .outcomes
            .iter()
            .any(|outcome| outcome.mapping.as_ref().is_ok_and(Mapping::is_permanent))
        {
            writeln!(
                f,
                "This router grants only permanent mappings. A relay removes them when it stops and again on its next launch, but one may outlive a crash."
            )?;
        }
        if self.tunnel {
            writeln!(
                f,
                "A VPN appears to be on. People can't reach a relay behind it."
            )?;
        }
        let verdict = if self.succeeded() {
            match self.external.map(classify) {
                Some(AddressKind::Public) | None => {
                    "Automatic port opening works here. Reachability from outside is not tested by this check."
                }
                Some(AddressKind::CarrierGradeNat) => {
                    "The router opened the port, but your internet provider shares one address between many customers, so nothing outside can reach this computer."
                }
                Some(AddressKind::Private) => {
                    "The router opened the port, but there's a second router between you and the internet. Automatic setup can't open it."
                }
                Some(AddressKind::Unusable) => {
                    "The router opened the port but reported an address that can't be reached from the internet."
                }
            }
        } else if self.method.is_none() {
            "Your router didn't allow automatic setup. Turn on UPnP in its settings, or ask whoever runs your network."
        } else {
            "Automatic setup only partly worked; see the lines above."
        };
        writeln!(f, "{verdict}")
    }
}
