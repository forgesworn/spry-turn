//! `spry-node portmap check`: try the router's automatic port opening on a
//! test port, print what worked and remove the mapping. No relay starts.

use spry_portmap::check::{self, CheckOptions};
use spry_portmap::{Options, Protocol};
use std::ffi::OsString;
use std::net::Ipv4Addr;

const USAGE: &str =
    "Usage: spry-node portmap check [--port PORT] [--protocol udp|tcp|both] [--gateway IPV4]

Asks the default gateway to open PORT (random high port by default) with
PCP, then NAT-PMP, then UPnP IGD, prints what worked and removes the mapping.
No relay is started and nothing listens on the port. --gateway names the
gateway when the route table cannot be read.";

/// Parsed `portmap check` arguments.
#[derive(Debug, PartialEq, Eq)]
pub struct Arguments {
    pub port: Option<u16>,
    pub protocols: Vec<Protocol>,
    pub gateway: Option<Ipv4Addr>,
}

/// Parse the arguments after `portmap`. `Ok(None)` asks for the usage text.
pub fn parse(args: &[OsString]) -> Result<Option<Arguments>, &'static str> {
    let mut args = args
        .iter()
        .map(|arg| arg.to_str().ok_or("arguments must be text"));
    match args.next().transpose()? {
        Some("check") => {}
        Some("--help" | "-h" | "help") | None => return Ok(None),
        Some(_) => return Err("unknown portmap command"),
    }
    let mut parsed = Arguments {
        port: None,
        protocols: vec![Protocol::Udp, Protocol::Tcp],
        gateway: None,
    };
    while let Some(flag) = args.next().transpose()? {
        let mut value = || args.next().transpose()?.ok_or("missing value");
        match flag {
            "--port" => {
                let port: u16 = value()?.parse().map_err(|_| "invalid --port")?;
                if port < 1024 {
                    return Err("--port must be 1024 or higher");
                }
                parsed.port = Some(port);
            }
            "--protocol" => {
                parsed.protocols = match value()? {
                    "both" => vec![Protocol::Udp, Protocol::Tcp],
                    other => vec![Protocol::parse(other).ok_or("invalid --protocol")?],
                };
            }
            "--gateway" => {
                parsed.gateway = Some(value()?.parse().map_err(|_| "invalid --gateway")?);
            }
            "--help" | "-h" => return Ok(None),
            _ => return Err("unknown option"),
        }
    }
    Ok(Some(parsed))
}

/// Run `spry-node portmap ...` and return the process exit code.
pub fn command(args: &[OsString]) -> i32 {
    let arguments = match parse(args) {
        Ok(Some(arguments)) => arguments,
        Ok(None) => {
            println!("{USAGE}");
            return 0;
        }
        Err(problem) => {
            eprintln!("spry-node portmap: {problem}.\n\n{USAGE}");
            return 2;
        }
    };
    let report = check::run(CheckOptions {
        mapper: Options {
            gateway: arguments.gateway,
            ..Options::default()
        },
        port: arguments.port,
        protocols: arguments.protocols,
        ..CheckOptions::default()
    });
    print!("{report}");
    if report.succeeded() { 0 } else { 1 }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(values: &[&str]) -> Vec<OsString> {
        values.iter().map(OsString::from).collect()
    }

    #[test]
    fn parses_check_options() {
        assert_eq!(
            parse(&args(&[
                "check",
                "--port",
                "50000",
                "--protocol",
                "tcp",
                "--gateway",
                "192.168.1.1"
            ])),
            Ok(Some(Arguments {
                port: Some(50000),
                protocols: vec![Protocol::Tcp],
                gateway: Some(Ipv4Addr::new(192, 168, 1, 1)),
            }))
        );
        assert_eq!(
            parse(&args(&["check"])).unwrap().unwrap().protocols,
            [Protocol::Udp, Protocol::Tcp]
        );
        assert_eq!(parse(&args(&[])), Ok(None));
        assert_eq!(parse(&args(&["check", "--help"])), Ok(None));
    }

    #[test]
    fn refuses_bad_options() {
        for (values, problem) in [
            (&["open"][..], "unknown portmap command"),
            (&["check", "--port"][..], "missing value"),
            (
                &["check", "--port", "80"][..],
                "--port must be 1024 or higher",
            ),
            (&["check", "--port", "x"][..], "invalid --port"),
            (&["check", "--protocol", "sctp"][..], "invalid --protocol"),
            (
                &["check", "--gateway", "router.lan"][..],
                "invalid --gateway",
            ),
            (&["check", "--verbose"][..], "unknown option"),
        ] {
            assert_eq!(parse(&args(values)), Err(problem), "{values:?}");
        }
    }

    #[test]
    fn usage_exits_cleanly_and_errors_exit_two() {
        assert_eq!(command(&args(&["--help"])), 0);
        assert_eq!(command(&args(&["nonsense"])), 2);
    }
}
