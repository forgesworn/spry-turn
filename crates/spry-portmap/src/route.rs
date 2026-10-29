//! The IPv4 default gateway, from the host's own route table.
//!
//! Linux (and Android where readable) uses `/proc/net/route`; macOS and the
//! BSDs run `route -n get default`; Windows runs `route print -4 0.0.0.0`.
//! Command output is read with a size limit and a deadline. Android apps
//! should pass the gateway from `LinkProperties` instead. The gateway is
//! never guessed.

use crate::Error;
use std::net::Ipv4Addr;

/// Largest route table or command output read.
const MAX_OUTPUT: usize = 64 * 1024;

/// The default route.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Route {
    pub gateway: Ipv4Addr,
    /// Interface name (or, on Windows, the interface address) when known.
    pub interface: Option<String>,
}

impl Route {
    /// Whether the default route leaves through what looks like a VPN or
    /// tunnel interface. A relay behind one cannot be reached (design 2.4).
    pub fn looks_like_tunnel(&self) -> bool {
        const PREFIXES: [&str; 8] = [
            "utun",
            "tun",
            "tap",
            "wg",
            "ipsec",
            "tailscale",
            "nordlynx",
            "zt",
        ];
        self.interface.as_deref().is_some_and(|name| {
            let name = name.to_ascii_lowercase();
            PREFIXES.iter().any(|prefix| name.starts_with(prefix))
        })
    }
}

fn usable(gateway: Ipv4Addr) -> bool {
    !(gateway.is_unspecified()
        || gateway.is_loopback()
        || gateway.is_multicast()
        || gateway.is_broadcast())
}

/// Parse Linux `/proc/net/route`: the up gateway route to 0.0.0.0/0 with the
/// lowest metric. Addresses are printed in host byte order.
pub fn parse_proc_net_route(text: &str) -> Option<Route> {
    let mut best: Option<(u32, Route)> = None;
    for line in text.lines().skip(1) {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 8 {
            continue;
        }
        let hex = |field: &str| u32::from_str_radix(field, 16).ok();
        let (Some(destination), Some(gateway), Some(flags), Some(mask)) = (
            hex(fields[1]),
            hex(fields[2]),
            hex(fields[3]),
            hex(fields[7]),
        ) else {
            continue;
        };
        let Ok(metric) = fields[6].parse::<u32>() else {
            continue;
        };
        // RTF_UP | RTF_GATEWAY
        if destination != 0 || mask != 0 || flags & 0x3 != 0x3 {
            continue;
        }
        let gateway = Ipv4Addr::from(gateway.to_ne_bytes());
        if !usable(gateway) || best.as_ref().is_some_and(|(known, _)| *known <= metric) {
            continue;
        }
        best = Some((
            metric,
            Route {
                gateway,
                interface: Some(fields[0].to_owned()),
            },
        ));
    }
    best.map(|(_, route)| route)
}

/// Parse `route -n get default` output from macOS or a BSD.
pub fn parse_bsd_route_get(text: &str) -> Option<Route> {
    let mut gateway = None;
    let mut interface = None;
    for line in text.lines() {
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        match key.trim() {
            "gateway" => gateway = value.trim().parse::<Ipv4Addr>().ok(),
            "interface" => interface = Some(value.trim().to_owned()),
            _ => {}
        }
    }
    gateway
        .filter(|&gateway| usable(gateway))
        .map(|gateway| Route { gateway, interface })
}

/// Parse `route print -4 0.0.0.0` output from Windows: rows of exactly five
/// fields `0.0.0.0 0.0.0.0 GATEWAY INTERFACE METRIC`, lowest metric wins.
/// Header words are localised, so only the row shape is used.
pub fn parse_windows_route_print(text: &str) -> Option<Route> {
    let mut best: Option<(u32, Route)> = None;
    for line in text.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() != 5 || fields[0] != "0.0.0.0" || fields[1] != "0.0.0.0" {
            continue;
        }
        let (Ok(gateway), Ok(interface), Ok(metric)) = (
            fields[2].parse::<Ipv4Addr>(),
            fields[3].parse::<Ipv4Addr>(),
            fields[4].parse::<u32>(),
        ) else {
            continue;
        };
        if !usable(gateway) || best.as_ref().is_some_and(|(known, _)| *known <= metric) {
            continue;
        }
        best = Some((
            metric,
            Route {
                gateway,
                interface: Some(interface.to_string()),
            },
        ));
    }
    best.map(|(_, route)| route)
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn read_table() -> Result<String, Error> {
    use std::io::Read;
    let mut text = String::new();
    std::fs::File::open("/proc/net/route")
        .map_err(|_| Error::NoGateway)?
        .take(MAX_OUTPUT as u64)
        .read_to_string(&mut text)
        .map_err(|_| Error::NoGateway)?;
    Ok(text)
}

/// Run a fixed system command with a deadline and bounded output.
#[cfg(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
    target_os = "dragonfly",
    windows
))]
fn run(program: &std::path::Path, args: &[&str]) -> Result<String, Error> {
    use std::io::Read;
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};
    let mut child = Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| Error::NoGateway)?;
    let stdout = child.stdout.take().ok_or(Error::NoGateway)?;
    let reader = std::thread::spawn(move || {
        let mut output = Vec::new();
        let _ = stdout.take(MAX_OUTPUT as u64).read_to_end(&mut output);
        output
    });
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(10)),
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(Error::NoGateway);
            }
        }
    }
    let output = reader.join().map_err(|_| Error::NoGateway)?;
    String::from_utf8(output).map_err(|_| Error::NoGateway)
}

/// Find the IPv4 default route from the host's route table.
pub fn default_route() -> Result<Route, Error> {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        parse_proc_net_route(&read_table()?).ok_or(Error::NoGateway)
    }
    #[cfg(any(
        target_os = "macos",
        target_os = "ios",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd",
        target_os = "dragonfly"
    ))]
    {
        let output = run(
            std::path::Path::new("/sbin/route"),
            &["-n", "get", "default"],
        )?;
        parse_bsd_route_get(&output).ok_or(Error::NoGateway)
    }
    #[cfg(windows)]
    {
        let root = std::env::var_os("SystemRoot").unwrap_or_else(|| "C:\\Windows".into());
        let program = std::path::Path::new(&root)
            .join("System32")
            .join("route.exe");
        let output = run(&program, &["print", "-4", "0.0.0.0"])?;
        parse_windows_route_print(&output).ok_or(Error::NoGateway)
    }
    #[cfg(not(any(
        target_os = "linux",
        target_os = "android",
        target_os = "macos",
        target_os = "ios",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd",
        target_os = "dragonfly",
        windows
    )))]
    {
        Err(Error::NoGateway)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_endian = "little")]
    #[test]
    fn reads_linux_route_table() {
        let table = "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n\
            wlan0\t00000000\t0101A8C0\t0003\t0\t0\t600\t00000000\t0\t0\t0\n\
            eth0\t00000000\t0100000A\t0003\t0\t0\t100\t00000000\t0\t0\t0\n\
            eth0\t0000000A\t00000000\t0001\t0\t0\t100\t00FFFFFF\t0\t0\t0\n\
            wg0\t00000000\t00000000\t0001\t0\t0\t50\t00000000\t0\t0\t0\n\
            down0\t00000000\t0202A8C0\t0002\t0\t0\t1\t00000000\t0\t0\t0\n";
        let route = parse_proc_net_route(table).unwrap();
        assert_eq!(route.gateway, Ipv4Addr::new(10, 0, 0, 1));
        assert_eq!(route.interface.as_deref(), Some("eth0"));
        assert_eq!(parse_proc_net_route("Iface\tDestination\n"), None);
        assert_eq!(
            parse_proc_net_route("header\ngarbage line with words\n"),
            None
        );
    }

    #[test]
    fn reads_bsd_route_get() {
        let output = "   route to: default\ndestination: default\n       mask: default\n    gateway: 192.168.1.254\n  interface: en0\n      flags: <UP,GATEWAY,DONE,STATIC,PRCLONING>\n";
        let route = parse_bsd_route_get(output).unwrap();
        assert_eq!(route.gateway, Ipv4Addr::new(192, 168, 1, 254));
        assert!(!route.looks_like_tunnel());
        let vpn = "   route to: default\n    gateway: 10.8.0.1\n  interface: utun4\n";
        assert!(parse_bsd_route_get(vpn).unwrap().looks_like_tunnel());
        assert_eq!(
            parse_bsd_route_get("route: writing to routing socket: not in table\n"),
            None
        );
        assert_eq!(parse_bsd_route_get("    gateway: utun3\n"), None);
    }

    #[test]
    fn reads_windows_route_print_in_any_language() {
        let output = "===========================================================================\n\
            Aktive Routen:\n\
            Netzwerkziel    Netzwerkmaske          Gateway    Schnittstelle Metrik\n\
                      0.0.0.0          0.0.0.0      192.168.178.1   192.168.178.20     35\n\
                      0.0.0.0          0.0.0.0         10.64.0.1       10.64.0.7     50\n\
            ===========================================================================\n\
            Ständige Routen:\n\
              Netzwerkadresse          Netzmaske  Gatewayadresse  Metrik\n\
                      0.0.0.0          0.0.0.0      192.168.0.1  Standard\n";
        let route = parse_windows_route_print(output).unwrap();
        assert_eq!(route.gateway, Ipv4Addr::new(192, 168, 178, 1));
        assert_eq!(route.interface.as_deref(), Some("192.168.178.20"));
        let on_link = "          0.0.0.0          0.0.0.0         On-link     10.0.0.5     5\n";
        assert_eq!(parse_windows_route_print(on_link), None);
    }
}
