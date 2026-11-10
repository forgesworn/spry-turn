use crate::public::SetupError;
use std::{env, net::Ipv4Addr, path::Path};
use tokio::process::Command;

/// Standard-profile configuration, resolved once before any relay is started.
/// The private peer profile keeps its existing configuration and limits.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Settings {
    pub turn_port: u16,
    pub tls_port: u16,
    pub relay_ports: (u16, u16),
    pub bytes_per_second: u64,
    pub aggregate_bytes_per_second: Option<u64>,
    limits: Limits,
    direct_tls: bool,
    advertise_tls: bool,
    tls_443: bool,
    certificate: String,
    key: String,
}

/// Relay admission limits. Existing defaults stay small; an operator can
/// explicitly budget a larger group without removing a finite ceiling.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Limits {
    allocations: u32,
    per_user: u32,
    connections: u32,
}

const DEFAULT_ALLOCATIONS: u32 = 32;
const DEFAULT_PER_USER: u32 = 8;
const DEFAULT_CONNECTIONS: u32 = 64;
pub(crate) const MAX_ALLOCATIONS: u32 = 512;
pub(crate) const MAX_PER_USER: u32 = 64;
// Leave bounded room for new-route handshakes while old sockets unwind.
// The allocation and per-user quotas remain independent.
pub(crate) const MAX_CONNECTIONS: u32 = 512;
pub(crate) const MAX_BYTES_PER_SECOND: u64 = 64 * 1024 * 1024;
const TURN_PORT: SetupError = SetupError("SPRY_TURN_PORT must be an integer from 1 to 65535");
const TLS_PORT: SetupError =
    SetupError("SPRY_TLS_PORT must be an integer from 1 to 65535 and differ from SPRY_TURN_PORT");
const RELAY_PORTS: SetupError = SetupError(
    "SPRY_RELAY_PORTS must be FIRST:LAST from 1 to 65535, in order and outside the TURN/TLS listener ports",
);
const BANDWIDTH: SetupError =
    SetupError("SPRY_BYTES_PER_SECOND must be an integer from 1 to 67108864");
const AGGREGATE: SetupError =
    SetupError("SPRY_AGGREGATE_BYTES_PER_SECOND must be an integer from 1 to 67108864");
const ALLOCATIONS: SetupError =
    SetupError("SPRY_MAX_ALLOCATIONS must be a decimal integer from 1 to 512");
const PER_USER: SetupError = SetupError(
    "SPRY_MAX_ALLOCATIONS_PER_USER must be a decimal integer from 1 to 64 and not exceed SPRY_MAX_ALLOCATIONS",
);
const CONNECTIONS: SetupError =
    SetupError("SPRY_MAX_TCP_CONNECTIONS must be a decimal integer from 1 to 512");
const TLS_FILES: SetupError = SetupError(
    "SPRY_TLS_CERT_FILE and SPRY_TLS_KEY_FILE must name certificate and key files together",
);

fn port(value: &str) -> Option<u16> {
    (!value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit()))
        .then(|| value.parse::<u16>().ok())
        .flatten()
        .filter(|value| *value != 0)
}

/// A plain decimal integer from 1 to `maximum`: no sign, space or empty value.
pub(crate) fn bounded(value: &str, maximum: u32) -> Option<u32> {
    (!value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit()))
        .then(|| value.parse::<u32>().ok())
        .flatten()
        .filter(|value| (1..=maximum).contains(value))
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            allocations: DEFAULT_ALLOCATIONS,
            per_user: DEFAULT_PER_USER,
            connections: DEFAULT_CONNECTIONS,
        }
    }
}

impl Limits {
    fn parse(
        allocations: Option<&str>,
        per_user: Option<&str>,
        connections: Option<&str>,
    ) -> Result<Self, SetupError> {
        let allocations = match allocations {
            Some(value) => bounded(value, MAX_ALLOCATIONS).ok_or(ALLOCATIONS)?,
            None => DEFAULT_ALLOCATIONS,
        };
        // An unset per-user limit follows a lowered total rather than refusing
        // startup; an explicit one above the total is refused.
        let per_user = match per_user {
            Some(value) => bounded(value, MAX_PER_USER)
                .filter(|value| *value <= allocations)
                .ok_or(PER_USER)?,
            None => DEFAULT_PER_USER.min(allocations),
        };
        let connections = match connections {
            Some(value) => bounded(value, MAX_CONNECTIONS).ok_or(CONNECTIONS)?,
            None => DEFAULT_CONNECTIONS,
        };
        Ok(Self {
            allocations,
            per_user,
            connections,
        })
    }
}

fn setting(name: &str, invalid: SetupError) -> Result<Option<String>, SetupError> {
    match env::var(name) {
        Ok(value) => Ok(Some(value)),
        Err(env::VarError::NotPresent) => Ok(None),
        Err(env::VarError::NotUnicode(_)) => Err(invalid),
    }
}

impl Settings {
    fn parse(
        turn: Option<&str>,
        tls: Option<&str>,
        relay: Option<&str>,
        bandwidth: Option<&str>,
    ) -> Result<Self, SetupError> {
        let turn_port = port(turn.unwrap_or("3478")).ok_or(TURN_PORT)?;
        let tls_port = port(tls.unwrap_or("5349"))
            .filter(|port| *port != turn_port)
            .ok_or(TLS_PORT)?;
        let (first, last) = relay
            .unwrap_or("49160:49191")
            .split_once(':')
            .ok_or(RELAY_PORTS)?;
        let first = port(first).ok_or(RELAY_PORTS)?;
        let last = port(last).ok_or(RELAY_PORTS)?;
        if first > last || (first..=last).contains(&turn_port) || (first..=last).contains(&tls_port)
        {
            return Err(RELAY_PORTS);
        }
        let raw = bandwidth.unwrap_or("1000000");
        let bytes_per_second = (!raw.is_empty() && raw.bytes().all(|byte| byte.is_ascii_digit()))
            .then(|| raw.parse::<u64>().ok())
            .flatten()
            .filter(|value| (1..=MAX_BYTES_PER_SECOND).contains(value))
            .ok_or(BANDWIDTH)?;
        Ok(Self {
            turn_port,
            tls_port,
            relay_ports: (first, last),
            bytes_per_second,
            aggregate_bytes_per_second: None,
            limits: Limits::default(),
            direct_tls: false,
            advertise_tls: false,
            tls_443: false,
            certificate: "/data/tls/fullchain.pem".into(),
            key: "/data/tls/privkey.pem".into(),
        })
    }

    pub fn from_environment() -> Result<Self, SetupError> {
        let turn = setting("SPRY_TURN_PORT", TURN_PORT)?;
        let tls = setting("SPRY_TLS_PORT", TLS_PORT)?;
        let relay = setting("SPRY_RELAY_PORTS", RELAY_PORTS)?;
        let bandwidth = setting("SPRY_BYTES_PER_SECOND", BANDWIDTH)?;
        let mut settings = Self::parse(
            turn.as_deref(),
            tls.as_deref(),
            relay.as_deref(),
            bandwidth.as_deref(),
        )?;
        let allocations = setting("SPRY_MAX_ALLOCATIONS", ALLOCATIONS)?;
        let per_user = setting("SPRY_MAX_ALLOCATIONS_PER_USER", PER_USER)?;
        let connections = setting("SPRY_MAX_TCP_CONNECTIONS", CONNECTIONS)?;
        settings.limits = Limits::parse(
            allocations.as_deref(),
            per_user.as_deref(),
            connections.as_deref(),
        )?;
        settings.aggregate_bytes_per_second =
            setting("SPRY_AGGREGATE_BYTES_PER_SECOND", AGGREGATE)?
                .map(|value| {
                    bounded(&value, MAX_BYTES_PER_SECOND as u32)
                        .map(u64::from)
                        .ok_or(AGGREGATE)
                })
                .transpose()?;
        let certificate = setting("SPRY_TLS_CERT_FILE", TLS_FILES)?;
        let key = setting("SPRY_TLS_KEY_FILE", TLS_FILES)?;
        let explicit = certificate.is_some() || key.is_some();
        if certificate.is_some() != key.is_some() {
            return Err(TLS_FILES);
        }
        if let (Some(certificate), Some(key)) = (certificate, key) {
            settings.certificate = certificate;
            settings.key = key;
        }
        settings.direct_tls =
            Path::new(&settings.certificate).is_file() && Path::new(&settings.key).is_file();
        if explicit && !settings.direct_tls {
            return Err(TLS_FILES);
        }
        settings.advertise_tls =
            settings.direct_tls || env::var("SPRY_TLS_GATE").as_deref() == Ok("true");
        settings.tls_443 = match setting("SPRY_TLS_443", TLS_PORT)?.as_deref() {
            None | Some("false") => false,
            Some("true") => true,
            Some(_) => return Err(SetupError("SPRY_TLS_443 must be true or false")),
        };
        Ok(settings)
    }

    pub fn urls(&self, host: &str) -> Vec<String> {
        let mut urls = vec![
            format!("turn:{host}:{}?transport=udp", self.turn_port),
            format!("turn:{host}:{}?transport=tcp", self.turn_port),
        ];
        if self.advertise_tls {
            urls.push(format!("turns:{host}:{}?transport=tcp", self.tls_port));
        }
        if self.tls_443 {
            urls.push(format!("turns:turn.{host}:443?transport=tcp"));
        }
        urls
    }

    pub fn configure_command(&self, command: &mut Command, address: Ipv4Addr) {
        command.args([
            "serve",
            "--listen",
            &format!("{address}:{}", self.turn_port),
            "--relay-ip",
            &address.to_string(),
            "--relay-ports",
            &format!("{}:{}", self.relay_ports.0, self.relay_ports.1),
            "--max-allocations",
            &self.limits.allocations.to_string(),
            "--max-per-user",
            &self.limits.per_user.to_string(),
            "--max-connections",
            &self.limits.connections.to_string(),
            "--bytes-per-second",
            &self.bytes_per_second.to_string(),
        ]);
        if let Some(rate) = self.aggregate_bytes_per_second {
            command.args(["--aggregate-bytes-per-second", &rate.to_string()]);
        }
        if self.direct_tls {
            command.args([
                "--tls-listen",
                &format!("{address}:{}", self.tls_port),
                "--tls-cert",
                &self.certificate,
                "--tls-key",
                &self.key,
            ]);
        }
    }

    pub(crate) fn relay_config(
        &self,
        address: Ipv4Addr,
        secret: Vec<u8>,
    ) -> std::io::Result<spry_turn::turn::Config> {
        let mut config = spry_turn::turn::Config::local(secret);
        config.listen = (address, self.turn_port).into();
        config.relay_ip = address.into();
        config.relay_port_range = Some(self.relay_ports);
        config.max_allocations = self.limits.allocations as usize;
        config.max_per_user = self.limits.per_user as usize;
        config.max_connections = self.limits.connections as usize;
        config.bytes_per_second = self.bytes_per_second;
        config.aggregate_bytes_per_second = self.aggregate_bytes_per_second;
        if self.direct_tls {
            use std::{
                fs::File,
                io::{self, BufReader},
                sync::Arc,
            };
            let certs = rustls_pemfile::certs(&mut BufReader::new(File::open(&self.certificate)?))
                .collect::<io::Result<Vec<_>>>()?;
            let key = rustls_pemfile::private_key(&mut BufReader::new(File::open(&self.key)?))?
                .ok_or_else(|| io::Error::other("TLS key unavailable"))?;
            let tls = rustls::ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(certs, key)
                .map_err(|_| io::Error::other("TLS configuration unavailable"))?;
            config.tls = Some(((address, self.tls_port).into(), Arc::new(tls)));
        }
        Ok(config)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replacement_turn_handshakes_have_headroom_without_more_relay_slots() {
        use std::io::{Read, Write};
        use std::time::Duration;

        let settings = Settings::parse(None, None, None, None).unwrap();
        let mut config = settings
            .relay_config(Ipv4Addr::LOCALHOST, vec![1; 32])
            .unwrap();
        config.listen.set_port(0);
        assert_eq!(config.max_allocations, 32);
        assert_eq!(config.max_per_user, 8);
        let mut server = spry_turn::turn::Server::bind(config).unwrap();
        let mut clients = Vec::new();
        // Old-route sockets and replacement handshakes coexist. These are
        // real TCP/STUN round trips; none reserves an extra relay allocation.
        let mut binding = [0u8; 20];
        binding[1] = 1;
        binding[4..8].copy_from_slice(&[0x21, 0x12, 0xa4, 0x42]);
        for index in 0..64 {
            let mut client = std::net::TcpStream::connect(server.local_addr().unwrap()).unwrap();
            client
                .set_read_timeout(Some(Duration::from_millis(100)))
                .unwrap();
            client.set_nodelay(true).unwrap();
            server.poll_once(Duration::from_millis(1)).unwrap();
            binding[19] = index;
            client.write_all(&binding).unwrap();
            for _ in 0..4 {
                server.poll_once(Duration::from_millis(1)).unwrap();
            }
            let mut response = [0u8; 40];
            client
                .read_exact(&mut response)
                .unwrap_or_else(|error| panic!("handshake {} refused: {error}", index + 1));
            assert_eq!(&response[..2], &[1, 1]);
            assert_eq!(&response[8..20], &binding[8..20]);
            clients.push(client);
        }
        let mut excess = std::net::TcpStream::connect(server.local_addr().unwrap()).unwrap();
        excess
            .set_read_timeout(Some(Duration::from_millis(100)))
            .unwrap();
        server.poll_once(Duration::from_millis(1)).unwrap();
        assert_eq!(
            excess.read(&mut [0u8; 1]).unwrap(),
            0,
            "the TCP cap remains bounded"
        );
        clients[0].write_all(&binding).unwrap();
        for _ in 0..4 {
            server.poll_once(Duration::from_millis(1)).unwrap();
        }
        clients[0].read_exact(&mut [0u8; 40]).unwrap();
    }

    #[test]
    fn node_front_door_and_aggregate_settings_reach_the_relay_configuration() {
        let mut settings = Settings::parse(None, None, None, None).unwrap();
        settings.tls_443 = true;
        settings.advertise_tls = true;
        settings.aggregate_bytes_per_second = Some(50_000);
        assert_eq!(
            settings.urls("node.example"),
            [
                "turn:node.example:3478?transport=udp",
                "turn:node.example:3478?transport=tcp",
                "turns:node.example:5349?transport=tcp",
                "turns:turn.node.example:443?transport=tcp"
            ]
        );
        let config = settings
            .relay_config(Ipv4Addr::LOCALHOST, vec![1; 32])
            .unwrap();
        assert_eq!(config.aggregate_bytes_per_second, Some(50_000));
        let mut command = Command::new("synthetic-relay");
        settings.configure_command(&mut command, Ipv4Addr::LOCALHOST);
        let args: Vec<_> = command
            .as_std()
            .get_args()
            .map(|a| a.to_str().unwrap())
            .collect();
        assert!(
            args.windows(2)
                .any(|a| a == ["--aggregate-bytes-per-second", "50000"])
        );
    }

    #[test]
    fn defaults_and_configured_transport_share_urls_and_child_arguments() {
        let defaults = Settings::parse(None, None, None, None).unwrap();
        assert_eq!(
            (
                defaults.turn_port,
                defaults.tls_port,
                defaults.relay_ports,
                defaults.bytes_per_second
            ),
            (3478, 5349, (49160, 49191), 1_000_000)
        );
        assert_eq!(
            defaults.urls("relay.example"),
            [
                "turn:relay.example:3478?transport=udp",
                "turn:relay.example:3478?transport=tcp"
            ]
        );
        let mut settings = Settings::parse(
            Some("3479"),
            Some("5350"),
            Some("49200:49231"),
            Some("8388608"),
        )
        .unwrap();
        settings.direct_tls = true;
        settings.advertise_tls = true;
        assert_eq!(
            settings.urls("relay.example"),
            [
                "turn:relay.example:3479?transport=udp",
                "turn:relay.example:3479?transport=tcp",
                "turns:relay.example:5350?transport=tcp"
            ]
        );
        let mut command = Command::new("synthetic-relay");
        settings.configure_command(&mut command, Ipv4Addr::LOCALHOST);
        let args: Vec<_> = command
            .as_std()
            .get_args()
            .map(|arg| arg.to_str().unwrap())
            .collect();
        for pair in [
            ["--listen", "127.0.0.1:3479"],
            ["--relay-ports", "49200:49231"],
            ["--bytes-per-second", "8388608"],
            ["--tls-listen", "127.0.0.1:5350"],
            ["--max-allocations", "32"],
            ["--max-per-user", "8"],
            ["--max-connections", "64"],
        ] {
            assert!(args.windows(2).any(|window| window == pair), "{pair:?}");
        }
    }

    #[test]
    fn unset_limits_are_todays_values_and_reach_the_child_unchanged() {
        assert_eq!(
            Limits::parse(None, None, None).unwrap(),
            Limits {
                allocations: 32,
                per_user: 8,
                connections: 64
            }
        );
        assert_eq!(Limits::default(), Limits::parse(None, None, None).unwrap());
        let settings = Settings::parse(None, None, None, None).unwrap();
        assert_eq!(settings.limits, Limits::default());
        let mut command = Command::new("synthetic-relay");
        settings.configure_command(&mut command, Ipv4Addr::LOCALHOST);
        let args: Vec<_> = command.as_std().get_args().collect();
        for pair in [
            ["--max-allocations", "32"],
            ["--max-per-user", "8"],
            ["--max-connections", "64"],
            ["--bytes-per-second", "1000000"],
        ] {
            assert!(args.windows(2).any(|window| window == pair), "{pair:?}");
        }
    }

    #[test]
    fn lowered_limits_reach_the_child_and_the_maximum_is_accepted() {
        let mut settings = Settings::parse(None, None, None, Some("125000")).unwrap();
        settings.limits = Limits::parse(Some("8"), Some("2"), Some("16")).unwrap();
        let mut command = Command::new("synthetic-relay");
        settings.configure_command(&mut command, Ipv4Addr::LOCALHOST);
        let args: Vec<_> = command.as_std().get_args().collect();
        for pair in [
            ["--max-allocations", "8"],
            ["--max-per-user", "2"],
            ["--max-connections", "16"],
            ["--bytes-per-second", "125000"],
        ] {
            assert!(args.windows(2).any(|window| window == pair), "{pair:?}");
        }
        assert!(Limits::parse(Some("32"), Some("8"), Some("64")).is_ok());
        assert!(Limits::parse(Some("1"), Some("1"), Some("1")).is_ok());
        // An unset per-user limit follows a lowered total.
        assert_eq!(Limits::parse(Some("4"), None, None).unwrap().per_user, 4);
        assert_eq!(Limits::parse(Some("20"), None, None).unwrap().per_user, 8);
    }

    #[test]
    fn explicit_group_budget_preserves_defaults_and_reaches_the_relay() {
        let defaults = Limits::default();
        assert_eq!(
            (
                defaults.allocations,
                defaults.per_user,
                defaults.connections
            ),
            (32, 8, 64)
        );
        // Seven devices need 42 directed peer connections, plus their
        // candidate alternatives and overlapping credential replacements.
        let limits = Limits::parse(Some("512"), Some("64"), Some("512")).unwrap();
        let mut settings = Settings::parse(None, None, Some("49160:49671"), None).unwrap();
        settings.limits = limits;
        let relay = settings
            .relay_config(Ipv4Addr::LOCALHOST, vec![7; 32])
            .unwrap();
        assert_eq!(
            (
                relay.max_allocations,
                relay.max_per_user,
                relay.max_connections
            ),
            (512, 64, 512)
        );
        let mut command = Command::new("synthetic-relay");
        settings.configure_command(&mut command, Ipv4Addr::LOCALHOST);
        let args: Vec<_> = command.as_std().get_args().collect();
        for pair in [
            ["--max-allocations", "512"],
            ["--max-per-user", "64"],
            ["--max-connections", "512"],
        ] {
            assert!(args.windows(2).any(|window| window == pair), "{pair:?}");
        }
    }

    #[test]
    fn invalid_limits_refuse_startup_naming_the_setting() {
        for bad in [
            "",
            "0",
            "-1",
            "+1",
            " 1",
            "1 ",
            "0x10",
            "1.0",
            "NaN",
            "513",
            "4294967296",
            "99999999999999999999",
        ] {
            assert_eq!(
                Limits::parse(Some(bad), None, None).unwrap_err(),
                ALLOCATIONS
            );
            if bad != "513" {
                assert_eq!(
                    Limits::parse(None, None, Some(bad)).unwrap_err(),
                    CONNECTIONS
                );
            }
        }
        assert!(Limits::parse(None, None, Some("32")).is_ok());
        assert!(Limits::parse(None, None, Some("33")).is_ok());
        assert_eq!(
            Limits::parse(None, None, Some("513")).unwrap_err(),
            CONNECTIONS
        );
        for bad in ["", "0", "-1", "+1", " 1", "65", "NaN"] {
            assert_eq!(Limits::parse(None, Some(bad), None).unwrap_err(), PER_USER);
        }
        // Per-user may not exceed the total.
        assert_eq!(
            Limits::parse(Some("2"), Some("3"), None).unwrap_err(),
            PER_USER
        );
        assert!(Limits::parse(Some("2"), Some("2"), None).is_ok());
        for error in [ALLOCATIONS, PER_USER, CONNECTIONS] {
            assert!(error.0.contains("SPRY_MAX_"), "{}", error.0);
        }
    }

    #[test]
    fn invalid_configuration_never_becomes_a_port_or_unbounded_rate() {
        for bad in ["", "0", "65536", "-1", "+3479", " 3479", "3479 ", "NaN"] {
            assert_eq!(
                Settings::parse(Some(bad), None, None, None).unwrap_err(),
                TURN_PORT
            );
            assert_eq!(
                Settings::parse(None, Some(bad), None, None).unwrap_err(),
                TLS_PORT
            );
        }
        assert_eq!(
            Settings::parse(None, Some("3478"), None, None).unwrap_err(),
            TLS_PORT
        );
        for bad in [
            "0:9",
            "9:0",
            "49231:49200",
            "49160:65536",
            "49160",
            "1:2:3",
            "3478:3479",
            "5349:5349",
        ] {
            assert_eq!(
                Settings::parse(None, None, Some(bad), None).unwrap_err(),
                RELAY_PORTS
            );
        }
        for bad in [
            "",
            "0",
            "-1",
            "+1",
            " 1",
            "67108865",
            "18446744073709551616",
        ] {
            assert_eq!(
                Settings::parse(None, None, None, Some(bad)).unwrap_err(),
                BANDWIDTH
            );
        }
        assert!(Settings::parse(Some("443"), None, Some("65535:65535"), Some("67108864")).is_ok());
    }

    #[tokio::test]
    async fn readiness_uses_the_selected_port_and_does_not_accept_another_responder() {
        use tokio::{
            net::UdpSocket,
            time::{Duration, timeout},
        };
        let responder = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let port = responder.local_addr().unwrap().port();
        let other = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let wrong_port = other.local_addr().unwrap().port();
        let task = tokio::spawn(async move {
            let mut request = [0_u8; 1024];
            let (size, peer) = timeout(Duration::from_secs(2), responder.recv_from(&mut request))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(size, 20);
            request[..2].copy_from_slice(&[1, 1]);
            responder.send_to(&request[..size], peer).await.unwrap();
        });
        assert!(!crate::binding(Ipv4Addr::LOCALHOST, wrong_port).await);
        assert!(crate::binding(Ipv4Addr::LOCALHOST, port).await);
        task.await.unwrap();
    }
}
