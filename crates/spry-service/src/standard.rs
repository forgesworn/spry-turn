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
    direct_tls: bool,
    advertise_tls: bool,
}

const MAX_BYTES_PER_SECOND: u64 = 64 * 1024 * 1024;
const TURN_PORT: SetupError = SetupError("SPRY_TURN_PORT must be an integer from 1 to 65535");
const TLS_PORT: SetupError =
    SetupError("SPRY_TLS_PORT must be an integer from 1 to 65535 and differ from SPRY_TURN_PORT");
const RELAY_PORTS: SetupError = SetupError(
    "SPRY_RELAY_PORTS must be FIRST:LAST from 1 to 65535, in order and outside the TURN/TLS listener ports",
);
const BANDWIDTH: SetupError =
    SetupError("SPRY_BYTES_PER_SECOND must be an integer from 1 to 67108864");

fn port(value: &str) -> Option<u16> {
    (!value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit()))
        .then(|| value.parse::<u16>().ok())
        .flatten()
        .filter(|value| *value != 0)
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
            direct_tls: false,
            advertise_tls: false,
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
        settings.direct_tls = Path::new("/data/tls/fullchain.pem").is_file()
            && Path::new("/data/tls/privkey.pem").is_file();
        settings.advertise_tls =
            settings.direct_tls || env::var("SPRY_TLS_GATE").as_deref() == Ok("true");
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
            "32",
            "--max-per-user",
            "8",
            "--max-connections",
            "32",
            "--bytes-per-second",
            &self.bytes_per_second.to_string(),
        ]);
        if self.direct_tls {
            command.args([
                "--tls-listen",
                &format!("{address}:{}", self.tls_port),
                "--tls-cert",
                "/data/tls/fullchain.pem",
                "--tls-key",
                "/data/tls/privkey.pem",
            ]);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
            ["--max-connections", "32"],
        ] {
            assert!(args.windows(2).any(|window| window == pair), "{pair:?}");
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
