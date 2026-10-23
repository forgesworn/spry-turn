//! Finite embedding host for PGO training; not the standalone service.
//! Normal exit writes LLVM profiles, unlike terminating a foreground daemon.

#[cfg(all(feature = "runtime", feature = "turn", feature = "tls"))]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    use spry_turn::turn::{Config, Server};
    use std::{
        env,
        fs::File,
        io::BufReader,
        sync::Arc,
        time::{Duration, Instant},
    };

    let mut config = Config::local(env::var("SPRY_TURN_SECRET")?.into_bytes());
    let mut args = env::args().skip(1);
    let mut tls_address = None;
    let mut certificate = None;
    let mut private_key = None;
    while let Some(option) = args.next() {
        if option == "serve" {
            continue;
        }
        if option == "--allow-loopback-peers" {
            config.allow_loopback_peers = true;
            continue;
        }
        let value = args.next().ok_or("option requires a value")?;
        match option.as_str() {
            "--listen" => config.listen = value.parse()?,
            "--bytes-per-second" => config.bytes_per_second = value.parse()?,
            "--max-connections" => config.max_connections = value.parse()?,
            "--relay-ports" => {
                let (first, last) = value.split_once(':').ok_or("relay range")?;
                config.relay_port_range = Some((first.parse()?, last.parse()?));
            }
            "--tls-listen" => tls_address = Some(value.parse()?),
            "--tls-cert" => certificate = Some(value),
            "--tls-key" => private_key = Some(value),
            _ => return Err("unknown training-host option".into()),
        }
    }
    if !config.listen.ip().is_loopback() {
        return Err("profile training is restricted to loopback".into());
    }
    config.relay_ip = config.listen.ip();
    if let Some(address) = tls_address {
        let address: std::net::SocketAddr = address;
        if !address.ip().is_loopback() {
            return Err("profile training TLS is restricted to loopback".into());
        }
        let certificates = rustls_pemfile::certs(&mut BufReader::new(File::open(
            certificate.ok_or("TLS certificate required")?,
        )?))
        .collect::<Result<Vec<_>, _>>()?;
        let key = rustls_pemfile::private_key(&mut BufReader::new(File::open(
            private_key.ok_or("TLS private key required")?,
        )?))?
        .ok_or("missing TLS private key")?;
        let tls = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certificates, key)?;
        config.tls = Some((address, Arc::new(tls)));
    }
    let seconds: u64 = env::var("SPRY_PROFILE_SECONDS")
        .unwrap_or_else(|_| "5".into())
        .parse()?;
    if !(1..=60).contains(&seconds) {
        return Err("SPRY_PROFILE_SECONDS must be in 1..60".into());
    }
    let mut server = Server::bind(config)?;
    let stop = Instant::now() + Duration::from_secs(seconds);
    while Instant::now() < stop {
        server.poll_once(Duration::from_millis(20))?;
    }
    Ok(())
}

#[cfg(not(all(feature = "runtime", feature = "turn", feature = "tls")))]
fn main() {
    eprintln!("profile_server requires the runtime, turn and tls features");
    std::process::exit(1);
}
