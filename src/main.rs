use std::{env, process::ExitCode};

const HELP: &str = "spry-turn: a small standalone packet relay\n\n\
  spry-turn serve [options]\n\
  spry-turn credential [--ttl SECONDS] [--label LABEL]\n\n\
Set SPRY_TURN_SECRET to an operator-generated secret of at least 32 bytes.\n\
The credential command emits a TURN REST username/password JSON pair.\n\n\
Options:\n\
  --listen ADDRESS              UDP and TCP listener (127.0.0.1:3478)\n\
  --relay-ip IP                 Local relay bind address (listener IP)\n\
  --public-ip IP                Advertised relay IP if behind one-to-one NAT\n\
  --realm NAME                  Authentication realm (spry-turn)\n\
  --max-allocations COUNT        Total allocation limit (1024)\n\
  --max-per-user COUNT           Per-credential allocation limit (8)\n\
  --max-connections COUNT        TCP/TLS connection limit (256)\n\
  --bytes-per-second COUNT       Per-allocation aggregate bandwidth (67108864)\n\
  --allow-loopback-peers         Local interop tests only; requires loopback listener\n\
  --tls-listen ADDRESS           Optional TLS listener (requires tls build feature)\n\
  --tls-cert FILE --tls-key FILE PEM certificate and private key\n\n\
No service discovery, hosted endpoints, room authority or media processing.\n";

fn main() -> ExitCode {
    let args: Vec<String> = env::args().skip(1).collect();
    if args.iter().any(|a| a == "--help" || a == "-h") {
        print!("{HELP}");
        return ExitCode::SUCCESS;
    }
    if args.iter().any(|a| a == "--version") {
        println!("spry-turn {}", env!("CARGO_PKG_VERSION"));
        return ExitCode::SUCCESS;
    }
    match run(args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("spry-turn: {error}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(not(feature = "turn"))]
fn run(_: Vec<String>) -> Result<(), Box<dyn std::error::Error>> {
    Err("this executable requires the turn build feature".into())
}

#[cfg(feature = "turn")]
fn run(args: Vec<String>) -> Result<(), Box<dyn std::error::Error>> {
    use spry_turn::{
        auth,
        turn::{Config, Server, unix_time},
    };
    use std::{net::SocketAddr, time::Duration};
    let secret = env::var("SPRY_TURN_SECRET")
        .map_err(|_| "SPRY_TURN_SECRET is required")?
        .into_bytes();
    if secret.len() < 32 {
        return Err("SPRY_TURN_SECRET must contain at least 32 bytes".into());
    }
    let mut config = Config::local(secret);
    let credential = args.first().is_some_and(|a| a == "credential");
    let mut ttl = 3600u64;
    let mut label = String::from("client");
    let mut relay_given = false;
    let mut tls_address: Option<SocketAddr> = None;
    let mut cert: Option<String> = None;
    let mut key: Option<String> = None;
    let mut iter = args.into_iter().peekable();
    if iter
        .peek()
        .is_some_and(|a| a == "serve" || a == "credential")
    {
        iter.next();
    }
    while let Some(option) = iter.next() {
        if option == "--allow-loopback-peers" {
            config.allow_loopback_peers = true;
            continue;
        }
        let value = iter.next().ok_or("option requires a value")?;
        match option.as_str() {
            "--listen" => config.listen = value.parse()?,
            "--relay-ip" => {
                config.relay_ip = value.parse()?;
                relay_given = true;
            }
            "--public-ip" => config.advertised_ip = Some(value.parse()?),
            "--realm" => config.realm = value,
            "--max-allocations" => config.max_allocations = value.parse()?,
            "--max-per-user" => config.max_per_user = value.parse()?,
            "--max-connections" => config.max_connections = value.parse()?,
            "--bytes-per-second" => config.bytes_per_second = value.parse()?,
            "--ttl" if credential => ttl = value.parse()?,
            "--label" if credential => label = value,
            "--tls-listen" => tls_address = Some(value.parse()?),
            "--tls-cert" => cert = Some(value),
            "--tls-key" => key = Some(value),
            _ => return Err(format!("unrecognised option {option}").into()),
        }
    }
    if credential {
        if !(1..=86400).contains(&ttl)
            || label.is_empty()
            || label.len() > 64
            || !label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        {
            return Err("use a TTL of 1..86400 and a short opaque ASCII label".into());
        }
        let username = format!("{}:{label}", unix_time() + ttl);
        let credential = auth::credential(&config.secret, &username);
        println!("{{\"username\":\"{username}\",\"credential\":\"{credential}\"}}");
        return Ok(());
    }
    if !relay_given {
        config.relay_ip = config.listen.ip();
    }
    if config.allow_loopback_peers && !config.listen.ip().is_loopback() {
        return Err("loopback-peer testing requires a loopback-only listener".into());
    }
    if let Some(address) = tls_address {
        #[cfg(feature = "tls")]
        {
            use std::{fs::File, io::BufReader, sync::Arc};
            let cert = cert.ok_or("--tls-cert is required")?;
            let key = key.ok_or("--tls-key is required")?;
            let certificates = rustls_pemfile::certs(&mut BufReader::new(File::open(cert)?))
                .collect::<Result<Vec<_>, _>>()?;
            let key = rustls_pemfile::private_key(&mut BufReader::new(File::open(key)?))?
                .ok_or("no private key in file")?;
            let tls = rustls::ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(certificates, key)?;
            config.tls = Some((address, Arc::new(tls)));
        }
        #[cfg(not(feature = "tls"))]
        {
            let _ = (address, cert, key);
            return Err("rebuild with --features tls to enable TLS".into());
        }
    } else if cert.is_some() || key.is_some() {
        return Err("--tls-listen is required with TLS files".into());
    }
    let mut server = Server::bind(config)?;
    eprintln!(
        "spry-turn {} ready (UDP/TCP {})",
        env!("CARGO_PKG_VERSION"),
        server.local_addr()?
    );
    loop {
        server.poll_once(Duration::from_secs(1))?;
    }
}
