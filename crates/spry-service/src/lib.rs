#![forbid(unsafe_code)]
pub mod mesh;
mod node;
pub mod signalling;
use bytes::Bytes;
use http_body_util::{BodyExt, Full, Limited};
use hyper::{Request, Response, StatusCode, body::Incoming, service::service_fn};
use hyper_util::rt::{TokioIo, TokioTimer};
use node::{PrivateSettings, ServiceState};
use serde_json::{Value, json};
use spry_access::{Authority, Config, MAX_BODY, Refused};
use std::{
    convert::Infallible,
    env,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::PathBuf,
    process::Stdio,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::{
    net::{TcpListener, UdpSocket},
    process::{Child, Command},
    sync::Semaphore,
    time::timeout,
};

/// Assets supplied by a host adapter. The standalone service has its own UI.
#[derive(Clone, Copy)]
pub struct UiAssets {
    pub index: &'static str,
    pub script: &'static str,
    pub style: &'static str,
    pub signer_provider: Option<&'static str>,
}
impl UiAssets {
    pub const STANDALONE: Self = Self {
        index: include_str!("../public/index.html"),
        script: include_str!("../public/app.mjs"),
        style: include_str!("../public/style.css"),
        signer_provider: None,
    };
}
type State = Arc<ServiceState>;
fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}
fn response(status: u16, kind: &str, bytes: impl Into<Bytes>) -> Response<Full<Bytes>> {
    let mut response = Response::new(Full::new(bytes.into()));
    *response.status_mut() =
        StatusCode::from_u16(status).unwrap_or(StatusCode::SERVICE_UNAVAILABLE);
    for (name, value) in [
        ("content-type", kind),
        ("cache-control", "no-store"),
        ("referrer-policy", "no-referrer"),
        ("x-content-type-options", "nosniff"),
        (
            "content-security-policy",
            "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; frame-src https:; frame-ancestors https:; base-uri 'none'; form-action 'none'",
        ),
    ] {
        if let Ok(value) = value.parse() {
            response.headers_mut().insert(name, value);
        }
    }
    response
}
fn json_response(status: u16, value: Value) -> Response<Full<Bytes>> {
    response(status, "application/json", value.to_string())
}
async fn dispatch(
    request: Request<Incoming>,
    state: State,
    peer: IpAddr,
    assets: UiAssets,
) -> spry_access::Result<Response<Full<Bytes>>> {
    let path = request.uri().path();
    if request.uri().query().is_some() || path.len() > 128 {
        return Err(Refused(404, "Not found."));
    }
    let origin = request
        .headers()
        .get("origin")
        .map(|h| h.to_str().unwrap_or("invalid"));
    if let Some(origin) = origin {
        if !state
            .lock()
            .map_err(|_| Refused(503, "Spry is temporarily unavailable."))?
            .config
            .origins
            .contains(origin)
        {
            return Err(Refused(403, "Request refused."));
        }
    }
    if request.method() == "OPTIONS" {
        let mut response = response(204, "text/plain", "");
        response.headers_mut().insert(
            "access-control-allow-methods",
            "POST".parse().map_err(|_| Refused(503, "Unavailable."))?,
        );
        response.headers_mut().insert(
            "access-control-allow-headers",
            "Authorization, Content-Type"
                .parse()
                .map_err(|_| Refused(503, "Unavailable."))?,
        );
        return Ok(response);
    }
    if request.method() == "GET" {
        return Ok(match path {
            "/" => response(200, "text/html; charset=utf-8", assets.index),
            "/app.mjs" => response(200, "text/javascript", assets.script),
            "/style.css" => response(200, "text/css", assets.style),
            "/nostr-provider.js" => response(
                200,
                "text/javascript",
                assets.signer_provider.ok_or(Refused(404, "Not found."))?,
            ),
            "/v1/status" => {
                let authority = state.lock().map_err(|_| Refused(503, "Unavailable."))?;
                json_response(
                    200,
                    json!({"ready":authority.config.ready,"endpoint":authority.config.endpoint,"audience":authority.config.audience,"privateRelay":authority.config.audience.is_some(),"controlReady":state.private()?.is_some_and(|private|private.control_ready()),"message":if authority.config.ready { "Ready to pair with KithMoot." } else { authority.config.readiness }}),
                )
            }
            _ => return Err(Refused(404, "Not found.")),
        });
    }
    if request.method() != "POST" || !path.starts_with("/v1/") {
        return Err(Refused(404, "Not found."));
    }
    state
        .lock()
        .map_err(|_| Refused(503, "Unavailable."))?
        .rate(&peer.to_string(), now())?;
    if request
        .headers()
        .get("content-type")
        .and_then(|h| h.to_str().ok())
        != Some("application/json")
        || request.headers().contains_key("content-encoding")
    {
        return Err(Refused(415, "Invalid request."));
    }
    if request
        .headers()
        .get("content-length")
        .and_then(|h| h.to_str().ok())
        .and_then(|s| s.parse::<u64>().ok())
        .is_some_and(|n| n > MAX_BODY as u64)
    {
        return Err(Refused(413, "Request too large."));
    }
    let header = request
        .headers()
        .get("authorization")
        .and_then(|h| h.to_str().ok())
        .ok_or(Refused(401, "Approval required."))?
        .to_owned();
    if header.len() > 4096 {
        return Err(Refused(401, "Approval required."));
    }
    let path = path.to_owned();
    let body = timeout(
        Duration::from_secs(5),
        Limited::new(request.into_body(), MAX_BODY).collect(),
    )
    .await
    .map_err(|_| Refused(408, "Request timed out."))?
    .map_err(|_| Refused(413, "Request too large."))?
    .to_bytes();
    let key = state
        .lock()
        .map_err(|_| Refused(503, "Unavailable."))?
        .authenticate(&header, &path, &body, now())?;
    let body = serde_json::from_slice(&body).map_err(|_| Refused(400, "Invalid request."))?;
    if path == "/v1/pairings" {
        if let Some(private) = state.private()? {
            private.prepare_pairing(&state, &key, &body).await?;
        }
    }
    Ok(json_response(200, state.api(&key, &path, &body, now())?))
}
async fn serve(
    request: Request<Incoming>,
    state: State,
    peer: IpAddr,
    assets: UiAssets,
) -> std::result::Result<Response<Full<Bytes>>, Infallible> {
    let origin = request.headers().get("origin").cloned().filter(|origin| {
        state.lock().ok().is_some_and(|a| {
            origin
                .to_str()
                .ok()
                .is_some_and(|s| a.config.origins.contains(s))
        })
    });
    let mut response = match dispatch(request, state, peer, assets).await {
        Ok(response) => response,
        Err(Refused(status, message)) => json_response(status, json!({"error":message})),
    };
    if let Some(origin) = origin {
        response
            .headers_mut()
            .insert("access-control-allow-origin", origin);
        response
            .headers_mut()
            .insert("vary", hyper::header::HeaderValue::from_static("Origin"));
    }
    Ok(response)
}
fn public_v4(ip: Ipv4Addr) -> bool {
    let [a, b, c, _] = ip.octets();
    !(ip.is_private()
        || ip.is_loopback()
        || ip.is_link_local()
        || ip.is_broadcast()
        || ip.is_documentation()
        || a == 0
        || a >= 224
        || (a == 100 && (64..=127).contains(&b))
        || (a == 198 && (b == 18 || b == 19))
        || (a == 192 && b == 0 && c == 0))
}
fn node_address() -> Option<Ipv4Addr> {
    if let Ok(explicit) = env::var("SPRY_RELAY_IP") {
        return explicit.parse().ok();
    }
    let output = std::process::Command::new("ip")
        .args(["-j", "-4", "address", "show", "scope", "global"])
        .output()
        .ok()?;
    if !output.status.success() || output.stdout.len() > 65_536 {
        return None;
    }
    let interfaces: Value = serde_json::from_slice(&output.stdout).ok()?;
    for interface in interfaces.as_array()? {
        for info in interface.get("addr_info")?.as_array()? {
            if let Some(ip) = info
                .get("local")
                .and_then(Value::as_str)
                .and_then(|s| s.parse().ok())
            {
                if public_v4(ip)
                    || env::var("SPRY_PUBLIC_IP")
                        .ok()
                        .and_then(|s| s.parse().ok())
                        .is_some_and(public_v4)
                {
                    return Some(ip);
                }
            }
        }
    }
    None
}
async fn start_relay(state: &State) -> Option<Child> {
    let address = node_address()?;
    let local_test = address.is_loopback() && env::var("SPRY_LOCAL_TEST").as_deref() == Ok("true");
    let public = env::var("SPRY_PUBLIC_IP").ok();
    if !local_test
        && !public_v4(address)
        && !public
            .as_ref()
            .and_then(|s| s.parse().ok())
            .is_some_and(public_v4)
    {
        return None;
    }
    let binary = env::var("SPRY_RELAY_BINARY").unwrap_or_else(|_| {
        env::current_exe()
            .ok()
            .and_then(|path| path.parent().map(|directory| directory.join("spry-turn")))
            .unwrap_or_else(|| PathBuf::from("spry-turn"))
            .to_string_lossy()
            .into_owned()
    });
    let mut command = Command::new(binary);
    command.args([
        "serve",
        "--listen",
        &format!("{address}:3478"),
        "--relay-ip",
        &address.to_string(),
        "--relay-ports",
        "49160:49191",
        "--max-allocations",
        "32",
        "--max-per-user",
        "8",
        "--max-connections",
        "32",
        "--bytes-per-second",
        "1000000",
    ]);
    if let Some(public) = public {
        if !public.parse().ok().is_some_and(public_v4) {
            return None;
        }
        command.args(["--public-ip", &public]);
    }
    if local_test {
        command.arg("--allow-loopback-peers");
    }
    let tls = PathBuf::from("/data/tls/fullchain.pem").is_file()
        && PathBuf::from("/data/tls/privkey.pem").is_file();
    if tls {
        command.args([
            "--tls-listen",
            &format!("{address}:5349"),
            "--tls-cert",
            "/data/tls/fullchain.pem",
            "--tls-key",
            "/data/tls/privkey.pem",
        ]);
    }
    let mut child = command
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .ok()?;
    for _ in 0..5 {
        tokio::time::sleep(Duration::from_millis(100)).await;
        if child.try_wait().ok().flatten().is_some() {
            return None;
        }
        if binding(address).await {
            if let Ok(mut authority) = state.lock() {
                authority.config.ready = true;
                if tls || env::var("SPRY_TLS_GATE").as_deref() == Ok("true") {
                    if let Ok(url) = url::Url::parse(&authority.config.endpoint) {
                        if let Some(host) = url.host_str() {
                            let url = format!("turns:{host}:5349?transport=tcp");
                            authority.config.urls.push(url);
                        }
                    }
                }
            }
            return Some(child);
        }
    }
    let _ = child.kill().await;
    None
}
async fn binding(address: Ipv4Addr) -> bool {
    let Ok(socket) = UdpSocket::bind("127.0.0.1:0").await else {
        return false;
    };
    // On a public bind, the kernel must select that interface as the local source.
    let socket = if address.is_loopback() {
        socket
    } else {
        let Ok(socket) = UdpSocket::bind((address, 0)).await else {
            return false;
        };
        socket
    };
    if socket.connect((address, 3478)).await.is_err() {
        return false;
    }
    let mut request = [0_u8; 20];
    request[1] = 1;
    request[4..8].copy_from_slice(&0x2112_a442_u32.to_be_bytes());
    if getrandom::fill(&mut request[8..]).is_err() || socket.send(&request).await.is_err() {
        return false;
    }
    let mut response = [0_u8; 1024];
    matches!(timeout(Duration::from_millis(700), socket.recv(&mut response)).await, Ok(Ok(n)) if n >= 20 && response[..2] == [1,1] && response[8..20] == request[8..])
}
/// Serve until a shutdown signal, using the host's runtime and environment.
pub async fn run_with_assets(
    assets: UiAssets,
) -> std::result::Result<(), Box<dyn std::error::Error>> {
    let secret = env::var("SPRY_TURN_SECRET")?;
    let private_settings = PrivateSettings::from_environment(secret.as_bytes())?;
    let endpoint = if private_settings.is_some() {
        env::var("SPRY_OWNER_URL").or_else(|_| env::var("SPRY_PUBLIC_URL"))?
    } else {
        env::var("SPRY_PUBLIC_URL")?
    };
    let mut config = Config::new(
        &endpoint,
        &env::var("SPRY_KITHMOOT_URL").unwrap_or_else(|_| "https://kithmoot.app/j/".into()),
        &env::var("SPRY_OWNER_KEYS")?,
        secret.as_bytes(),
        Some(
            env::var("SPRY_STATE_FILE")
                .map_or_else(|_| PathBuf::from("/data/pairings.json"), PathBuf::from),
        ),
    )
    .map_err(|_| "Invalid Spry configuration")?;
    // Client-specific origins are an explicit host choice, never library defaults.
    for origins in ["SPRY_ALLOWED_ORIGINS", "SPRY_DASHBOARD_ORIGINS"]
        .into_iter()
        .filter_map(|name| env::var(name).ok())
    {
        for origin in origins.split(',').filter(|s| !s.is_empty()) {
            let url = url::Url::parse(origin)?;
            if url.scheme() != "https"
                || !url.username().is_empty()
                || url.password().is_some()
                || url.path() != "/"
                || url.query().is_some()
                || url.fragment().is_some()
            {
                return Err("Invalid allowed origin".into());
            }
            config.origins.insert(url.origin().ascii_serialization());
        }
    }
    if let Some(settings) = &private_settings {
        config.audience = Some(settings.audience().map_err(|_| "Invalid node identity")?);
        config.readiness = "Waiting for your node’s network.";
    }
    let mut authority = Authority::new(config);
    authority.restore().map_err(|_| "Pairings unavailable")?;
    if private_settings.is_none() && authority.config.transport_endpoint.is_some() {
        return Err("Private relay settings require a peer network".into());
    }
    let state = Arc::new(ServiceState::new(authority));
    let bind: SocketAddr = format!(
        "{}:{}",
        env::var("SPRY_HTTP_BIND").unwrap_or_else(|_| "127.0.0.1".into()),
        env::var("SPRY_HTTP_PORT").unwrap_or_else(|_| "3744".into())
    )
    .parse()?;
    if !bind.ip().is_loopback() {
        return Err("The control service must sit behind an HTTPS reverse proxy".into());
    }
    let listener = TcpListener::bind(bind).await?;
    let mut relay = if private_settings.is_none() {
        start_relay(&state).await
    } else {
        None
    };
    let mut signalling = None;
    if let Some(settings) = &private_settings {
        // Keep owner status available while the optional network is starting.
        if let Ok(started) = settings.start(state.clone()).await {
            signalling = started;
        }
    }
    let permits = Arc::new(Semaphore::new(64));
    let mut monitor = tokio::time::interval(Duration::from_secs(5));
    #[cfg(unix)]
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => break,
            _ = async { #[cfg(unix)] { terminate.recv().await; } #[cfg(not(unix))] { std::future::pending::<()>().await; } } => break,
            _ = monitor.tick() => {
                if let Some(settings)=&private_settings {
                    if state.private().ok().flatten().is_some_and(|private|!private.mesh.healthy()){state.clear_private();signalling=None;}
                    if state.private().ok().flatten().is_none(){if let Ok(started)=settings.start(state.clone()).await{signalling=started;}}
                } else if relay.as_mut().is_some_and(|child| child.try_wait().ok().flatten().is_some()) {relay=None;if let Ok(mut authority)=state.lock(){authority.config.ready=false;authority.config.readiness="Spry stopped. Restart the service.";}}
            },
            accepted = listener.accept() => {
                let (stream, address) = accepted?;
                let Ok(permit) = permits.clone().try_acquire_owned() else { drop(stream); continue };
                let state = state.clone();
                tokio::spawn(async move {
                    let _permit = permit;
                    let _ = hyper::server::conn::http1::Builder::new().keep_alive(false).max_headers(32).max_buf_size(16_384)
                        .timer(TokioTimer::new()).header_read_timeout(Duration::from_secs(5))
                        .serve_connection(TokioIo::new(stream), service_fn(move |request| serve(request, state.clone(), address.ip(), assets))).await;
                });
            }
        }
    }
    drop(signalling);
    state.clear_private();
    if let Some(mut relay) = relay {
        let _ = relay.kill().await;
    }
    Ok(())
}
/// Run the standalone service with host-selected assets and environment configuration.
pub fn main_with_assets(assets: UiAssets) {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .max_blocking_threads(2)
        .enable_all()
        .build();
    let Ok(runtime) = runtime else {
        eprintln!("Spry could not start.");
        std::process::exit(1);
    };
    if runtime.block_on(run_with_assets(assets)).is_err() {
        eprintln!("Spry setup is not ready. Check the service configuration.");
        std::process::exit(1);
    }
}
