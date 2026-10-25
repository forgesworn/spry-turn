#![forbid(unsafe_code)]
pub mod mesh;
mod node;
pub mod public;
pub mod resolver;
pub mod signalling;
use bytes::Bytes;
use http_body_util::{BodyExt, Full, Limited};
use hyper::{Request, Response, StatusCode, body::Incoming, service::service_fn};
use hyper_util::rt::{TokioIo, TokioTimer};
use node::{PrivateSettings, ServiceState};
use serde_json::{Value, json};
use spry_access::{Authority, Config, MAX_BODY, PUBLIC_PATH, Refused};
use std::{
    convert::Infallible,
    env,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
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
/// A public request body is `{"v":1}`; anything near this size is refused.
const PUBLIC_MAX_BODY: usize = 256;
fn json_headers(headers: &hyper::HeaderMap, limit: usize) -> spry_access::Result<()> {
    if headers.get("content-type").and_then(|h| h.to_str().ok()) != Some("application/json")
        || headers.contains_key("content-encoding")
    {
        return Err(Refused(415, "Invalid request."));
    }
    if headers
        .get("content-length")
        .and_then(|h| h.to_str().ok())
        .and_then(|s| s.parse::<u64>().ok())
        .is_some_and(|n| n > limit as u64)
    {
        return Err(Refused(413, "Request too large."));
    }
    Ok(())
}
async fn read_body(body: Incoming, limit: usize) -> spry_access::Result<Bytes> {
    Ok(
        timeout(Duration::from_secs(5), Limited::new(body, limit).collect())
            .await
            .map_err(|_| Refused(408, "Request timed out."))?
            .map_err(|_| Refused(413, "Request too large."))?
            .to_bytes(),
    )
}
/// The caller as the operator's reverse proxy saw it. The service listens
/// only on loopback behind that proxy, which appends the address it saw to
/// `X-Forwarded-For`, so the right-most entry is the proxy's own. IPv6
/// callers are grouped by /64, the usual smallest customer allocation.
/// Used only as a hashed, in-memory rate key, by the public limiter and by
/// the limiter every other API request meets before authentication.
fn public_source(headers: &hyper::HeaderMap, peer: IpAddr) -> IpAddr {
    let forwarded = peer
        .is_loopback()
        .then(|| headers.get_all("x-forwarded-for").iter().next_back())
        .flatten()
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.rsplit(',').next())
        .map(str::trim)
        .and_then(|entry| {
            entry
                .parse::<IpAddr>()
                .ok()
                .or_else(|| entry.parse::<SocketAddr>().ok().map(|address| address.ip()))
        });
    match forwarded.unwrap_or(peer) {
        IpAddr::V6(ip) => match ip.to_ipv4_mapped() {
            Some(ip) => IpAddr::V4(ip),
            None => {
                let [a, b, c, d, ..] = ip.segments();
                IpAddr::V6(Ipv6Addr::new(a, b, c, d, 0, 0, 0, 0))
            }
        },
        ip => ip,
    }
}
fn public_enabled(state: &State) -> spry_access::Result<bool> {
    Ok(state
        .lock()
        .map_err(|_| Refused(503, "Spry is temporarily unavailable."))?
        .config
        .public)
}
/// Anonymous relay credentials. Reachable only in public mode; accepts any
/// origin, needs no Authorization and keeps the body, type and time limits.
async fn public_dispatch(
    request: Request<Incoming>,
    state: State,
    peer: IpAddr,
) -> spry_access::Result<Response<Full<Bytes>>> {
    if !public_enabled(&state)? {
        return Err(Refused(404, "Not found."));
    }
    if request.method() == "OPTIONS" {
        let mut response = response(204, "text/plain", "");
        for (name, value) in [
            ("access-control-allow-methods", "POST"),
            ("access-control-allow-headers", "Content-Type"),
        ] {
            response.headers_mut().insert(
                name,
                value.parse().map_err(|_| Refused(503, "Unavailable."))?,
            );
        }
        return Ok(response);
    }
    if request.method() != "POST" {
        return Err(Refused(404, "Not found."));
    }
    let source = public_source(request.headers(), peer).to_string();
    state
        .lock()
        .map_err(|_| Refused(503, "Unavailable."))?
        .public_rate(&source, now())?;
    json_headers(request.headers(), PUBLIC_MAX_BODY)?;
    let body = read_body(request.into_body(), PUBLIC_MAX_BODY).await?;
    let body: Value =
        serde_json::from_slice(&body).map_err(|_| Refused(400, "Invalid request."))?;
    let issued = state
        .lock()
        .map_err(|_| Refused(503, "Unavailable."))?
        .public_credentials(&body, now())?;
    Ok(json_response(200, issued))
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
    if path == PUBLIC_PATH {
        return public_dispatch(request, state, peer).await;
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
    // Keyed by the caller the proxy saw, not the proxy itself, so one
    // caller's flood cannot spend the allowance of owners and paired apps.
    let source = public_source(request.headers(), peer).to_string();
    state
        .lock()
        .map_err(|_| Refused(503, "Unavailable."))?
        .rate(&source, now())?;
    json_headers(request.headers(), MAX_BODY)?;
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
    let body = read_body(request.into_body(), MAX_BODY).await?;
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
    // Only the public credential path, and only in public mode, is open to
    // every origin. It carries no credentials mode.
    let public = request.uri().path() == PUBLIC_PATH
        && request.uri().query().is_none()
        && public_enabled(&state).unwrap_or(false);
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
    if public {
        response.headers_mut().insert(
            "access-control-allow-origin",
            hyper::header::HeaderValue::from_static("*"),
        );
    } else if let Some(origin) = origin {
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
    if private_settings.is_some() && env::var("SPRY_PUBLIC").as_deref() == Ok("true") {
        return Err(public::PRIVATE_PROFILE.into());
    }
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
    // Public mode belongs to the standard profile, whose relay allocates
    // ordinary addresses. Its adverts are signed by the node transport
    // identity, never the owner's key.
    let public_setup = if private_settings.is_none() {
        let identity = Arc::new(
            spry_link::identity::Identity::derive(secret.as_bytes())
                .map_err(|_| "Invalid node identity")?,
        );
        let policy = if env::var("SPRY_LOCAL_TEST").as_deref() == Ok("true") {
            spry_link::control::RelayPolicy::LocalFixture
        } else {
            spry_link::control::RelayPolicy::Public
        };
        let settings = public::PublicSettings::from_environment(&identity.public_key(), policy)?;
        // Outbound relay settings matter only when there is a relay to reach.
        let options = if settings.relays.is_empty() {
            signalling::RelayOptions::default()
        } else {
            node::relay_options_from_environment()?
        };
        if settings.enabled && !settings.relays.is_empty() {
            spry_link::advert::Offer {
                credentials: format!("{}{PUBLIC_PATH}", config.endpoint),
                urls: config.urls.clone(),
                note: settings.note.clone(),
            }
            .validate()
            .map_err(|_| public::ADVERT_ENDPOINT)?;
        }
        config.public = settings.enabled;
        Some((identity, options, settings))
    } else {
        None
    };
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
    let mut publisher = None;
    let mut _withdrawal = None;
    if let Some((identity, options, settings)) = public_setup {
        if settings.enabled && !settings.relays.is_empty() {
            let state = state.clone();
            let note = settings.note.clone();
            let source = move || {
                let authority = state.lock().ok()?;
                authority.config.ready.then(|| spry_link::advert::Offer {
                    credentials: format!("{}{PUBLIC_PATH}", authority.config.endpoint),
                    urls: authority.config.urls.clone(),
                    note: note.clone(),
                })
            };
            publisher = Some(public::Publisher::start(
                identity,
                settings.relays,
                settings.region,
                options,
                Arc::new(source),
            ));
        } else if !settings.enabled && !settings.relays.is_empty() {
            // Public mode was turned off but its relays are still named:
            // replace any advert a previous run left there. The pause keeps
            // this newer than an advert published in the same second.
            _withdrawal = Some(tokio::spawn(async move {
                tokio::time::sleep(Duration::from_secs(1)).await;
                public::withdraw(
                    identity,
                    &settings.relays,
                    &options,
                    now(),
                    public::WITHDRAW_WAIT,
                )
                .await;
            }));
        }
    }
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
    if let Some(publisher) = publisher {
        // Withdraw before the relay stops; bounded so shutdown cannot hang.
        publisher.shutdown(public::WITHDRAW_WAIT).await;
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
    if let Err(error) = runtime.block_on(run_with_assets(assets)) {
        // Only setup refusals that name a setting are printed; other errors
        // may carry configuration values.
        match error.downcast_ref::<public::SetupError>() {
            Some(refusal) => eprintln!("Spry setup is not ready: {refusal}."),
            None => eprintln!("Spry setup is not ready. Check the service configuration."),
        }
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    const OWNER: &str = "1b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f";

    async fn host(public: bool, ready: bool) -> SocketAddr {
        host_seen_from(public, ready, None).await
    }
    /// `peer` stands in for the connecting address, as if the service were
    /// reached directly rather than through the loopback proxy.
    async fn host_seen_from(public: bool, ready: bool, peer: Option<IpAddr>) -> SocketAddr {
        let mut config = Config::new(
            "https://relay.example",
            "https://calls.example/j/",
            OWNER,
            b"synthetic-test-secret-not-for-deployment",
            None,
        )
        .unwrap();
        config.public = public;
        config.ready = ready;
        let state = Arc::new(ServiceState::new(Authority::new(config)));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let (stream, address) = listener.accept().await.unwrap();
                let peer = peer.unwrap_or(address.ip());
                let state = state.clone();
                tokio::spawn(async move {
                    let _ = hyper::server::conn::http1::Builder::new()
                        .keep_alive(false)
                        .serve_connection(
                            TokioIo::new(stream),
                            service_fn(move |request| {
                                serve(request, state.clone(), peer, UiAssets::STANDALONE)
                            }),
                        )
                        .await;
                });
            }
        });
        address
    }
    async fn send(
        address: SocketAddr,
        method: &str,
        path: &str,
        headers: &str,
        body: &str,
    ) -> String {
        let mut socket = tokio::net::TcpStream::connect(address).await.unwrap();
        let request = format!(
            "{method} {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n{headers}Content-Length: {}\r\n\r\n{body}",
            body.len()
        );
        socket.write_all(request.as_bytes()).await.unwrap();
        let mut bytes = Vec::new();
        timeout(Duration::from_secs(5), socket.read_to_end(&mut bytes))
            .await
            .unwrap()
            .unwrap();
        // Header names and status text in lower case; the body untouched.
        let text = String::from_utf8(bytes).unwrap();
        let (head, body) = text.split_once("\r\n\r\n").unwrap();
        format!("{}\r\n\r\n{body}", head.to_ascii_lowercase())
    }
    fn json(headers: &str) -> String {
        format!("Content-Type: application/json\r\n{headers}")
    }
    async fn issue(address: SocketAddr, headers: &str) -> String {
        send(address, "POST", PUBLIC_PATH, &json(headers), r#"{"v":1}"#).await
    }
    fn body(response: &str) -> Value {
        serde_json::from_str(response.split("\r\n\r\n").nth(1).unwrap()).unwrap()
    }

    #[tokio::test]
    async fn the_public_path_does_not_exist_unless_public_mode_is_on() {
        let address = host(false, true).await;
        assert!(issue(address, "").await.starts_with("http/1.1 404"));
        let preflight = send(
            address,
            "OPTIONS",
            PUBLIC_PATH,
            "Origin: https://elsewhere.example\r\n",
            "",
        )
        .await;
        assert!(preflight.starts_with("http/1.1 404"), "{preflight}");
        assert!(!preflight.contains("access-control-allow-origin"));
    }

    #[tokio::test]
    async fn public_credentials_need_no_authorisation_and_accept_any_origin_on_that_path_only() {
        let address = host(true, true).await;
        let issued = issue(address, "Origin: https://elsewhere.example\r\n").await;
        assert!(issued.starts_with("http/1.1 200"), "{issued}");
        assert!(issued.contains("access-control-allow-origin: *\r\n"));
        assert!(issued.contains("cache-control: no-store"));
        assert!(!issued.contains("access-control-allow-credentials"));
        let value = body(&issued);
        assert_eq!(
            value["urls"],
            json!([
                "turn:relay.example:3478?transport=udp",
                "turn:relay.example:3478?transport=tcp"
            ])
        );
        let username = value["username"].as_str().unwrap();
        let (expires, label) = username.split_once(':').unwrap();
        assert_eq!(
            expires.parse::<u64>().unwrap(),
            value["expiresAt"].as_u64().unwrap()
        );
        assert!(label.starts_with("pub-") && label.len() == 28);
        let again = body(&issue(address, "").await);
        assert_ne!(again["username"], value["username"]);
        assert_ne!(again["credential"], value["credential"]);

        let preflight = send(
            address,
            "OPTIONS",
            PUBLIC_PATH,
            "Origin: https://elsewhere.example\r\n",
            "",
        )
        .await;
        assert!(preflight.starts_with("http/1.1 204"), "{preflight}");
        assert!(preflight.contains("access-control-allow-origin: *\r\n"));
        assert!(preflight.contains("access-control-allow-headers: content-type\r\n"));
        // Every other path keeps its origin allowlist and Authorization rule.
        let other = send(
            address,
            "POST",
            "/v1/pairings/list",
            &json("Origin: https://elsewhere.example\r\n"),
            "{}",
        )
        .await;
        assert!(other.starts_with("http/1.1 403"), "{other}");
        assert!(!other.contains("access-control-allow-origin"));
        let other = send(
            address,
            "OPTIONS",
            "/v1/credentials",
            "Origin: https://elsewhere.example\r\n",
            "",
        )
        .await;
        assert!(other.starts_with("http/1.1 403"), "{other}");
        assert!(
            send(address, "POST", "/v1/credentials", &json(""), "{}")
                .await
                .starts_with("http/1.1 401")
        );
        let allowed = send(
            address,
            "POST",
            "/v1/pairings/list",
            &json("Origin: https://calls.example\r\n"),
            "{}",
        )
        .await;
        assert!(allowed.contains("access-control-allow-origin: https://calls.example\r\n"));
    }

    #[tokio::test]
    async fn public_requests_keep_the_type_size_and_body_checks() {
        let address = host(true, true).await;
        let source = |n: u8| format!("X-Forwarded-For: 192.0.2.{n}\r\n");
        assert!(
            send(address, "POST", PUBLIC_PATH, &source(1), r#"{"v":1}"#)
                .await
                .starts_with("http/1.1 415")
        );
        assert!(
            send(
                address,
                "POST",
                PUBLIC_PATH,
                &json(&format!("{}Content-Encoding: gzip\r\n", source(2))),
                r#"{"v":1}"#
            )
            .await
            .starts_with("http/1.1 415")
        );
        let large = format!(r#"{{"v":1,"x":"{}"}}"#, "x".repeat(300));
        assert!(
            send(address, "POST", PUBLIC_PATH, &json(&source(3)), &large)
                .await
                .starts_with("http/1.1 413")
        );
        for wrong in ["{}", r#"{"v":2}"#, "not json", r#"{"v":1,"grant":"x"}"#] {
            assert!(
                send(address, "POST", PUBLIC_PATH, &json(&source(4)), wrong)
                    .await
                    .starts_with("http/1.1 400"),
                "{wrong}"
            );
        }
        assert!(
            send(address, "GET", PUBLIC_PATH, "", "")
                .await
                .starts_with("http/1.1 404")
        );
        assert!(
            send(
                address,
                "POST",
                &format!("{PUBLIC_PATH}?x=1"),
                &json(""),
                r#"{"v":1}"#
            )
            .await
            .starts_with("http/1.1 404")
        );
    }

    #[tokio::test]
    async fn public_limits_apply_per_source_and_in_total() {
        let address = host(true, true).await;
        let from = |source: &str| format!("X-Forwarded-For: 203.0.113.250, {source}\r\n");
        for _ in 0..6 {
            assert!(
                issue(address, &from("192.0.2.1"))
                    .await
                    .starts_with("http/1.1 200")
            );
        }
        let limited = issue(address, &from("192.0.2.1")).await;
        assert!(limited.starts_with("http/1.1 429"), "{limited}");
        assert!(limited.contains("access-control-allow-origin: *\r\n"));
        // One IPv6 /64 is one source.
        for n in 1..=6 {
            assert!(
                issue(address, &from(&format!("2001:db8:1:2::{n}")))
                    .await
                    .starts_with("http/1.1 200")
            );
        }
        assert!(
            issue(address, &from("2001:db8:1:2:ffff::1"))
                .await
                .starts_with("http/1.1 429")
        );
        for n in 0..20 {
            assert!(
                issue(address, &from(&format!("198.51.100.{n}")))
                    .await
                    .starts_with("http/1.1 200")
            );
        }
        assert!(
            issue(address, &from("198.51.100.200"))
                .await
                .starts_with("http/1.1 429")
        );
    }

    async fn unsigned(address: SocketAddr, forwarded: &str) -> String {
        let headers = json(&format!("X-Forwarded-For: {forwarded}\r\n"));
        send(address, "POST", "/v1/credentials", &headers, "{}").await
    }

    #[tokio::test]
    async fn the_api_limiter_keys_on_the_forwarded_source_not_the_proxy() {
        let address = host(false, true).await;
        // Each source has its own allowance before authentication.
        for _ in 0..120 {
            let refused = unsigned(address, "198.51.100.1").await;
            assert!(refused.starts_with("http/1.1 401"), "{refused}");
        }
        let flooded = unsigned(address, "198.51.100.1").await;
        assert!(flooded.starts_with("http/1.1 429"), "{flooded}");
        assert!(flooded.contains("Too many requests. Try again shortly."));
        // A flood from one source leaves another, such as an owner, alone.
        let other = unsigned(address, "198.51.100.2").await;
        assert!(other.starts_with("http/1.1 401"), "{other}");
        // One IPv6 /64 is one source here too.
        for n in 0..120 {
            assert!(
                unsigned(address, &format!("2001:db8:5:6::{n:x}"))
                    .await
                    .starts_with("http/1.1 401")
            );
        }
        assert!(
            unsigned(address, "2001:db8:5:6:ffff::1")
                .await
                .starts_with("http/1.1 429")
        );
    }

    #[tokio::test]
    async fn a_direct_callers_forwarded_header_is_ignored() {
        let remote: IpAddr = "203.0.113.5".parse().unwrap();
        let address = host_seen_from(false, true, Some(remote)).await;
        // Varying the header does not buy a non-loopback caller new buckets.
        for n in 0..120 {
            let refused = unsigned(address, &format!("192.0.2.{n}")).await;
            assert!(refused.starts_with("http/1.1 401"), "{refused}");
        }
        assert!(
            unsigned(address, "192.0.2.200")
                .await
                .starts_with("http/1.1 429")
        );
    }

    #[tokio::test]
    async fn public_credentials_wait_for_the_relay() {
        let address = host(true, false).await;
        let refused = issue(address, "").await;
        assert!(refused.starts_with("http/1.1 503"), "{refused}");
        assert!(refused.contains("needs public access before Spry can connect calls"));
    }

    #[test]
    fn public_source_trusts_only_the_proxy_appended_entry() {
        let loopback: IpAddr = "127.0.0.1".parse().unwrap();
        let mut headers = hyper::HeaderMap::new();
        assert_eq!(public_source(&headers, loopback), loopback);
        headers.insert(
            "x-forwarded-for",
            "192.0.2.9, 198.51.100.7".parse().unwrap(),
        );
        assert_eq!(
            public_source(&headers, loopback).to_string(),
            "198.51.100.7"
        );
        let remote: IpAddr = "203.0.113.5".parse().unwrap();
        assert_eq!(public_source(&headers, remote), remote);
        headers.insert(
            "x-forwarded-for",
            "[2001:db8:a:b:c:d:e:f]:443".parse().unwrap(),
        );
        assert_eq!(
            public_source(&headers, loopback).to_string(),
            "2001:db8:a:b::"
        );
        headers.insert("x-forwarded-for", "::ffff:192.0.2.1".parse().unwrap());
        assert_eq!(public_source(&headers, loopback).to_string(), "192.0.2.1");
        headers.insert("x-forwarded-for", "not an address".parse().unwrap());
        assert_eq!(public_source(&headers, loopback), loopback);
    }
}
