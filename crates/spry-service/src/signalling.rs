//! Optional outbound Nostr control adapter. Relays are explicitly owner-selected.
use futures_util::{SinkExt, StreamExt};
use serde_json::{Value, json};
use spry_link::{
    MAX_EVENT,
    control::{self, AcceptedRequest, ControlEndpoint, RelayPolicy},
    identity::{Event, Identity},
};
use std::{
    collections::HashMap,
    io,
    net::{IpAddr, SocketAddr},
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpStream, lookup_host},
    sync::{broadcast, mpsc, watch},
    task::{JoinHandle, JoinSet},
    time::{interval, timeout},
};
use tokio_tungstenite::{
    MaybeTlsStream, WebSocketStream, client_async_tls_with_config,
    tungstenite::{Message, protocol::WebSocketConfig},
};
use url::Url;

pub trait ControlHandler: Send + Sync + 'static {
    fn handle(&self, request: &AcceptedRequest, now: u64) -> (u16, Value);
}
#[derive(Clone)]
pub struct RelayOptions {
    pub policy: RelayPolicy,
    pub socks_proxy: Option<SocketAddr>,
    pub tls: Option<Arc<rustls::ClientConfig>>,
}
impl Default for RelayOptions {
    fn default() -> Self {
        Self {
            policy: RelayPolicy::Public,
            socks_proxy: None,
            tls: None,
        }
    }
}

#[derive(Clone)]
pub struct RelayControl {
    updates: watch::Sender<Option<ControlEndpoint>>,
    active: Arc<AtomicUsize>,
}
impl RelayControl {
    pub fn configure(&self, endpoint: ControlEndpoint) {
        if self.updates.borrow().as_ref() == Some(&endpoint) {
            return;
        }
        self.updates.send_replace(Some(endpoint));
    }
    pub fn active_relays(&self) -> usize {
        self.active.load(Ordering::Relaxed)
    }
}
pub struct SignallingRuntime {
    pub control: RelayControl,
    manager: JoinHandle<()>,
    processor: JoinHandle<()>,
}
impl Drop for SignallingRuntime {
    fn drop(&mut self) {
        self.manager.abort();
        self.processor.abort();
    }
}
impl SignallingRuntime {
    pub fn start(
        identity: Arc<Identity>,
        handler: Arc<dyn ControlHandler>,
        options: RelayOptions,
    ) -> Self {
        let (updates, receive) = watch::channel(None);
        let (incoming, requests) = mpsc::channel(64);
        let (outgoing, _) = broadcast::channel(32);
        let active = Arc::new(AtomicUsize::new(0));
        let processor = tokio::spawn(process(
            identity.clone(),
            handler,
            requests,
            outgoing.clone(),
        ));
        let manager = tokio::spawn(manage(
            identity,
            receive,
            incoming,
            outgoing,
            active.clone(),
            options,
        ));
        Self {
            control: RelayControl { updates, active },
            manager,
            processor,
        }
    }
}
fn refused() -> io::Error {
    io::Error::other("Control relay is unavailable")
}
fn now() -> u64 {
    super::now()
}

async fn process(
    identity: Arc<Identity>,
    handler: Arc<dyn ControlHandler>,
    mut requests: mpsc::Receiver<Event>,
    outgoing: broadcast::Sender<Event>,
) {
    let mut cache: HashMap<String, (u64, Event)> = HashMap::new();
    let mut second = now();
    let mut count = 0_u16;
    while let Some(event) = requests.recv().await {
        let timestamp = now();
        cache.retain(|_, (expires, _)| *expires > timestamp);
        if second != timestamp {
            second = timestamp;
            count = 0;
        }
        count = count.saturating_add(1);
        if count > 64 {
            continue;
        }
        if event.created_at.abs_diff(timestamp) > 60 {
            continue;
        }
        if let Some((_, response)) = cache.get(&event.id) {
            let _ = outgoing.send(response.clone());
            continue;
        }
        let Ok(request) = control::open_request(&identity, &event, timestamp) else {
            continue;
        };
        let (status, body) = if cache.len() >= 1024 {
            (429, json!({"error":"Spry is busy. Try again shortly."}))
        } else {
            handler.handle(&request, timestamp)
        };
        let Ok(response) = control::response(&identity, &request, status, &body, timestamp) else {
            continue;
        };
        if (200..300).contains(&status) {
            cache.insert(event.id, (request.expires_at, response.clone()));
        }
        let _ = outgoing.send(response);
    }
}

async fn manage(
    identity: Arc<Identity>,
    mut updates: watch::Receiver<Option<ControlEndpoint>>,
    incoming: mpsc::Sender<Event>,
    outgoing: broadcast::Sender<Event>,
    active: Arc<AtomicUsize>,
    options: RelayOptions,
) {
    let mut workers = JoinSet::new();
    while updates.changed().await.is_ok() {
        workers.abort_all();
        while workers.join_next().await.is_some() {}
        let target = updates.borrow_and_update().clone();
        let Some(target) = target else {
            continue;
        };
        if target.public_key != identity.public_key() {
            continue;
        }
        let Ok(target) = ControlEndpoint::new(target.public_key, target.relays, options.policy)
        else {
            continue;
        };
        for relay in target.relays {
            let (identity, incoming, outgoing, active, options) = (
                identity.clone(),
                incoming.clone(),
                outgoing.clone(),
                active.clone(),
                options.clone(),
            );
            workers.spawn(async move {
                let mut backoff = 1;
                loop {
                    if let Ok(Ok(socket)) =
                        timeout(Duration::from_secs(10), connect(&relay, &options)).await
                    {
                        backoff = 1;
                        let _ = session(
                            identity.clone(),
                            &relay,
                            socket,
                            incoming.clone(),
                            outgoing.subscribe(),
                            active.clone(),
                        )
                        .await;
                    }
                    tokio::time::sleep(Duration::from_secs(backoff)).await;
                    backoff = (backoff * 2).min(30);
                }
            });
        }
    }
}
struct Active(Arc<AtomicUsize>);
impl Active {
    fn new(count: Arc<AtomicUsize>) -> Self {
        count.fetch_add(1, Ordering::Relaxed);
        Self(count)
    }
}
impl Drop for Active {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Relaxed);
    }
}

type RelaySocket = WebSocketStream<MaybeTlsStream<TcpStream>>;
async fn send_message(socket: &mut RelaySocket, message: Message) -> io::Result<()> {
    timeout(Duration::from_secs(3), socket.send(message))
        .await
        .map_err(|_| refused())?
        .map_err(|_| refused())
}
async fn session(
    identity: Arc<Identity>,
    relay: &str,
    mut socket: RelaySocket,
    incoming: mpsc::Sender<Event>,
    mut outgoing: broadcast::Receiver<Event>,
    active: Arc<AtomicUsize>,
) -> io::Result<()> {
    let subscription = "spry-control-v1";
    let filter=json!(["REQ",subscription,{"kinds":[control::REQUEST_KIND],"#p":[identity.public_key()],"since":now().saturating_sub(60),"limit":64}]).to_string();
    send_message(&mut socket, Message::Text(filter.clone().into())).await?;
    let mut ready = None;
    let mut authentication = 0;
    let mut auth_pending: Option<String> = None;
    let mut second = now();
    let mut count = 0_u16;
    let mut keepalive = interval(Duration::from_secs(20));
    let mut latest = now();
    let subscribe_deadline = tokio::time::sleep(Duration::from_secs(10));
    tokio::pin!(subscribe_deadline);
    loop {
        tokio::select! {
            _=&mut subscribe_deadline,if ready.is_none()=>return Err(refused()),
            response=outgoing.recv()=>match response {
                Ok(event)=>send_message(&mut socket,Message::Text(json!(["EVENT",event]).to_string().into())).await?,
                Err(broadcast::error::RecvError::Lagged(_))=>continue,
                Err(_)=>return Ok(()),
            },
            _=keepalive.tick()=>{
                if now().saturating_sub(latest)>60{return Err(refused());}
                send_message(&mut socket,Message::Ping(Vec::new().into())).await?;
            },
            message=socket.next()=>{
                latest=now();if latest!=second{second=latest;count=0;}count=count.saturating_add(1);if count>256{return Err(refused());}
                let Some(Ok(message))=message else{return Err(refused());};
                let Message::Text(text)=message else {if matches!(message,Message::Close(_)){return Ok(());}continue;};
                if text.len()>MAX_EVENT+512{return Err(refused());}
                let Ok(value)=serde_json::from_str::<Value>(&text)else{continue;};
                match value[0].as_str(){
                    Some("EOSE")if value[1]==subscription&&auth_pending.is_none()=>if ready.is_none(){ready=Some(Active::new(active.clone()));},
                    Some("EVENT")if value[1]==subscription=>{
                        if let Ok(event)=serde_json::from_value(value[2].clone()){let _=incoming.try_send(event);}
                    },
                    Some("AUTH")=>{
                        authentication+=1;if authentication>4{return Err(refused());}
                        let Some(challenge)=value[1].as_str().filter(|challenge|challenge.len()<=256)else{return Err(refused());};
                        let event=identity.sign(22242,vec![vec!["relay".into(),relay.into()],vec!["challenge".into(),challenge.into()]],String::new(),now()).map_err(|_|refused())?;
                        auth_pending=Some(event.id.clone());ready.take();subscribe_deadline.as_mut().reset(tokio::time::Instant::now()+Duration::from_secs(10));
                        send_message(&mut socket,Message::Text(json!(["AUTH",event]).to_string().into())).await?;
                    },
                    Some("OK")if auth_pending.as_deref()==value[1].as_str()=>{
                        if value[2]!=true{return Err(refused());}auth_pending=None;
                        send_message(&mut socket,Message::Text(filter.clone().into())).await?;
                    },
                    Some("CLOSED")if value[1]==subscription=>{
                        if !value[2].as_str().is_some_and(|reason|reason.starts_with("auth-required:")){return Err(refused());}
                        ready.take();
                    },
                    _=>{},
                }
            }
        }
    }
}

/// Publishes one event to one relay and waits, bounded, for its acceptance.
/// Answers at most two NIP-42 challenges with the same transport identity.
pub(crate) async fn publish(
    relay: &str,
    options: &RelayOptions,
    identity: &Identity,
    event: &Event,
) -> io::Result<()> {
    let mut socket = timeout(Duration::from_secs(10), connect(relay, options))
        .await
        .map_err(|_| refused())??;
    let message = json!(["EVENT", event]).to_string();
    send_message(&mut socket, Message::Text(message.clone().into())).await?;
    let mut authentication = 0;
    let mut auth_pending: Option<String> = None;
    let result = timeout(Duration::from_secs(10), async {
        for _ in 0..64 {
            let Some(Ok(reply)) = socket.next().await else {
                return Err(refused());
            };
            let Message::Text(text) = reply else {
                if matches!(reply, Message::Close(_)) {
                    return Err(refused());
                }
                continue;
            };
            if text.len() > MAX_EVENT + 512 {
                return Err(refused());
            }
            let Ok(value) = serde_json::from_str::<Value>(&text) else {
                continue;
            };
            match value[0].as_str() {
                Some("AUTH") => {
                    authentication += 1;
                    let Some(challenge) = value[1]
                        .as_str()
                        .filter(|challenge| challenge.len() <= 256 && authentication <= 2)
                    else {
                        return Err(refused());
                    };
                    let auth = identity
                        .sign(
                            22242,
                            vec![
                                vec!["relay".into(), relay.into()],
                                vec!["challenge".into(), challenge.into()],
                            ],
                            String::new(),
                            now(),
                        )
                        .map_err(|_| refused())?;
                    auth_pending = Some(auth.id.clone());
                    send_message(
                        &mut socket,
                        Message::Text(json!(["AUTH", auth]).to_string().into()),
                    )
                    .await?;
                }
                Some("OK")
                    if auth_pending.is_some() && auth_pending.as_deref() == value[1].as_str() =>
                {
                    if value[2] != true {
                        return Err(refused());
                    }
                    auth_pending = None;
                    send_message(&mut socket, Message::Text(message.clone().into())).await?;
                }
                Some("OK") if value[1] == event.id.as_str() => {
                    if value[2] == true {
                        return Ok(());
                    }
                    // A relay that wants authentication first says so, then challenges.
                    if !value[3]
                        .as_str()
                        .is_some_and(|reason| reason.starts_with("auth-required:"))
                    {
                        return Err(refused());
                    }
                }
                _ => {}
            }
        }
        Err(refused())
    })
    .await
    .map_err(|_| refused())?;
    let _ = timeout(Duration::from_secs(1), socket.close(None)).await;
    result
}
fn public_address(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => super::public_v4(ip),
        IpAddr::V6(ip) => {
            let parts = ip.segments();
            parts[0] & 0xe000 == 0x2000
                && parts[0] != 0x2002
                && parts[0] != 0x3fff
                && !(parts[0] == 0x2001 && (parts[1] < 0x0200 || parts[1] == 0x0db8))
        }
    }
}
async fn connect(
    relay: &str,
    options: &RelayOptions,
) -> io::Result<WebSocketStream<MaybeTlsStream<TcpStream>>> {
    let url = Url::parse(relay).map_err(|_| refused())?;
    let host = url
        .host_str()
        .ok_or_else(refused)?
        .trim_start_matches('[')
        .trim_end_matches(']');
    let port = url.port_or_known_default().ok_or_else(refused)?;
    let stream = if let Some(proxy) = options.socks_proxy {
        dial_socks(proxy, host, port).await?
    } else {
        let mut chosen = None;
        for address in lookup_host((host, port)).await?.take(8) {
            if !matches!(options.policy, RelayPolicy::LocalFixture) && !public_address(address.ip())
            {
                continue;
            }
            // Connect each checked address directly, with a bounded fallback
            // for hosts whose IPv6 route is unavailable. Never resolve twice.
            if let Ok(Ok(stream)) =
                timeout(Duration::from_secs(2), TcpStream::connect(address)).await
            {
                chosen = Some(stream);
                break;
            }
        }
        chosen.ok_or_else(refused)?
    };
    stream.set_nodelay(true)?;
    let config = WebSocketConfig::default()
        .max_message_size(Some(MAX_EVENT + 512))
        .max_frame_size(Some(MAX_EVENT + 512))
        .write_buffer_size(1024)
        .max_write_buffer_size(65_536);
    let (socket, _) = client_async_tls_with_config(
        relay,
        stream,
        Some(config),
        options
            .tls
            .clone()
            .map(tokio_tungstenite::Connector::Rustls),
    )
    .await
    .map_err(|_| refused())?;
    Ok(socket)
}
async fn dial_socks(proxy: SocketAddr, host: &str, port: u16) -> io::Result<TcpStream> {
    if host.len() > 253 || host.is_empty() {
        return Err(refused());
    }
    let mut stream = TcpStream::connect(proxy).await?;
    stream.write_all(&[5, 1, 0]).await?;
    let mut method = [0; 2];
    stream.read_exact(&mut method).await?;
    if method != [5, 0] {
        return Err(refused());
    }
    let mut request = vec![5, 1, 0, 3, host.len() as u8];
    request.extend_from_slice(host.as_bytes());
    request.extend_from_slice(&port.to_be_bytes());
    stream.write_all(&request).await?;
    let mut header = [0; 4];
    stream.read_exact(&mut header).await?;
    if header[..3] != [5, 0, 0] {
        return Err(refused());
    }
    let length = match header[3] {
        1 => 4,
        4 => 16,
        3 => {
            let length = usize::from(stream.read_u8().await?);
            if length == 0 {
                return Err(refused());
            }
            length
        }
        _ => return Err(refused()),
    };
    let mut bound = vec![0; length + 2];
    stream.read_exact(&mut bound).await?;
    Ok(stream)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn socks_uses_remote_dns_and_refuses_unsupported_authentication() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let proxy = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut hello = [0; 3];
            socket.read_exact(&mut hello).await.unwrap();
            assert_eq!(hello, [5, 1, 0]);
            socket.write_all(&[5, 0]).await.unwrap();
            let mut header = [0; 5];
            socket.read_exact(&mut header).await.unwrap();
            assert_eq!(&header[..4], &[5, 1, 0, 3]);
            let mut target = vec![0; usize::from(header[4]) + 2];
            socket.read_exact(&mut target).await.unwrap();
            assert_eq!(&target[..target.len() - 2], b"relay.example");
            assert_eq!(&target[target.len() - 2..], &443_u16.to_be_bytes());
            socket
                .write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0, 1])
                .await
                .unwrap();
            let mut data = [0; 4];
            socket.read_exact(&mut data).await.unwrap();
            assert_eq!(&data, b"ping");
        });
        let mut stream = dial_socks(address, "relay.example", 443).await.unwrap();
        stream.write_all(b"ping").await.unwrap();
        proxy.await.unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let proxy = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut hello = [0; 3];
            socket.read_exact(&mut hello).await.unwrap();
            socket.write_all(&[5, 2]).await.unwrap();
        });
        assert!(dial_socks(address, "relay.example", 443).await.is_err());
        proxy.await.unwrap();
    }

    #[test]
    fn direct_control_refuses_private_and_reserved_dns_answers() {
        for address in [
            "127.0.0.1",
            "10.0.0.1",
            "192.168.0.1",
            "100.64.0.1",
            "169.254.0.1",
            "::1",
            "fd12::1",
            "fe80::1",
            "::ffff:127.0.0.1",
        ] {
            assert!(!public_address(address.parse().unwrap()), "{address}");
        }
    }
}
