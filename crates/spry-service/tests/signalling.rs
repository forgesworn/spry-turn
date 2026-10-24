use futures_util::{SinkExt, StreamExt};
use serde_json::{Value, json};
use spry_link::{
    control::{self, AcceptedRequest, ControlEndpoint, RelayPolicy},
    identity::{Event, Identity},
};
use spry_service::signalling::{ControlHandler, RelayOptions, SignallingRuntime};
use std::{
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::{
    net::{TcpListener, TcpStream},
    time::timeout,
};
use tokio_tungstenite::{accept_async, client_async, tungstenite::Message};

struct Handler(AtomicUsize);
impl ControlHandler for Handler {
    fn handle(&self, request: &AcceptedRequest, _: u64) -> (u16, Value) {
        self.0.fetch_add(1, Ordering::Relaxed);
        (200, json!({"scope":request.body["scope"]}))
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn targeted_control_authenticates_the_relay_and_replies_once_across_retries() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("ws://{}/", listener.local_addr().unwrap());
    let node = Arc::new(Identity::from_secret(&[1; 32]).unwrap());
    let client = Identity::from_secret(&[2; 32]).unwrap();
    let target = ControlEndpoint::new(
        node.public_key(),
        vec![url.clone()],
        RelayPolicy::LocalFixture,
    )
    .unwrap();
    let relay = tokio::spawn(async move {
        let (server, _) = listener.accept().await.unwrap();
        let mut server = accept_async(server).await.unwrap();
        server
            .send(Message::Text(
                json!(["AUTH", "generated-challenge"]).to_string().into(),
            ))
            .await
            .unwrap();
        let subscription = loop {
            let Some(Ok(Message::Text(text))) = server.next().await else {
                continue;
            };
            let value: Value = serde_json::from_str(&text).unwrap();
            if value[0] == "REQ" {
                server
                    .send(Message::Text(
                        json!(["CLOSED", value[1], "auth-required: fixture"])
                            .to_string()
                            .into(),
                    ))
                    .await
                    .unwrap();
            }
            if value[0] == "AUTH" {
                let event: Event = serde_json::from_value(value[1].clone()).unwrap();
                event.verify().unwrap();
                assert_eq!(event.kind, 22242);
                assert_eq!(event.tag("challenge").unwrap(), "generated-challenge");
                server
                    .send(Message::Text(
                        json!(["OK", event.id, true, ""]).to_string().into(),
                    ))
                    .await
                    .unwrap();
                loop {
                    let Some(Ok(Message::Text(text))) = server.next().await else {
                        continue;
                    };
                    let value: Value = serde_json::from_str(&text).unwrap();
                    if value[0] == "REQ" {
                        assert_eq!(value[1], "spry-control-v1");
                        break;
                    }
                }
                break "spry-control-v1".to_string();
            }
        };
        server
            .send(Message::Text(
                json!(["EOSE", subscription]).to_string().into(),
            ))
            .await
            .unwrap();
        let (caller, _) = listener.accept().await.unwrap();
        let mut caller = accept_async(caller).await.unwrap();
        for _ in 0..2 {
            let event = loop {
                if let Some(Ok(Message::Text(text))) = caller.next().await {
                    let value: Value = serde_json::from_str(&text).unwrap();
                    if value[0] == "EVENT" {
                        break value[1].clone();
                    }
                }
            };
            server
                .send(Message::Text(
                    json!(["EVENT", subscription, event]).to_string().into(),
                ))
                .await
                .unwrap();
            loop {
                if let Some(Ok(Message::Text(text))) = server.next().await {
                    let value: Value = serde_json::from_str(&text).unwrap();
                    if value[0] == "EVENT" {
                        caller.send(Message::Text(text)).await.unwrap();
                        break;
                    }
                }
            }
        }
    });
    let handler = Arc::new(Handler(AtomicUsize::new(0)));
    let runtime = SignallingRuntime::start(
        node,
        handler.clone(),
        RelayOptions {
            policy: RelayPolicy::LocalFixture,
            socks_proxy: None,
            tls: None,
        },
    );
    runtime.control.configure(target.clone());
    timeout(Duration::from_secs(5), async {
        while runtime.control.active_relays() == 0 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let request = control::request(
        &client,
        &target,
        "/v1/grants",
        &json!({"scope":"generated"}),
        now,
    )
    .unwrap();
    let parsed = url::Url::parse(&url).unwrap();
    let stream = TcpStream::connect((parsed.host_str().unwrap(), parsed.port().unwrap()))
        .await
        .unwrap();
    let (mut socket, _) = client_async(url, stream).await.unwrap();
    let mut ids = Vec::new();
    for _ in 0..2 {
        socket
            .send(Message::Text(json!(["EVENT", request]).to_string().into()))
            .await
            .unwrap();
        let response = timeout(Duration::from_secs(3), async {
            loop {
                if let Some(Ok(Message::Text(text))) = socket.next().await {
                    let value: Value = serde_json::from_str(&text).unwrap();
                    if value[0] == "EVENT" {
                        break serde_json::from_value::<Event>(value[1].clone()).unwrap();
                    }
                }
            }
        })
        .await
        .unwrap();
        assert_eq!(
            control::open_response(&client, &request, &target, &response, now).unwrap(),
            (200, json!({"scope":"generated"}))
        );
        ids.push(response.id);
    }
    assert_eq!(ids[0], ids[1]);
    assert_eq!(handler.0.load(Ordering::Relaxed), 1);
    timeout(Duration::from_secs(3), relay)
        .await
        .unwrap()
        .unwrap();
    drop(runtime);
}
