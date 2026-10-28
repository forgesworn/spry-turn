use futures_util::{SinkExt, StreamExt};
use serde_json::{Value, json};
use spry_link::{
    advert::{AdvertBook, MAX_TRACKED, Offer, Status},
    control::RelayPolicy,
    identity::{Event, Identity},
};
use spry_service::{
    public::{Publisher, WITHDRAW_WAIT},
    signalling::RelayOptions,
};
use std::{sync::Arc, time::Duration};
use tokio::{net::TcpListener, sync::mpsc, time::timeout};
use tokio_tungstenite::{accept_async, tungstenite::Message};

fn offer() -> Offer {
    Offer {
        credentials: "https://relay.example/v1/public/credentials".into(),
        urls: vec!["turn:relay.example:3478?transport=udp".into()],
        note: None,
    }
}

/// A generated relay that accepts every event, answering one NIP-42
/// challenge first, and forwards what it received.
async fn fixture_relay() -> (String, mpsc::Receiver<Event>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("ws://{}/", listener.local_addr().unwrap());
    let (sender, receiver) = mpsc::channel(8);
    tokio::spawn(async move {
        loop {
            let (stream, _) = listener.accept().await.unwrap();
            let sender = sender.clone();
            tokio::spawn(async move {
                let mut socket = accept_async(stream).await.unwrap();
                socket
                    .send(Message::Text(
                        json!(["AUTH", "generated-challenge"]).to_string().into(),
                    ))
                    .await
                    .unwrap();
                let mut authenticated = false;
                while let Some(Ok(Message::Text(text))) = socket.next().await {
                    let value: Value = serde_json::from_str(&text).unwrap();
                    match value[0].as_str() {
                        Some("AUTH") => {
                            let auth: Event = serde_json::from_value(value[1].clone()).unwrap();
                            auth.verify().unwrap();
                            assert_eq!(auth.kind, 22242);
                            authenticated = true;
                            let reply = json!(["OK", auth.id, true, ""]);
                            socket
                                .send(Message::Text(reply.to_string().into()))
                                .await
                                .unwrap();
                        }
                        Some("EVENT") => {
                            let event: Event = serde_json::from_value(value[1].clone()).unwrap();
                            let reply = if authenticated {
                                json!(["OK", event.id, true, ""])
                            } else {
                                json!(["OK", event.id, false, "auth-required: fixture"])
                            };
                            socket
                                .send(Message::Text(reply.to_string().into()))
                                .await
                                .unwrap();
                            if authenticated {
                                sender.send(event).await.unwrap();
                            }
                        }
                        _ => {}
                    }
                }
            });
        }
    });
    (url, receiver)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn publisher_waits_for_ready_and_withdraws_with_a_newer_advert() {
    let (relay, mut received) = fixture_relay().await;
    let node = Arc::new(Identity::from_secret(&[6; 32]).unwrap());
    let ready = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let source = {
        let ready = ready.clone();
        move || ready.load(std::sync::atomic::Ordering::Acquire).then(offer)
    };
    let options = RelayOptions {
        policy: RelayPolicy::LocalFixture,
        ..RelayOptions::default()
    };
    let publisher = Publisher::start(
        node.clone(),
        vec![relay],
        Some("GB".into()),
        Some("https://operator.example/privacy".into()),
        options,
        Arc::new(source),
    );
    // Nothing is advertised before the relay reports ready.
    assert!(
        timeout(Duration::from_millis(1500), received.recv())
            .await
            .is_err()
    );
    ready.store(true, std::sync::atomic::Ordering::Release);
    let open = timeout(Duration::from_secs(10), received.recv())
        .await
        .unwrap()
        .unwrap();
    // Withdraw in the same second as the open advert: it must still be newer.
    let withdrawn = timeout(Duration::from_secs(10), publisher.shutdown(WITHDRAW_WAIT))
        .await
        .unwrap()
        .unwrap();
    let delivered = timeout(Duration::from_secs(10), received.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(delivered.id, withdrawn.id);
    assert!(withdrawn.created_at > open.created_at);
    assert_eq!(open.pubkey, node.public_key());

    let now = withdrawn.created_at;
    let mut book = AdvertBook::new(MAX_TRACKED);
    let first = book.accept(&open, now).unwrap();
    assert_eq!(first.status, Status::Open(offer()));
    assert_eq!(first.region.as_deref(), Some("GB"));
    assert_eq!(
        first.privacy.as_deref(),
        Some("https://operator.example/privacy")
    );
    // A withdrawal names no region and carries no privacy link.
    assert!(withdrawn.tag("privacy").is_err());
    let gone = book.accept(&withdrawn, now).unwrap();
    assert_eq!(gone.status, Status::Withdrawn);
    assert_eq!(gone.privacy, None);
    assert_eq!(book.open(now).count(), 0);
    assert!(book.accept(&open, now).is_err());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_unreachable_relay_does_not_hold_shutdown_past_the_bound() {
    // A reserved local port with nothing listening.
    let closed = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let relay = format!("ws://{}/", closed.local_addr().unwrap());
    drop(closed);
    let publisher = Publisher::start(
        Arc::new(Identity::from_secret(&[7; 32]).unwrap()),
        vec![relay],
        None,
        None,
        RelayOptions {
            policy: RelayPolicy::LocalFixture,
            ..RelayOptions::default()
        },
        Arc::new(|| Some(offer())),
    );
    tokio::time::sleep(Duration::from_millis(200)).await;
    let started = std::time::Instant::now();
    assert!(publisher.shutdown(Duration::from_secs(2)).await.is_some());
    assert!(started.elapsed() < Duration::from_secs(4));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn losing_readiness_withdraws_the_advert_and_regaining_it_reopens() {
    let (relay, mut received) = fixture_relay().await;
    let node = Arc::new(Identity::from_secret(&[8; 32]).unwrap());
    let ready = Arc::new(std::sync::atomic::AtomicBool::new(true));
    let source = {
        let ready = ready.clone();
        move || ready.load(std::sync::atomic::Ordering::Acquire).then(offer)
    };
    let publisher = Publisher::start(
        node.clone(),
        vec![relay],
        None,
        None,
        RelayOptions {
            policy: RelayPolicy::LocalFixture,
            ..RelayOptions::default()
        },
        Arc::new(source),
    );
    let mut next = async || {
        timeout(Duration::from_secs(10), received.recv())
            .await
            .unwrap()
            .unwrap()
    };
    let first = next().await;
    // The relay stops, as when its process dies while the service runs.
    ready.store(false, std::sync::atomic::Ordering::Release);
    let withdrawn = next().await;
    ready.store(true, std::sync::atomic::Ordering::Release);
    let reopened = next().await;
    assert!(first.created_at < withdrawn.created_at);
    assert!(withdrawn.created_at < reopened.created_at);

    let now = reopened.created_at;
    let mut book = AdvertBook::new(MAX_TRACKED);
    assert_eq!(
        book.accept(&first, now).unwrap().status,
        Status::Open(offer())
    );
    assert_eq!(
        book.accept(&withdrawn, now).unwrap().status,
        Status::Withdrawn
    );
    assert_eq!(book.open(now).count(), 0);
    assert_eq!(
        book.accept(&reopened, now).unwrap().status,
        Status::Open(offer())
    );
    assert_eq!(book.open(now).count(), 1);
    // A repeat of the withdrawal cannot hide the newer open advert.
    assert!(book.accept(&withdrawn, now).is_err());
    publisher.shutdown(WITHDRAW_WAIT).await;
}
