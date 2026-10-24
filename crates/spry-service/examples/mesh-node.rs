//! Generated-fixture controller over local stdin; never an unauthenticated network API.
use serde_json::{Value, json};
use spry_link::{identity::Event, peer::PeerCard, registry::PeerRegistry};
use spry_service::mesh::{Mesh, MeshConfig};
use std::io::{BufRead, Write};

#[tokio::main(flavor = "multi_thread", worker_threads = 2)]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let (send, mut receive) = tokio::sync::mpsc::channel(8);
    let input = std::thread::spawn(move || {
        let input = std::io::stdin();
        for line in input.lock().lines() {
            let Ok(line) = line else {
                break;
            };
            if line.len() > 16_384 {
                break;
            }
            if send.blocking_send(line).is_err() {
                break;
            }
        }
    });
    let line = receive.recv().await.ok_or("Missing fixture config")?;
    let config: Value = serde_json::from_str(&line)?;
    let mesh = Mesh::start(MeshConfig {
        peer_name: config["name"].as_str().map(str::to_owned),
        resolver: config["resolver"]
            .as_str()
            .map(|address| {
                spry_service::resolver::PeerResolver::new(address.parse().unwrap(), "fips".into())
            })
            .transpose()?,
        client_listen: config["client"].as_str().ok_or("client")?.parse()?,
        peer_listen: config["peer"].as_str().ok_or("peer")?.parse()?,
        secret: config["secret"]
            .as_str()
            .ok_or("secret")?
            .as_bytes()
            .to_vec(),
    })
    .await?;
    let mut registry = PeerRegistry::new(mesh.public_key()).map_err(|_| "registry")?;
    println!("{}", json!({"card":mesh.card()?}));
    std::io::stdout().flush()?;
    while let Some(line) = receive.recv().await {
        let command: Value = serde_json::from_str(&line)?;
        if let Some(events) = command.get("peers") {
            let events: Vec<Event> = serde_json::from_value(events.clone())?;
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_secs();
            registry
                .update("generated_fixture", &events, now)
                .map_err(|_| "peer registry")?;
            let cards: Vec<PeerCard> = registry.active(now);
            mesh.set_peers(cards)?;
        }
        println!(
            "{}",
            json!({"healthy":mesh.healthy(),"connected":mesh.connected_peers()})
        );
        std::io::stdout().flush()?;
    }
    drop(mesh);
    let _ = input.join();
    Ok(())
}
