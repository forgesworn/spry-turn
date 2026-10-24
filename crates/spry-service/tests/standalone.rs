use base64::{Engine, engine::general_purpose::STANDARD};
use k256::schnorr::SigningKey;
use serde_json::json;
use spry_access::{hash, hex};
use std::{
    io::{Read, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    process::{Child, Command, Stdio},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

struct Service(Child);
impl Drop for Service {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn request(address: SocketAddr, method: &str, path: &str, auth: Option<&str>) -> String {
    let mut socket = TcpStream::connect_timeout(&address, Duration::from_secs(2)).unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    socket
        .set_write_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let authorization = auth.map_or(String::new(), |value| format!("Authorization: {value}\r\n"));
    write!(socket, "{method} {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nContent-Type: application/json\r\n{authorization}Content-Length: 2\r\n\r\n{{}}").unwrap();
    let mut bytes = Vec::new();
    socket.take(32_768).read_to_end(&mut bytes).unwrap();
    String::from_utf8(bytes).unwrap()
}

#[test]
fn standalone_host_uses_owner_signatures_without_an_archipelago_installation() {
    let signing = SigningKey::from_bytes(&[1; 32]).unwrap();
    let public = hex(&signing.verifying_key().to_bytes());
    let reserved = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = reserved.local_addr().unwrap();
    drop(reserved);
    let child = Command::new(env!("CARGO_BIN_EXE_spry-node"))
        .env_clear()
        .env("SPRY_PUBLIC_URL", "https://relay.example:3744")
        .env("SPRY_KITHMOOT_URL", "https://calls.example/j/")
        .env("SPRY_OWNER_KEYS", &public)
        .env(
            "SPRY_TURN_SECRET",
            "synthetic-test-secret-not-for-deployment",
        )
        .env("SPRY_HTTP_PORT", address.port().to_string())
        // A documentation address cannot start the relay or touch live sockets.
        .env("SPRY_RELAY_IP", "192.0.2.1")
        .env(
            "SPRY_STATE_FILE",
            "uncreated-standalone-fixture/pairings.json",
        )
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut service = Service(child);
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if TcpStream::connect_timeout(&address, Duration::from_millis(50)).is_ok() {
            break;
        }
        assert!(service.0.try_wait().unwrap().is_none(), "service exited");
        assert!(Instant::now() < deadline, "service did not listen");
        std::thread::sleep(Duration::from_millis(10));
    }
    let index = request(address, "GET", "/", None);
    assert!(index.starts_with("HTTP/1.1 200"));
    assert!(index.contains("YOUR SPRY RELAY"));
    assert!(!index.contains("nostr-provider.js"));
    assert!(!index.contains("ARCHIPELAGO"));
    let status = request(address, "GET", "/v1/status", None);
    assert!(status.contains("\"ready\":false"));
    assert!(request(address, "GET", "/nostr-provider.js", None).starts_with("HTTP/1.1 404"));
    assert!(request(address, "POST", "/v1/pairings/list", None).starts_with("HTTP/1.1 401"));

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let mut nonce = [0_u8; 32];
    getrandom::fill(&mut nonce).unwrap();
    let tags = json!([
        ["u", "https://relay.example:3744/v1/pairings/list"],
        ["method", "POST"],
        ["payload", &hash(b"{}")],
        [
            "nonce",
            &base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(nonce)
        ],
    ]);
    let id = hash(serde_json::to_vec(&json!([0, public, now, 27235, tags, ""])).unwrap());
    let digest: Vec<u8> = id
        .as_bytes()
        .chunks_exact(2)
        .map(|bytes| u8::from_str_radix(std::str::from_utf8(bytes).unwrap(), 16).unwrap())
        .collect();
    let signature = hex(&signing.sign_raw(&digest, &[0; 32]).unwrap().to_bytes());
    let auth = format!("Nostr {}", STANDARD.encode(serde_json::to_vec(&json!({
        "kind":27235,"created_at":now,"tags":tags,"content":"", "pubkey":public,"id":id,"sig":signature
    })).unwrap()));
    let allowed = request(address, "POST", "/v1/pairings/list", Some(&auth));
    assert!(allowed.starts_with("HTTP/1.1 200"), "{allowed}");
    assert!(allowed.contains("\"pairings\":[]"));
    assert!(request(address, "POST", "/v1/pairings/list", Some(&auth)).starts_with("HTTP/1.1 401"));
}
