# Rust and WASM API reference

Version 0.2.1. Source is authoritative; there is no published crates.io,
docs.rs or npm package. Authorised users can generate local Rust API pages
with `cargo doc --locked --all-features --no-deps`.

## Cargo features

| Feature | Behaviour |
|---|---|
| `runtime` | Native Mio sockets and OS randomness; by itself it does not enable TURN |
| `turn` | STUN/TURN wire codec, credential helpers and nonce logic |
| `direct-index` | Native runtime and TURN, with generation-tagged readiness slots |
| `connected-udp` | `direct-index` plus concrete-IPv4 connected-socket optimisation |
| `tls` | Native runtime, TURN and optional rustls TLS client listener |
| `wasm` | TURN helpers and wasm-bindgen; the exported arena is WASM-only |

Defaults are `runtime`, `turn` and `connected-udp`. Use
`--no-default-features --features runtime,turn` for the portable native
path, `--no-default-features --features turn --lib` for codec/auth only,
or `--no-default-features --features wasm --lib` for a WASM module. The
WASM build must exclude the native defaults.

## Native configuration

Source: [src/turn.rs](../src/turn.rs).

`Config::local(secret: Vec<u8>) -> Config` sets these defaults:

| Field | Default and purpose |
|---|---|
| `listen` | `127.0.0.1:3478`, shared UDP/TCP listening address |
| `relay_ip` | `127.0.0.1`, local bind address of UDP peer sockets |
| `relay_port_range` | `None` for OS ephemeral ports, or `Some((first, last))` for an inclusive nonzero UDP relay range with no fallback |
| `advertised_ip` | `None`; optional NAT-visible relay IP of the same address family |
| `realm` | `spry-turn`, long-term authentication realm |
| `secret` | Caller supplied, at least 32 bytes |
| `allow_loopback_peers` | `false`; explicit loopback testing |
| `max_allocations` | `1024`, total logical allocation limit |
| `max_per_user` | `8`, per-username allocation limit |
| `max_connections` | `256`, TCP/TLS connections |
| `bytes_per_second` | `67108864`, aggregate byte rate per allocation across both directions |
| `tls` | `None`; with `tls`, an optional address and `Arc<rustls::ServerConfig>` |

`Server::bind(config)` validates configuration and binds listeners. Realm
must contain 1–128 bytes, relay bind IP must be concrete and numeric limits
must be positive. A configured relay range requires `1 <= first <= last`;
port exhaustion produces TURN 508 without widening the range. The CLI additionally restricts loopback-peer opt-in to a
loopback-only listener; embedding hosts must enforce the same policy.

| Method | Result |
|---|---|
| `Server::bind(config: Config)` | `io::Result<Server>` |
| `server.local_addr()` | `io::Result<SocketAddr>` |
| `server.poll_once(timeout: Duration)` | `io::Result<()>`; processes readiness and expiry work |
| `server.stats()` | Copy of `limits::Stats` aggregate counters |
| `server.allocation_count()` | Current number of allocations |
| `turn::unix_time()` | Current epoch seconds |

The library starts no threads. A host must keep polling and drop `Server`
when it wants to close listeners and allocations. `Stats` contains
`forwarded_packets`, `forwarded_bytes` and `dropped_packets`; these are
process-local counters, not a remote monitoring or billing API.

## Wire and authentication helpers

Sources: [src/wire.rs](../src/wire.rs), [src/auth.rs](../src/auth.rs).

- `wire::Message::parse(&[u8]) -> Option<Message<'_>>`: borrowed STUN parser,
  with `method`, `class` and transaction ID; attributes remain borrowed.
- `message.attr(type)`, `number(type)` and `address(type)`: read attributes.
- `message.verify(key) -> bool`: verify message integrity.
- `wire::Builder::new(method, class, transaction)`: construct a STUN packet;
  `attr`, `number`, `address`, then `finish(key)` produce owned bytes.
- `wire::channel(&[u8]) -> Option<(u16, &[u8])>`: borrowed ChannelData parser.
- `wire::frame_len(&[u8]) -> Option<usize>`: obtain the declared stream frame
  length, including channel padding. Fewer than four bytes return `None`;
  an invalid leading type returns `Some(0)`. The caller must wait for that
  many bytes and validate the complete packet separately.
- `auth::credential(secret, username) -> String`: TURN REST password.
- `auth::key(username, realm, password) -> [u8; 16]`: long-term integrity key.
- `auth::expires(username) -> Option<u64>`: parse the expiry prefix.
- `auth::Nonces`: issue and validate time-, IP- and realm-bound nonces;
  `new()` uses OS randomness when `runtime` is enabled.

Parsing and integrity verification do not themselves grant a peer
permission, allocate a relay or enforce the application's membership.
For normal server use, let `Server` own the TURN state machine.

## WASM build

```sh
rustup target add wasm32-unknown-unknown
cargo build --locked --release --target wasm32-unknown-unknown \
  --no-default-features --features wasm --lib
wasm-bindgen --target web --out-dir .local/wasm --out-name spry_turn \
  target/wasm32-unknown-unknown/release/spry_turn.wasm
node tests/wasm.mjs
```

Use wasm-bindgen CLI 0.2.129 to match the pinned crate. Install that
specific CLI version if needed; the server does not depend on the CLI at
runtime. The generated package contains `.wasm`, JavaScript and TypeScript
declarations. See [integration](integration.md#browser-wasm-packet-codec).

Source: [src/wasm.rs](../src/wasm.rs).

| JavaScript API | Meaning |
|---|---|
| `new PacketArena(capacity)` | Allocate 20–65,536 bytes once |
| `arena.ptr()` / `arena.capacity()` | Location and length for a borrowed `Uint8Array` |
| `arena.valid_stun(len)` | Validate a STUN packet in the arena |
| `arena.stun_method(len)` / `stun_class(len)` | Parsed value, or `-1` |
| `arena.verify_integrity(len, key)` | Verify an in-arena STUN packet |
| `arena.frame_channel(number, payloadLen)` | Write a ChannelData header; payload starts at offset 4 |
| `arena.channel_number(len)` / `channel_payload_len(len)` | Parsed value, or `-1` |
| `arena.free()` | Release the arena; invalidate all borrowed views |
| `rest_credential(secret, username)` | Trusted operator credential helper |

Channel numbers accepted by this initial codec are `0x4000`–`0x4fff`.
The caller owns networking, channel allocation and session authorisation.
Do not retain views across WASM memory growth or past `arena.free()`.
Credential helpers are not for placing a server secret into a public client.
