# Rust and WASM API reference

Version 0.3.0. Source is authoritative; there is no published crates.io,
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
| `relay_port_mappings` | `None`; optional 1–1024 exact `RelayPortMapping` local/public UDP pairs, excluding range mode; see [mapped ports](mapped-ports.md) |
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

## Room-grant paths

Source: [crates/spry-access/src/lib.rs](../crates/spry-access/src/lib.rs).

The `spry-node` service and `spry:` control channel pass these `POST`
bodies to `Authority::handle` after the usual signed-request check, body
limit and per-source and per-key rate limits. Every refusal is
`{"error":"<message>"}` with the status shown.

| Path | Signer | Body | Success |
|---|---|---|---|
| `/v1/grants` | Paired app | `{"pairing","scope"}` | `{"v":1,"endpoint","token","expiresAt"}`; one grant per pairing and scope, renewed in place |
| `/v1/grants/remove` | Paired app | `{"pairing","grant"}` | `{"removed":true}`; drops the grant and its registered keys |
| `/v1/grants/devices` | The pairing that owns the grant | `{"v":1,"pairing","grant","add":[...],"remove":[...],"seal":true,"revision":N}` | `{"v":1,"sealed":bool,"enforced":bool,"devices":N}` |
| `/v1/grants/vouch` | A confirmed key on the grant | `{"v":1,"grant","add":[...]}` | `{"v":1,"added":N}` |
| `/v1/credentials` | Any key, or a registered key when enforced | `{"grant"}` | TURN `urls`, `username`, `credential`, `expiresAt` (at most 5 minutes) and `accessExpiresAt` |

`/v1/grants/devices` and `/v1/grants/vouch` refuse any field not shown and
any `v` other than 1 (400 "Invalid request."). Keys are distinct lowercase
64-hex x-only public keys that are valid curve points.

- `/v1/grants/devices`: at most 32 keys in each of `add` and `remove`, no key
  in both; `seal` optional; `revision` an integer up to 2^53 - 1 that must
  exceed the last one accepted for the grant in the past 90 seconds (else
  409 "Out of date. Try again."). A signer that does not hold the named
  pairing, or a grant of another pairing, gets 403 "Approval required.";
  an unknown or expired grant gets 403 "Call access has expired.". An added
  key becomes a confirmed entry with a 30-day lease, replacing a vouched
  entry for it. A removed key loses its entry and its device slot at once.
  `seal: true` seals the grant for good; `false` never unseals. Changes apply
  all or nothing: a request refused for capacity also drops its removals
  and its seal. Clients should therefore send removals, and a seal, in a
  request of their own rather than with adds.
- `/v1/grants/vouch`: one to four keys. The signer must hold a confirmed,
  unexpired entry, else 403 "Call access has expired.". A key already listed
  is left as it is; any other gains a vouched entry that lapses 24 hours
  later, is never renewed by use and cannot vouch. Every named key counts
  against the caps, listed or not, and `added` is the number of keys named,
  so the answer does not reveal which keys were listed. At most 8 vouched
  entries per grant at once, 8 vouches per signer per grant per 24 hours
  and 64 signers tracked per grant; these and the grant, pairing and node
  limits below all refuse with 429 "Spry is busy. Try again shortly.". A
  vouch never evicts.
- `/v1/credentials`: an enforced grant refuses a key without an unexpired
  entry with 403 "Call access has expired.", the same refusal as an expired
  grant, before counting it against the 32 concurrent device slots. A
  confirmed entry's lease renews to 30 days on use once fewer than 29 days
  remain.

A grant is enforced when `Config::seal` is `Required`, or when it is `Auto`
(the default) and the grant is sealed. `Off` stores registrations and
vouches but never enforces them. `spry-node` reads this from
`SPRY_ROOM_SEAL` (`auto`, `required` or `off`) once at startup.

A grant holds at most 64 registered keys, the grants of one pairing at most
512 together (half the node) and the node at most 1024. Adding to a full
grant evicts the confirmed entry with no live device slot that was used
least recently since start; with none to evict it refuses with 429 "This
call has reached its device limit.". Over the pairing's share or the node
limit it refuses with 429 "Spry is already helping too many calls.". Registered keys persist
in the state file as `"sealed":true` and `"members":[["<key>",<lease end>,
<vouched>]]` on each grant; the file stays version 1 and within its 131072
byte limit, and an older binary loads it with every grant unsealed.

## Supervised pairing and standard cards

`Authority::trust_pairing(key, now)` makes `key` the node's only pairing,
for a host that runs `spry-node supervised` and holds that key. Call it after
`restore`. The id is derived from the node secret and the key, so it is the
same after a restart; any other pairing, its grants and pending claim codes
are removed in the same saved write. A key that is not a lowercase x-only
curve point gets 400 "Invalid pairing key.".

`spry_link::standard::StandardCard` signs and verifies the kind 24183
`spry-standard-v1` card a supervised node adds as `node` to `/v1/grants` and
`/v1/credentials` answers. It has no address field. `PeerCard::verify`
refuses it and `StandardCard::verify` refuses a peer card. See
[supervised standard mode](supervised-mode.md#the-spry-standard-v1-node-card).

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
