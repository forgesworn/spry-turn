# spry-turn

A lightweight standalone **STUN/TURN server in Rust**, an embeddable native
library and a portable **WebAssembly packet codec**. UDP and TCP clients,
optional TLS, coturn-compatible shared-secret credentials, bounded resources
and no media stack. MIT licensed; the repository and initial release are private.

[Documentation](docs/README.md) · [Quick start](docs/getting-started.md) ·
[WebRTC and native integration](docs/integration.md) ·
[Coturn compatibility](docs/coturn-compatibility.md) ·
[API](docs/api.md) · [Support development](SUPPORT.md#donations) ·
[LLM index](llms.txt)

In the measured native Apple M4 Max UDP loopback comparison, spry-turn
delivered **17–22% more packets/s** than the tested coturn configuration,
with **19–23% less server CPU time** and **78–82% less process RSS**.
The recorded benchmark predates bounded relay ports. The optimisation
uses an extra UDP socket per allocation; RSS excludes kernel socket buffers.
These results do not establish WAN, Linux or TLS
performance. See [the method, raw results and limitations](docs/benchmarks.md).

The first target is a server running independently on a normal computer.
Later, an Archy owner can install it and configure KithMoot to use their
chosen TURN address and credentials. The software publisher operates no
relay, credential service, discovery directory or calling entitlement.
There are no hosted defaults in the code.

## What works

- STUN Binding, authenticated TURN Allocate and Refresh, CreatePermission,
  ChannelBind, Send/Data indications and ChannelData.
- UDP relaying, with clients connecting over UDP or TCP. The `tls` feature
  adds TLS 1.2/1.3 client connections using rustls.
- Optional inclusive UDP peer-relay port range, with occupied-port skipping,
  authenticated 508 on exhaustion and no allocation outside the range.
- Coturn-compatible TURN REST credentials: expiry-prefixed usernames and
  a shared secret. Credential generation is an operator-run local command.
- IPv4 or IPv6 relay address family per configured instance. Native IPv6
  sockets and XOR address encoding are supported; dual allocations are not.
- Expiring allocations, IP permissions and channel bindings; bounded
  allocations, per-user allocations, connections, peers, stream buffers,
  control request rate and per-allocation bandwidth.
- Private, loopback, link-local and multicast targets blocked by default.
  Explicit loopback testing is restricted to a loopback-only listener.
- No media decoders, WebRTC stack, database, async runtime, admin website,
  analytics, access log, room membership or application admission service.

The UDP ChannelData path borrows incoming payloads and reserves header space
in its receive buffer, avoiding a payload copy on the return path. One
non-blocking Mio event loop owns sockets and allocation state; no per-packet
tasks or worker queues. Generation-tagged slots route readiness events
without hashing internal tokens and reject stale events after reuse.
TCP/TLS uses bounded output buffers.
The library forbids unsafe Rust in its own code; dependencies may use it.

Concrete IPv4 listeners use a connected client-facing UDP socket per
allocation to retain the client's fixed five-tuple in the kernel. This
improves the measured send/receive path and costs one additional UDP socket
per client. Wildcard/IPv6 listeners and unavailable fast-path sockets retain
standard forwarding. The portable build is available with
`--no-default-features --features runtime,turn`. RSS measurements exclude
kernel socket memory; see the comparison's socket counts and limitations.

This is an initial implementation, not full coturn parity or a production
qualification. [Compatibility and remaining work](GOALS.md) are explicit.

## Run locally

Rust 1.85 or later; stable Rust 1.94 is tested. Build output uses `target/`.

```sh
cargo build --release
export SPRY_TURN_SECRET="$(openssl rand -hex 32)"
./target/release/spry-turn serve
```

The default UDP/TCP listener is `127.0.0.1:3478`. Generate a short-lived
credential locally using the same environment:

```sh
./target/release/spry-turn credential --ttl 3600 --label client
```

For larger workloads, size the process file-descriptor limit for listeners,
two sockets per optimised UDP allocation and any TCP/TLS connections.
`--max-allocations` limits logical allocations; it cannot raise an OS limit.
The comparison runner sets 4,096 for its own processes only.

Use an opaque transport label. Do not put room IDs, personal identities or
application membership in usernames. The credential output is a secret;
do not commit it or put it in public logs. The shared secret never belongs
in a browser, join URL or client build. Operators decide how to give their
own users credentials; no remotely callable credential issuer is included.

Configure a standard ICE client with `turn:HOST:3478?transport=udp` or
`turn:HOST:3478?transport=tcp`, the generated username and credential. A
website uses its browser's existing WebRTC support; it does not host TURN.

To listen on a chosen interface, supply `--listen IP:PORT` and, if needed,
`--relay-ip IP`. Wildcard listeners require an explicit concrete relay IP.
`--public-ip IP` advertises an operator-configured NAT address. The
operator must provide actual reachability and firewall rules; installing
the server cannot make an inaccessible home connection a public relay.

Use `--relay-ports 49160:49191` to bound peer UDP allocations for an
operator-controlled firewall/NAT configuration. Without it, allocations
retain OS-assigned ephemeral ports. See [the operator guide](docs/operations.md)
for reachability, resource budgets and port-preserving NAT requirements.

TLS is optional at build time:

```sh
cargo build --release --features tls
./target/release/spry-turn serve --tls-listen 127.0.0.1:5349 \
  --tls-cert certificate.pem --tls-key private-key.pem
```

Use a certificate trusted by the intended clients. Local tests generate
temporary certificates and test trust separately from public deployment.
The process has no certificate renewal or TLS file watcher yet.

## Embed

`spry_turn::turn::Server::bind(Config)` creates a server;
`poll_once(Duration)` advances its event loop. The host controls its lifetime
and configuration. No threads are started by the library. Build with
`--no-default-features --features turn` for the borrowed wire codec and
credential helpers without the socket runtime. Swift/Kotlin bindings and
physical phone acceptance are later work.

## WebAssembly

The portable packet codec and credential helpers also build to WASM,
without Mio, socket2, TLS or an OS random-number dependency:

```sh
cargo build --release --target wasm32-unknown-unknown \
  --no-default-features --features wasm --lib
wasm-bindgen --target web --out-dir .local/wasm --out-name spry_turn \
  target/wasm32-unknown-unknown/release/spry_turn.wasm
node tests/wasm.mjs
```

Use wasm-bindgen CLI 0.2.129 to match the pinned bindings. `PacketArena`
provides a reusable region of linear memory that a host accesses through
`Uint8Array`. Channel framing/parsing reuses that region without per-packet
Rust allocations or whole-payload binding marshalling. Recreate the view
after memory growth and do not retain it after freeing the arena.

The initial module is about 56 kB. A real WASM execution test validates the
published STUN integrity vector and repeats a million framing/parsing
operations without growing linear memory. That is a protocol microbenchmark,
separate from server network throughput. Networking and allocation/session
I/O belong to the native server adapter; ordinary browser WASM cannot host
a standard raw-socket TURN server.

TURN forwards arbitrary datagrams; it has no WebRTC media semantics. A
future SRT/Sapflow client could use an appropriate transport adapter.
Unmodified SRT/RTMP applications do not automatically speak TURN. Sapflow
integration and transparent UDP forwarding are not implemented here.

## Verify

```sh
cargo fmt --all -- --check
cargo clippy --all-features --all-targets -- -D warnings
cargo test --all-features
cargo test --no-default-features --lib
cargo test --no-default-features --features turn --lib
cargo build --release --features tls
python3 tests/interop.py --tls
npm ci --ignore-scripts
npx playwright install chromium
python3 tests/browser.py --tls
```

The independent Python stdlib client checks real UDP/TCP/TLS sockets.
Chromium forces relay/relay candidates and verifies generated video decoded,
audio received and application data returned in both directions for all
three client transports. Browser tests use a generated test certificate and
explicit browser certificate bypass; the Python TLS test validates its
generated CA. This is not public-certificate or real-phone acceptance.

The [comparison runner](scripts/compare.py) uses the same socket-level load
generator against each server, alternating order. It reports delivered
packets, loss/corruption, round-trip latency, RSS and server CPU. All test
servers bind loopback and clean up their processes and generated secrets.

## Scope and legal position

The chosen role is publishing software, with independent owners operating
their own relay instances. The [transport position](docs/legal/transport-position.md)
records that architecture and the unresolved legal interpretations. A
private repository, MIT licence, encryption or use of TURN does not by
itself determine a future operator's Online Safety Act position.

MIT applies to our code. Dependency notices are in
[THIRD_PARTY_LICENSES.txt](THIRD_PARTY_LICENSES.txt); published RFC test data
is credited in [NOTICE](NOTICE). There is no package publication or hosted
service deployment in this repository.

## Documentation and discovery

Start with the [documentation index](docs/README.md), then choose the
[operator guide](docs/operations.md), [integration guide](docs/integration.md)
or [Rust/WASM API reference](docs/api.md). [Coturn compatibility](docs/coturn-compatibility.md)
maps supported features and migration gaps. [Verification](docs/verification.md),
[benchmarks](docs/benchmarks.md) and [the remaining work](GOALS.md) distinguish
implemented behaviour from production qualification.

AI tools can read [llms.txt](llms.txt) for a short canonical index or
[llms-full.txt](llms-full.txt) for generated documentation context. Both
are maintained from the same source documents and checked in CI. Private
repository access is required; these files do not make the project public
or guarantee search-engine or model indexing.

## Support development

spry-turn is part of [ForgeSworn](https://github.com/forgesworn), maintained
by TheCryptoDonkey. Donations support development, testing and documentation.

- [GitHub Sponsors](https://github.com/sponsors/TheCryptoDonkey)
- [Ko-fi](https://ko-fi.com/brays)
- [ForgeSworn on Geyser](https://geyser.fund/project/forgesworn)
- Lightning: `profusemeat89@walletofsatoshi.com`

See [support and donation details](SUPPORT.md), including Nostr zaps.
Donations are optional and do not purchase relay access or a service guarantee.
