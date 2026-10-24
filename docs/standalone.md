# Standalone Spry and reusable libraries

Spry is a standalone ForgeSworn product. Its libraries and service are usable
without Archipelago. Other ForgeSworn products consume the same libraries;
Archipelago packages that product for its node owners.

| Component | Responsibility |
|---|---|
| `spry-turn` | Bounded packet forwarding, TURN authentication and protocol codecs; native library and standalone relay executable |
| `spry-access` | Owner-authorised pairing, scoped grants, short-lived credentials and private state; no network runtime |
| `spry-link` | Signed encrypted control messages, peer cards, packet frames and expiring scoped routes; no sockets or runtime |
| `spry-service` | Optional HTTP, Nostr and OS-ULA host adapters and standalone `spry-node` executable; supplied UI assets and explicit owner configuration |
| Archipelago package | Installation, node-supplied owner identities, host certificates, permissions and an optional dashboard signing provider |
| Calling application | Pairing consent, room membership, media keys, credential renewal and call controls |

The relay never imports the access service or Archipelago. The service uses
the access library and supervises the separate native relay executable.
Hosts can also embed the relay directly. Shared library configuration has no
hard-coded KithMoot origin allowlist; each host supplies its intended calling
application and any extra permitted origins. The standalone UI uses the
owner's existing NIP-07 signing extension. Archipelago can supply its own
signing-provider assets through the host adapter.

Build both standalone executables:

```sh
cargo build --locked --release --workspace --features tls
```

For the pairing service, supply `SPRY_PUBLIC_URL` (its HTTPS origin),
`SPRY_OWNER_KEYS` (comma-separated owner public keys), `SPRY_TURN_SECRET`
(at least 32 bytes) and `SPRY_RELAY_IP` (the relay's reachable IPv4 address).
Set `SPRY_STATE_FILE` to a private persistent file and, if needed,
`SPRY_KITHMOOT_URL` to the intended calling application's HTTPS URL.
`SPRY_ALLOWED_ORIGINS` explicitly adds HTTPS origins for other clients.

`spry-node` listens on loopback HTTP port 3744 behind the operator's HTTPS
reverse proxy. It finds `spry-turn` beside itself; `SPRY_RELAY_BINARY`
overrides that location. Standard TURN listeners and the bounded peer range
are described in the [operator guide](operations.md). Optional certificate
files for the relay reside under `/data/tls`; an external host adapter can
instead terminate TURN TLS. Setting `SPRY_TLS_GATE=true` advertises that
host's configured TLS transport and does not start or configure a TLS proxy.

No Archipelago daemon, node identity store, dashboard, container runtime or
FIPS installation is required for this standalone path. A reachable relay
and valid HTTPS still require operator configuration. The optional private-node profile below connects paired nodes over an existing
OS mesh route. It does not create that route or configure a router.

Networking integrations belong behind optional adapters. An Archipelago
adapter uses its existing mesh and host facilities; reusable improvements to
those facilities can be proposed upstream. Other hosts can supply a different
transport without importing Archipelago into Spry's forwarding or access
libraries.

Within Archipelago, the app manager owns package installation and lifecycle,
the existing identity/signing layer approves owner operations, the app gate
owns its HTTPS integration, and the networking layer owns mesh connectivity.
Those are the integration points for the relevant library or thin adapter.
Each library retains its own narrow purpose and independent build; installing
the package does not transfer those host responsibilities into Spry.

Git dependencies use a reviewed full commit SHA; see the
[access library](../crates/spry-access/README.md) and
[native embedding guide](integration.md#embed-the-native-rust-server).
No new package registry publication is implied by these libraries.

## Private-node profile

For a Linux host with an existing IPv6 ULA route to the other nodes, set
`SPRY_PEER_INTERFACE` to that interface name, or set `SPRY_PEER_BIND` to its
explicit `[ULA]:3745` address. Keep `SPRY_RELAY_IP` as the concrete local IPv4
client listener, and set `SPRY_CLIENT_HOST` if clients use a different local
hostname. `SPRY_OWNER_URL` is the HTTPS owner UI origin. The host admits TCP
3745 on its private mesh interface; Spry requires no extra capabilities.

The service embeds the native forwarding library in this profile. Its
virtual relay addresses belong to 127.64.0.0/10, with UDP ports 49160–49191.
They are carried across authenticated peer links and must never be exposed
as arbitrary loopback proxies. Each node only accepts signed, unexpired peer
cards registered by one of its paired apps. Revoking that pairing withdraws
its routes. The core rejects host services, LAN addresses and arbitrary
Internet destinations in this profile.

Choose **Pair with KithMoot**. The owner signing provider supplies the person's
existing read/write Nostr relays; standalone hosts may explicitly configure
`SPRY_CONTROL_RELAYS` as a JSON array instead. Spry verifies connectivity before
issuing the pairing link and persists that selection for restarts. No extra
relay account, default directory or publisher-operated call server is added.
Control messages contain opaque access scopes and signed peer cards, without
room secrets or media keys. Media packets travel between nodes over their OS
route; Nostr carries control and the calling application's own signalling.

Only the explicitly paired node may return local client TURN addresses.
Foreign room adverts are verified offline and registered with that node;
clients must not contact foreign private endpoints or automatically open the
relays advertised by them. Everyone in a private-only call needs access to
their own paired node. A public TURN host remains an alternative for guests
without a reachable private node.

`SPRY_SOCKS_PROXY` optionally selects a SOCKS5 proxy for outbound control,
including remote DNS. A configured proxy has no direct-connect fallback.
`SPRY_CONTROL_CA_FILE` optionally adds a bounded PEM CA bundle to normal TLS
trust for explicitly selected control relays. Certificate and hostname
validation remain enabled. `SPRY_LOCAL_TEST=true` is for generated fixtures;
never enable it in a deployed node.

Run the independent packet test with `python3 tests/mesh.py --binary <Linux
mesh-node example> --output .local/mesh.json`. `tests/home-flow.mjs` additionally
drives actual standalone pairing screens and a built KithMoot PWA across
separate Linux containers, using generated audio/video and relay-only ICE.
Its receipt records the precise network and browser limits. Neither local
test substitutes for physical phones, the installed Archipelago bundle or
independent home broadband/NAT acceptance.

The [three-node browser receipt](evidence/spry-private-nodes-browser-20261024.json)
records actual pairing, relay-only 1:1/group media, reload and fresh audio/video
progress after 330 seconds. The [packet receipt](evidence/spry-private-nodes-packets-20261024.json)
separately records UDP/TCP forwarding and withdrawal on an isolated network
with no external connectivity. Both name their exact fixture limits.

A mesh whose routing needs an identity lookup can supply `SPRY_PEER_NAME`,
`SPRY_PEER_RESOLVER` (a loopback DNS socket) and `SPRY_PEER_ZONE`. The optional
adapter queries only that zone, binds the DNS response to its question and
transaction, and requires the returned AAAA address to equal the signed ULA.
It never substitutes an arbitrary DNS destination. Archipelago supplies the
seeded public mesh name and its existing FIPS resolver; Spry imports no mesh
SDK. The [FIPS/NAT packet receipt](evidence/spry-fips-two-nats-20261024.json)
checks this adapter with two simulated home NATs, an isolated WAN and a
separate fixture mesh anchor. Spry containers retain no extra capabilities;
TUN and forwarding permissions belong to the fixture's host/network layer.

Reproduce that packet check with Docker and a Linux `mesh-node` example
matching the Docker engine's CPU architecture. Fetch the released FIPS
0.4.1 archive and verify it before extraction:

```sh
mkdir -p .local/fips-fixture
gh release download v0.4.1 --repo jmcorgan/fips \
  --pattern checksums-linux.txt --pattern fips-0.4.1-linux-aarch64.tar.gz \
  --dir .local/fips-fixture
(cd .local/fips-fixture && \
  grep '  fips-0.4.1-linux-aarch64.tar.gz$' checksums-linux.txt | sha256sum -c - && \
  tar -xzf fips-0.4.1-linux-aarch64.tar.gz --strip-components=1)
docker build -f tests/fixtures/fips/Dockerfile -t spry-fips-fixture:0.4.1 tests/fixtures/fips
cargo build --locked --target aarch64-unknown-linux-gnu \
  --example mesh-node -p spry-service
python3 tests/fips-mesh.py \
  --binary target/aarch64-unknown-linux-gnu/debug/examples/mesh-node \
  --fips-dir .local/fips-fixture --output .local/fips-two-nats.json
```

On x86-64 Linux use the `linux-x86_64` archive and
`x86_64-unknown-linux-gnu` Rust target instead. Cross-compiling requires a
Linux linker and sysroot (for example an installed `cargo-zigbuild`); on
macOS replace `cargo build` above with `cargo zigbuild`. Keep the existing
worktree's target directory. The fixture removes its containers, networks
and binary snapshot on exit. Remove downloaded binaries, archives and the
task-owned fixture image after retaining the required receipt privately.
