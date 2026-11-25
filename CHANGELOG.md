# Changelog

## 0.5.0 (25 November 2026)

Public MIT prerelease through the existing native executable, Android
library and container image channels. It tightens the relay's limits on
clients that have not yet authenticated: control requests are budgeted by
source, and one source can hold only half of the TCP and TLS connection
slots without an allocation. The standalone HTTP API can now sit behind a
reverse proxy on another container or host. Operators should update, and
should read the notes on shared addresses below if UDP reaches the relay
through a forwarder. The library's relay metrics gain two fields. Both
hosted qualification runs of the request-budget change
[failed the sparse CPU guard](docs/tcp-pr75-results-2026-11-25.md) and the
owner accepted it with that disclosed. This release does not deploy a
hosted relay.

- Control requests now draw on separate budgets by source. TCP and TLS
  connections, loopback, and UDP requests carrying a nonce the relay issued
  to that address share 2,000 a second (burst 6,000). Each address has a
  soft allowance of 20 a second (burst 40) within it: addresses within it
  keep priority when the budget runs low, and an address over it may still
  use what the budget holds above a 2,000 reserve. Other UDP
  requests, including a client's first, share 2,000 a second (burst 2,000),
  with each address or IPv6 /64 held to 5 a second (burst 20). Clients with
  an allocation keep their own budget of 10 a second. Per-address state is
  two fixed tables allocated at startup. All new UDP clients behind one
  address, such as a UDP proxy or a large shared NAT, share that address's
  allowance for requests without a nonce. Refusals are counted as
  `unverified_request_refusals` and `verified_request_refusals` in the
  library's relay metrics; they are not added to the HTTP status.
- Relay nonces are now 32 characters rather than 38, so the challenge to a
  request without credentials is 100 bytes rather than 108. Clients treat
  nonces as opaque. Nonces issued before an upgrade are no longer accepted,
  as after any restart.
- When asked for any free port, the relay now alternates which of UDP and
  TCP takes the system's offer. Windows offers ports in sequence and
  reserves them in blocks per protocol, so repeating the same order could
  be refused on every attempt. A configured port is still tried once.
- Let the standalone HTTP API be reached from a reverse proxy on another
  container or host. Setting `SPRY_HTTP_BIND` beyond loopback now needs
  `SPRY_HTTP_TRUSTED_PROXIES`, a list of proxy addresses and CIDR ranges;
  startup is refused without it, and for `0.0.0.0/0`, `::/0` and other
  very wide ranges. Connections from other addresses are closed, and only a
  listed proxy's right-most `X-Forwarded-For` entry keys the rate limiter.
  With neither variable set, the service stays on loopback as before. The
  image still does not expose port 3744.
- Unauthenticated TCP and TLS connections from one source are now limited
  to half of `--max-connections` (rounded down, at least one). A connection
  stops counting once it holds an allocation and counts again if that
  allocation ends while the stream stays open. IPv6 sources are grouped by
  /64 and IPv4-mapped addresses count as IPv4. Further connections from a
  source at its limit are refused and counted in `refusedStreams`, as at the
  total limit. This is a cap, not a complete safeguard: the total limit still
  applies, and several sources together can still fill it.

## 0.4.5 (24 November 2026)

Public MIT prerelease through the existing native executable, Android
library and container image channels. It keeps the standalone HTTP API
answering owner and paired keys when its per-caller table is full. The
relay itself is unchanged from 0.4.4. Operators who run the standalone HTTP
API should update. This release does not deploy a hosted relay.

- When the HTTP API's per-caller table is full, a request that claims an
  owner's or paired app's key still goes on to have its signature checked,
  within a total cap, so those keys keep access however many other callers
  arrive. Unsigned and unknown callers are refused as before.
- Document that the container's HTTP API listens on loopback only: a
  published port does not reach it, and the reverse proxy must share the
  container's network namespace or the container must use host networking.
  The image no longer lists port 3744 as exposed.
- Let the fuzz wrapper raise the fuzzer's memory limit for long campaigns.

## 0.4.4 (24 November 2026)

Public MIT prerelease through the existing native executable, Android
library and container image channels. It tightens the IPv6 peer policy and
makes control-request limits fairer to clients that already hold an
allocation. The payload path is the 0.4.2 one. Operators of an IPv6
instance should update. This release does not deploy a hosted relay.

- Restrict IPv6 peers to global unicast addresses. This refuses the ranges
  that embed or translate to IPv4 (IPv4-compatible, NAT64, 6to4, Teredo),
  the site-local, discard and RFC 9637 documentation ranges, and anything
  outside `2000::/3`. IPv4 instances are unaffected.
- Give each client with an allocation its own small control-request budget,
  drawn before the budget every source shares, so its refreshes and
  permissions do not depend on what other sources send.
- Document the control-request and connection limits in
  [operations](docs/operations.md).
- The two hosted qualification runs of the change above **failed** guards:
  the sparse TCP CPU guard in both, and a memory guard on one pair of the
  512-client profile against `main`. Loaded throughput and CPU were flat
  against `main`. The owner accepted the change with both results
  disclosed; see [the results](docs/tcp-pr63-results-2026-11-24.md).

## 0.4.3 (24 November 2026)

Public MIT prerelease through the existing native executable, Android
library and container image channels. It carries the standalone container,
owner statistics, shared-proxy and pairing changes made since 0.4.2, with
supply-chain and test hardening. The forwarding path is the 0.4.2 one, so
the performance trade-off disclosed for 0.4.2 still applies. This release
does not deploy a hosted relay.

- Add standalone container packaging: a non-root image holding `spry-node`
  and `spry-turn`, with the relay secret readable from a mounted secret
  file. See [the container image](docs/standalone.md#container-image).
- Publish the image's `latest` and version tags only from a `v*` release
  tag that matches `Cargo.toml`. Commits to `main` publish a moving `edge`
  tag and an immutable commit tag instead of `latest`. Before this
  release `latest` was pushed from every commit to `main`; this tag is the
  first to set it from a release.
- Add `SPRY_TLS_ADVERTISE_DIRECT=false` for a shared SNI proxy, so
  credentials omit the direct `turns:HOST:PORT` URL whose certificate would
  not match. The default keeps the dedicated-host URLs.
- Add signed-owner relay statistics and grant administration
  (`/v1/owner/stats`, `/v1/owner/grants/list`, `/v1/owner/grants/remove`) in
  the private-node profile.
- Report `paired` on `GET /v1/status`; the owner page confirms a successful
  KithMoot pairing and clears the one-use link.
- Refresh saved control relays when the owner approves, and log control
  relay connection outcomes.
- Update `url` to 2.5.9 for RUSTSEC-2026-0592 (stack overflow in
  `Url::origin()` on nested `blob:` URLs). Spry calls it only on operator
  configuration. Replace the unmaintained `rustls-pemfile`
  (RUSTSEC-2025-0134) with the PEM reader already in `rustls`; a TLS key
  file without a private key is still refused.
- Check every lockfile against the RustSec advisory database in CI and
  weekly. Pin all workflow actions by commit and the container base images
  by digest.
- Remove `curl` from the container image: nothing in the image uses it and
  the service has no HTTP health endpoint to probe. Propose action and base
  image pin updates weekly through Dependabot.
- Attest build provenance for the release artefacts and the container
  image with GitHub artefact attestations. This is the first release built
  with that step; releases up to 0.4.2 carry checksums only.
- Fuzz the port-mapping gateway parsers and the Nostr event, advert, card
  and pairing-link parsers alongside the existing wire target.
- Build on Rust 1.85 and run the Rust suite on Windows in CI. Run CI once
  per pull-request commit rather than twice.
- Fix a race in the `hot_stream_yields_to_other_clients_and_expiry_sweeps`
  unit test, which could drain its own backlog while accepting connections
  and then fail on a loaded machine. The relay is unchanged.
- Document that a Windows host must keep `SystemRoot` when it starts the
  node with a cleared environment; without it the service exits at start-up.
- When the relay is asked for an ephemeral listener (port 0), try a few
  offered ports if the matching TCP port is taken or, on Windows, excluded.
  A configured port is still bound once and a clash still fails.
- Add an end-to-end IPv6 unit test: a native IPv6 instance refuses the
  default IPv4 family with 440, allocates an IPv6 relayed address and
  forwards data both ways over loopback sockets. Field IPv6 acceptance on a
  real network remains open.
- A manual run of the release workflow now rehearses the whole publish path
  (artefacts, `SHA256SUMS`, manifest and provenance attestation) and stops
  before creating a release. One rehearsal passed before this tag and its
  attestation verified with `gh attestation verify`.
- Record a further hosted TCP qualification of `main`, which passed every
  guard including the sparse CPU guard 0.4.2 failed. It is one shared-host
  run and leaves the 0.4.2 decision and the bare-metal item unchanged. See
  [the results](docs/tcp-main-cd9d027-results-2026-11-24.md).
- Fix and lint the TLS-only feature set's test build in CI.
- Move the relay's unit tests from `src/turn.rs` to
  `src/turn/policy_tests.rs`; no behaviour change.

## 0.4.2 (11 November 2026)

Public MIT prerelease through the existing native executable and Android
library release channel. This release includes the changes since 0.4.1;
it does not deploy a hosted relay or change Archipelago screens.

- Batch plain TCP return traffic in groups of up to 16 frames or 16 KiB,
  and reuse empty output buffers. Partial writes retain their own pending
  buffer, and failed batch flushes account for each dropped frame once.
  Send the first eligible return immediately; batching starts only after a
  second return in the same dispatch, without a timer or look-ahead syscall.
  Large first frames still borrow empty storage when needed.
- Publish with an explicitly accepted performance trade-off. In the final
  pinned Linux loopback qualification, with 1,200-byte packets and window 8,
  median paired throughput rose 53.61% with 128 clients and 35.30% with 512
  clients; server CPU per verified forward fell 34.76% and 25.83%.
  The campaign **failed** its sparse TCP CPU guard: two pairs exceeded the
  0.2-percentage-point limit, with a worst increase of 0.334 points of one
  core. An earlier final-source campaign failed the same guard. Host,
  useful-work, latency, loaded/control and memory guards passed in the final
  campaign. The owner explicitly accepted this disclosed trade-off for the
  prerelease; neither failed result was relabelled or rerun to pass.
  These are measured loopback workloads, not WAN capacity or loaded-latency
  guarantees. See the [release decision](docs/release-v0.4.2-acceptance-2026-11-11.md)
  and [complete final results](docs/tcp-v0.4.2-3a843bb-results-2026-11-11.md).
- Add the opt-in keeper-controlled node profile: signed grant/device
  expiry, live credential revocation and a renewable 15-second desk lease
  control admission and existing allocations. A lost lease fails closed;
  restarting starts without issued credentials or a lease. Existing
  standalone and supervised profiles retain their behaviour when the
  profile is absent. See the [operator contract](docs/standalone.md#keeper-controlled-node-profile).
- Expose bounded aggregate node status and allocation/forwarded-byte
  metrics without room identifiers, addresses or credentials. Add an
  optional aggregate payload budget and explicit TLS advertisement and
  certificate settings; these settings do not configure a public endpoint.
- Bound private-node allocation leases, reclaim expired capacity before
  new allocations, and allow explicit bounded group-call budgets with
  connection and multihomed renewal headroom. Preserve the per-allocation
  limits and admission checks.
- Include Windows dependency licence texts in the packaged notices and
  collect the inventory for every existing native and Android release
  target, including dependency licence files with lowercase names.
- Close a deallocated UDP allocation's connected socket before sending its
  zero-lifetime Refresh acknowledgement. Previously an immediate next
  request could reach that socket just before teardown and be lost. The
  response keeps its authenticated transaction and client-facing endpoint;
  TCP and TLS connections remain open for subsequent requests.

## 0.4.1 (30 October 2026)

Public MIT prerelease, built by the release workflow like 0.4.0, for
KithMoot's built-in call relay behind home routers without NAT loopback.

- Two allocations on one relay now reach each other by their advertised
  addresses behind a router without NAT loopback. Before, a packet for the
  relay's own public address went out to the router, which dropped it, so a
  host's own device could not use its relay to reach a guest using the same
  relay. Such packets now go straight to the other allocation's local socket
  and arrive shown as from the sender's advertised address. Peer policy is
  unchanged: private addresses are still refused.

## 0.4.0 — 30 October 2026

Public MIT prerelease, the first built by the release workflow: both
executables for macOS arm64, Windows x64 (unsigned) and Linux x64 and arm64,
and the Android library with its C ABI and JNI shim. Supervised mode, port
mapping and in-process embedding are what KithMoot's built-in call relay
runs on.

- Supervised mode checks every router mapping once a minute between
  renewals and puts back any the router dropped, reporting
  `{"v":1,"event":"portmap","state":"restored","restored":N}`. A real home
  router dropped half of a node's UPnP mappings, the UDP listener among them,
  within 12 minutes of a 3600 s lease, and the node only renewed at half the
  lease, so the relay was unreachable for up to 20 minutes without a word.
  UPnP is asked with `GetSpecificPortMappingEntry`; PCP and NAT-PMP have no
  query, so their mappings are renewed every minute instead. New
  `PortMapper::present` in `spry-portmap`.
- Run supervised mode inside a host app's own process.
  `spry_service::embedded::start` takes the same options as
  `spry-node supervised` (without `--exit-on-stdin-close`, which is refused
  there) and the same five settings as name and value pairs; it never reads
  the process environment, installs no signal handler and never ends the
  process. Lines go to the host's sink and end with a new
  `{"v":1,"event":"stopped","code":N}` line carrying the exit code and any
  refusal. `Node::stop` replaces closing stdin: the relay stops and the
  node's own router mappings are removed. The child process is unchanged.
- Add `crates/spry-ffi`, `libspry_relay`: a hand-written C ABI
  (`include/spry_relay.h`: start, poll lines into the caller's buffer, stop,
  exit code, free) with every pointer borrowed for the call and every export
  behind `catch_unwind`, and, with the `jni` feature, a JNI shim for the
  Kotlin class `dev.forgesworn.spry.SpryRelayNative`, written against the JNI
  function table with no binding crate. Android keep rules ship with it. A
  new `release-ffi` profile unwinds on panic so the guards hold in release
  builds; the executables still abort. This crate is the only place `unsafe`
  is allowed, in its two ABI modules. See `docs/embedding.md`.
- Add `scripts/build-android.py`, which builds the library for arm64-v8a and
  x86_64 (API 33) with the NDK's clang through cargo's own target variables
  (no `cargo-ndk`), links with 16 KB pages and checks machine, alignment,
  exports and needed libraries, and `scripts/jni-smoke.py`, which drives
  every JNI entry point from a JVM. A test-only `panic-probe` feature proves
  that a panic in the `release-ffi` library returns an error code.
- Add a release workflow. Every pull request builds both executables
  natively for macOS arm64, Windows x64, Linux x64 and Linux arm64, runs them
  and the C ABI tests on each, and builds and checks the Android library. A
  `v*` tag matching `Cargo.toml` also writes `SHA256SUMS` and
  `release-manifest.json` over every asset, adds the exact source archive and
  creates a draft prerelease for a maintainer to publish. The Windows
  executables are unsigned and there is no macOS Intel build.

- Refuse a control relay whose host name ends in a dot (`wss://localhost./`,
  `wss://relay.local./`) in `ControlEndpoint::new`. A trailing dot named the
  same host but hid its last label from the local-name check, so it slipped
  past the refusal of `local`, `localhost`, `internal`, `invalid` and `test`
  names. This matches the KithMoot web client.
- Add supervised standard mode, `spry-node supervised`, for a host app that
  runs Spry as its child process for its own rooms. It opens no HTTP
  listener and answers only the room-grant control paths (`/v1/grants`,
  `/v1/grants/devices`, `/v1/grants/vouch`, `/v1/credentials`) over the
  `spry:` Nostr control channel, on one to four supervisor-named relays;
  every other path gets 404. The supervisor's signing key is trusted as the
  only pairing (stable id across restarts; other pairings and their grants
  are removed), every grant is sealed (`SPRY_ROOM_SEAL` must be unset or
  `required`), and public mode, adverts, claim codes and the private mesh
  are absent. The TURN relay runs in the same process with an explicit bind
  address, public IPv4, listener port, separate public UDP and TCP listener
  ports and 1 to 64 `--relay-port-map` pairs; home caps default to 8
  allocations, 2 per user, 16 TCP connections and 125000 bytes/s per
  allocation, raisable to the standard maximums. `--exit-on-stdin-close` is
  required. Unknown options and any other `SPRY_` variable refuse startup.
  Without the `supervised` argument `spry-node` is unchanged.
- Wire router port opening into supervised mode. `spry-node supervised
  --map-ports` replaces `--public-ip`, `--public-udp-port`,
  `--public-tcp-port` and `--relay-port-map` (now refused alongside it) with
  what the router grants through `spry-portmap` (PCP, NAT-PMP, then UPnP
  IGD): it first removes the mappings a crashed run recorded, then maps the
  UDP and TCP listener and up to `--max-allocations` allocation ports (at
  least four, or all if fewer were asked for), refuses a VPN route, a
  `--bind` that does not reach the router and a carrier-grade, private or
  reserved external address, starts the relay on the granted values, renews
  each mapping at half its lease (7200 s, or 3600 s on UPnP; a permanent UPnP
  lease is added again every 30 minutes), and removes only its own mappings
  on stdin close, SIGINT and SIGTERM within two seconds, leaving anything
  unfinished in the record. A changed external address or port restarts the
  node's own relay on the same local ports and updates the TURN URLs that
  credentials carry. Permanent UPnP leases are used, recorded and reported.
  The record is `<state file>.mappings`. New `--gateway IPV4` names the
  router for a host that knows it. New stdout lines, `portmap` (states,
  counts and fixed reason words only) and `urls`, join `ready` and `status`;
  `ready` keeps its shape. A router that cannot host ends the node with exit
  code 3 so a supervisor does not treat it as a crash. Without `--map-ports`
  the mode is unchanged. Tests use the in-house fake gateways only; no real
  router has been tried.
- Add an aggregate bandwidth cap and a counts-only status line to supervised
  mode. `--aggregate-bytes-per-second` (1 to 67108864, default 625000) limits
  relayed payload bytes across every allocation together, in addition to the
  per-allocation limit, by dropping what is over. The node prints
  `{"v":1,"event":"status","allocations":N,"bytesRelayed":N,"lastAllocation":N|null}`
  after `ready` and then at most every 5 seconds when a count changes; it
  carries no address, key, login or room. `turn::Config` gains
  `aggregate_bytes_per_second` (`None`, unchanged, by default) and `Server`
  gains `last_remote_allocation()`.
- Add the `spry-standard-v1` node card (kind 24183, no address) in
  `spry_link::standard`, returned with supervised grant and credential
  answers, and a reproducible `standardNode` entry in
  `tests/vectors/spry-link.json`. Existing vector entries are unchanged.
- Add `Authority::trust_pairing` for supervised hosts.
- Add `spry-portmap`, an in-house router port-mapping library: PCP (MAP),
  then NAT-PMP, then UPnP IGD (v1 and v2, WANIPConnection and
  WANPPPConnection), with gateway discovery from the route table, renewal at
  half the lease, epoch-based restart detection, owned-only removal (PCP by
  nonce, UPnP after `GetSpecificPortMappingEntry` shows this host and tag)
  and a record file so a later launch can remove a crashed run's mappings.
  UPnP routers that grant only permanent leases are used and recorded unless
  the caller refuses them. Router replies are parsed with fixed size limits
  and deadlines; UPnP URLs are followed only when they name the gateway, and
  the XML reader refuses document type declarations and custom entities.
  No new dependency: `getrandom` and `socket2` were already in the workspace.
  Tests run against in-house fake PCP, NAT-PMP and UPnP gateways on
  loopback. `spry-node portmap check` maps a test port, prints what worked
  and removes it, without starting a relay. Not yet wired into `spry-node`'s
  relay; real routers remain untested.

- Retry existing nonblocking stream output once before dropping a relay packet
  for queue pressure. Recheck the unchanged queue/control-reserve limits after
  that attempt; a genuinely blocked stream still drops the packet.

- Add `SPRY_MAX_ALLOCATIONS`, `SPRY_MAX_ALLOCATIONS_PER_USER` and
  `SPRY_MAX_TCP_CONNECTIONS` to the `spry-node` standard profile so a small
  host can lower the relay's caps. Defaults stay 32, 8 and 32, which are also
  the maximums; invalid values, or a per-credential cap above the total,
  refuse startup. The private-node profile and the public credential issuance
  limits are unchanged.
- Seal room grants: a paired app registers the signing keys that may redeem
  its grant through `POST /v1/grants/devices` (add and remove with 30-day
  leases, ordered by revision) and may seal the grant; a confirmed key may
  vouch for up to four newcomers at a time through `POST /v1/grants/vouch`
  (24-hour entries that cannot vouch, at most 8 per grant and per sponsor
  per day, sponsors tracked per grant so one grant cannot stop vouching on
  another; every named key is counted and answered alike, so vouching does
  not reveal which keys are registered). An enforced grant refuses
  unregistered keys at `/v1/credentials` with the existing "Call access has
  expired." refusal. `SPRY_ROOM_SEAL` (`auto` by default, `required` or
  `off`) chooses when grants are enforced; any other value refuses startup.
  At most 64 registered keys per grant, 512 across one pairing's grants and
  1024 per node. Registered keys persist in the version 1 state file within
  its 128 KiB limit; an older binary still loads it, with every grant
  unsealed. Both paths also work over the `spry:` control channel.
- Removing a pairing now drops its grants from the saved state in the same
  write, and a state write that would exceed the read limit is refused.
- Add an optional operator privacy-notice link to public adverts as a
  `["privacy", url]` tag, set with `SPRY_PUBLIC_PRIVACY_URL` (no default).
  The link is `https://` on a DNS name with a restricted path, at most 256
  bytes; an invalid value refuses startup. Adverts stay version 1, older
  readers ignore the tag, and Spry never fetches the link. Advert verifiers
  now refuse `xn--` labels in the credential host, as Android already did.
  The fixture gains twenty-five cases; existing cases are unchanged. Rust
  callers of `advert::open` and `advert::open_parts` pass the new `privacy`
  argument, and `Advert` gains a `privacy` field.
- Resume queued application bytes after TLS ciphertext drains, without waiting
  for another writable event. Queue limits and the control reserve are unchanged.
- Configure the existing Linux verify job on `ubuntu-24.04` to build both
  TLS-enabled standalone executables and upload a three-day CI artefact after
  its checks pass. Include exact committed source, dependency licences,
  checksums and ELF/GLIBC provenance. This adds no formal Linux release, image,
  service or deployment qualification; existing prerelease bytes stay unchanged.

## 0.3.0 — 26 October 2026

Public MIT prerelease. The native macOS ARM64 download includes the TLS-enabled
`spry-turn` executable. Other platforms and the service adapter remain source
builds for this version; older release artefacts retain their original bytes.

- Add exact local/public UDP allocation pairs with `--relay-port-map`, bounded
  to 1024 unique entries, no gap/ephemeral fallback and authenticated 508 on
  exhaustion. Local socket ownership and advertised endpoints remain separate.
- Reject crossed or released own-address endpoint authority, including stale
  permission/channel forwarding; translated ports require a distinct public IP.
- Add the explicit serve-only `--exit-on-stdin-close` parent-lifetime guard.
  Standalone default lifetime remains unchanged.
- Record private/public self-hosting goals, software-publisher boundaries and
  separate desktop, VPN, Android, media and maintainer acceptance gates.
- Add `Config::relay_port_mappings`: Rust hosts using struct literals must
  supply it, or use `Config::local(secret)`. Map acquisition/renewal, Proton
  reachability, independent-network media and physical-device acceptance remain
  unqualified. No desktop binary bundling or running service is included.

Previously merged source changes included in this prerelease:


- Extract owner-authorised pairing and scoped credentials into the reusable
  `spry-access` Rust library, with explicit calling-application configuration.
- Add `spry-service`, a reusable HTTP host adapter and standalone `spry-node`
  executable. Archipelago integration supplies its own UI/signing assets;
  standalone use requires no Archipelago installation.
- Keep forwarding in the independent `spry-turn` library and executable.
  Home-network mesh integration and physical-phone acceptance remain open.
- Add opt-in [public mode](docs/public-mode.md) for the standard profile:
  anonymous, separately rate-limited TURN credentials and a kind 31478
  Nostr advert published only to operator-named relays, with a shared
  verifier and synthetic fixtures. Off by default, with no default relays.
- Rate-limit API requests before authentication per forwarded caller, not
  per reverse proxy, and keep owners and paired apps a place in the
  authenticated limiter, so strangers cannot lock them out.
- Withdraw the public advert when the relay stops being ready, and reopen it
  when ready again, instead of leaving it up for up to two hours.
- Issue public logins for an hour rather than ten minutes. The relay ends an
  allocation when its login expires, so a call on one public login lasts at
  most that long; clients fetch a fresh login and restart ICE before then.
- Tighten advert verification: TURN URL ports must be 3478, 5349 or 443, or
  omitted, and `expiration` must be 1 to 16 ASCII digits.

## 0.2.1 — 23 October 2026

Public MIT prerelease. Stream readiness registrations now change only when
backpressure changes write interest. Public Rust configuration is unchanged.

- Native UDP/TCP/TLS benchmark tooling, loaded latency samples, explicit
  TLS verification, binary identities and live Linux socket-memory counters.
- Controlled M4 comparison against v0.2.0 and coturn, with TCP/TLS tuning
  gains, workload limits and memory trade-offs recorded.
- Twenty-seven socket tests, real backpressure transition coverage,
  sustained allocation churn, loss/jitter, expiry, slow-client recovery
  and coverage-guided ASan fuzzing. CI includes bounded stress and fuzz runs.
- Actual KithMoot web acceptance with relay credentials entered through
  device Settings, bidirectional generated media and no credential service.
  Public-network, physical GrapheneOS and Archy acceptance remain open.

## Public source, 23 October 2026

The owner authorised public MIT source and the existing GitHub prereleases.
History and release archives were checked before visibility changed. Existing
tags and archive bytes are retained; historical private-release wording below
describes their original creation. Package registries and hosted services remain
separate scope. This documentation change does not requalify runtime performance.

## 0.2.0 — 23 October 2026

Private prerelease. Adds a public `Config::relay_port_range` field; Rust
hosts using struct literals must supply it, or use `Config::local(secret)`.

- Optional inclusive `--relay-ports FIRST:LAST` bounds UDP peer allocations.
  Occupied ports are skipped; exhaustion returns 508 without falling back
  outside the range. Existing default ephemeral allocation is unchanged.
- Operator firewall/NAT/certificate plan and bounded-range socket/browser
  regression coverage. Public deployment qualification remains open.
- Versioned native/WASM release archives, current API/installation guides
  and regenerated LLM context. Donation destinations are unchanged.

## 0.1.0 — 23 October 2026

Initial private prerelease. No package registry, public relay or Archy
deployment is included. Full coturn parity and production qualification
remain open.

- Standalone Rust server and embeddable native library with STUN Binding,
  authenticated TURN UDP allocations, permissions, ChannelData and indications.
- UDP/TCP clients, optional rustls TLS, expiring shared-secret credentials
  and bounded allocation, connection and bandwidth resources.
- Borrowed forwarding buffers, generation-tagged readiness slots and the
  concrete-IPv4 connected-UDP optimisation, with socket trade-offs disclosed.
- Native ARM64 M4 Max comparison against coturn 4.18.0, with complete raw
  results and superseded translated-architecture runs identified.
- WASM packet arena and credential helpers, verified through actual execution.
- Independent UDP/TCP/TLS socket checks, relay-only generated browser media,
  Linux/macOS CI and explicit remaining qualification gates.
- Installation, integration, API, operations and coturn compatibility guides;
  ForgeSworn donation links and generated LLM navigation/full context checked
  for freshness in CI.
