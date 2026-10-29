# Spry goals and acceptance

## Software publisher and self-hosting goals

Owner direction recorded 26 October 2026: ForgeSworn supplies software;
people and independent operators run their own communications infrastructure.
Make this practical through standalone Spry, Docker, Archipelago and optional
native desktop/Android hosting, with public hosting off by default.

Owner priorities confirmed in the same discussion: **KithMoot desktop first,
privacy and performance throughout**. The initial desktop environment uses a
commercial Proton VPN connection. Public, independently operated Nostr relays
may carry operator announcements and encrypted access requests; this does not
authorise a ForgeSworn relay or directory.

Terminology: a **Nostr relay** carries announcements and encrypted control
messages; a **STUN server** helps discover network addresses; a **TURN media
relay** forwards encrypted call packets. Spry hosting means a STUN/TURN server,
not a Nostr relay. Audio/video must never be transported as Nostr events.

Joining a KithMoot room is separate from establishing its audio/video path and
never requires the person to enable Spry hosting. Preserve the person's chosen
IP privacy policy: use a direct media path where permitted and working, or their
own/approved independent TURN media relay. A signed Nostr advert proves control
of an announcing key, not that the operator is trustworthy. Never automatically
choose an unknown public TURN media operator to make a call appear successful.

The objective is to keep software publication separate from providing a
regulated communications service. This is an architectural goal, not a
finding that ForgeSworn, every deployment or every self-hoster is outside
UK law. Publishing this plan does not enable hosting, authorise a deployment
or approve a UI revision.

### G1. Keep operation with the independent operator

- The operator owns the server, secrets, credentials, exposure, logs and
  shutdown. ForgeSworn has no shared provider account, root secret,
  calling entitlement or routine remote administration of their deployment.
- ForgeSworn runs no public relay, credential broker, discovery directory,
  advert index or managed calling network for this design. There is no
  publisher-operated fallback or reachability probe.
- Room admission and media keys stay with the calling application and its
  users. Transport credentials grant transport access only.
- Ordinary app installation and joining a conversation never silently make
  the device a transit node for unrelated people.
- The owner's existing Archipelago node stays private. Its operation is
  assessed separately from software publication; this roadmap authorises
  no change to that node.

Acceptance: inventory each release's defaults, network requests, admission
controls and secret holders. An installed native or cached client must be
able to use independently selected infrastructure with publisher origins
blocked, without obtaining a ForgeSworn calling entitlement.

### G2. Separate disabled, private and public hosting

These describe intended behaviour, not approved screen labels or layouts.

| State | Intended behaviour |
|---|---|
| Off | Optional embedded hosting opens no relay listener, forwards no other person's traffic and publishes no server advert. Ordinary client use remains available. |
| Private | The operator explicitly enables restricted, authenticated hosting for their chosen scope. No public credential endpoint or public discovery advert. Private mesh operation still requires a working mesh route. |
| Public | The operator separately enables public transport access. Anonymous users can obtain bounded transport credentials. Publishing an advert is a further choice; public but unlisted is still public operation. |

New native clients leave embedded hosting off. Installing and starting the
Archipelago server package is an explicit hosting choice; it must not enable
public service. Upgrades preserve deliberate private configuration without
promoting it to public access.

Keep public/private secrets, state, identities, listeners and exposure rules
separate where both profiles are available. Public users must gain no private
pairing, mesh, room or owner authority. A transition that interrupts private
calls must explain that consequence before it starts and preserve recoverable
private state. Stop must release listeners, stop forwarding and attempt advert
withdrawal; missed withdrawals expire under the discovery protocol.

Acceptance: test fresh installation, upgrade, enable/disable, restart, failure
and interrupted transitions. Prove public access cannot reach private services
or keep running after the operator stops it.

### G3. Make desktop and container hosting straightforward

Provide a native Start/Stop hosting control using the existing Rust server,
either embedded or supervised as a bundled executable. Docker and Archipelago
are optional hosting routes; neither becomes a dependency of the relay core.

The intended user flow handles route checks, credentials and cleanup after the
explicit enable action. Do not require the person to understand NAT-PMP, ports,
IP addresses or JSON files. The current owner-configured preview is engineering
scaffolding; its file configuration is not the intended product setup. Detect
unusable hosting routes and explain the result plainly. An ordinary call may
still use an approved independent TURN media relay without making this device a
public STUN/TURN server. Hosting and public announcements remain separate opt-ins.

The host application owns scheduling, secret storage, process lifecycle and
cleanup. Show actual running state, exposure, resource limits and actionable
errors. Starting a process must not be presented as proof of external
reachability. Autostart needs the operator's explicit choice.

The native CLI provides an opt-in `--exit-on-stdin-close` guard for supervised
`serve` processes. The host supplies and exclusively owns a stdin pipe; EOF
ends the child process and lets the OS close its sockets, including when the
host crashes. A stdin read error exits unsuccessfully. Ordinary standalone
operation is unchanged without the flag. This is a native mechanism, not proof
that a packaged desktop host correctly owns the pipe or cleans up on every
platform; qualify parent death, inherited pipe handles and installed-app exit
before claiming crash cleanup. Explicit Stop still needs bounded termination
and observed child exit.

Acceptance: qualify the chosen desktop platforms separately, including stop,
app exit, crash recovery, sleep/wake, port conflicts and firewall refusal.
Qualify Docker Desktop separately from Linux Docker and a Linux VM.

### G4. Explore native Android hosting without Google runtime services

Add the native bindings and lifecycle integration needed to host Spry inside
an Android app. Use Android platform facilities, with an appropriate foreground
service declaration, visible running notification and a Stop action. Do not
add Google Play services, Firebase or a Google-hosted control dependency.

Acceptance requires a physical no-Play GrapheneOS device: private and public
paths where reachable, screen-off operation, user stop, process death,
Wi-Fi/mobile transitions, credential renewal and measured battery, temperature
and data use. Source builds, emulators and ordinary TURN client calls do not
establish phone-hosting acceptance.

Do not promise an unattended iOS relay. Assess a foreground-only iOS host
separately if there is a concrete need. A browser/PWA alone cannot host a
standard raw-socket TURN server; its WASM codec is not a server runtime.

### G5. Explain and prove network reachability

Detect or explain missing routes, blocked ports, carrier-grade NAT, unsuitable
addresses and certificate failures. A server on the same inaccessible network
as its client does not automatically solve that client's NAT problem.

For the current public profile, document the reachable IPv4 address, listener
and allocation ports, operator-controlled DNS name and trusted HTTPS/TURN TLS
needed by the selected client and discovery paths. Keep future IPv6 support
separate from present capability. Private mesh hosting relies on the chosen
mesh's routing and must not imply Spry creates that route itself.

Use an operator-controlled test from an independent network. Never introduce
a ForgeSworn tunnel, gateway or testing service as a hidden prerequisite.
Respect relay-only mode when a route fails; do not silently expose a direct
connection instead.

Acceptance: real calls across independent home/mobile networks, blocked UDP,
expiry and renewal, rejoin, operator replacement and resource exhaustion.
Record the exact tested transports and routes; local hairpin and simulated
NAT results remain separate evidence.

For commercial VPNs, distinguish an outbound internet connection from a shared
private mesh. Do not assume another caller can reach the VPN-assigned address.
Proton's [port-forwarding guide](https://protonvpn.com/support/port-forwarding)
documents an assigned port on eligible paid/P2P connections, which can change
on reconnect; its macOS support is marked early access as checked on
26 October 2026. The [manual NAT-PMP guide](https://protonvpn.com/support/port-forwarding-manual-setup)
documents the same assigned port for TCP and UDP, 60-second mapping leases and
renewal every 45 seconds. That documented single port does not cover the
current Spry UDP/TCP listener plus its separate UDP allocation ports on the
same local address. Neither guide establishes multiple simultaneous assigned
port numbers, a contiguous range or arbitrary external-port requests. This
does not establish that Proton rejects those requests or that every TURN
architecture is unsuitable.

Before selecting a Proton adapter, establish supported mapping multiplicity,
port preservation or translation, independent renewal and reconnect behaviour.
Research an explicit allowed-port set if assigned allocation ports are
noncontiguous, and port translation if external and local ports differ; the
standalone `--public-ip` substitutes the advertised IP only. The native
[explicit allocation map](docs/mapped-ports.md) now accepts exact noncontiguous
local/public port pairs through repeatable `--relay-port-map LOCAL:PUBLIC`.
It does not acquire or renew mappings or advertise the client listener. Do not widen a relay
range across ports without mappings. Qualify the listener and allocated-peer
traffic from an independent internet connection, with the actual advertised
address/ports, lease expiry, renewal, reconnect and route-loss behaviour. No
endpoint publication or external-readiness claim follows from local binds,
NAT-PMP replies or this research alone.

The KithMoot development worktree now includes a separate operator-run NAT-PMP
mapping diagnostic: validate-only by default, explicit source/gateway, a small
listener/allocation plan and one bounded renewal cycle. Local UDP fixtures test
the protocol and failure paths. A live Proton address-only preflight returned
connection refused before any mappings were requested; no route acceptance has
been recorded. It never deletes mappings because replies cannot establish
ownership, and it never starts or advertises Spry. Provider-specific internal
port-zero allocation remains unsupported by that experiment. Its detailed
operator instructions and receipt live in KithMoot's
`docs/2026-10-26-proton-mapping-diagnostic.md`; supervising the native endpoint
map still follows the actual provider contract and independent-network evidence.

Bind only the explicitly selected local address. A lost or replaced VPN route
must not trigger a wildcard bind, home-network fallback or silent direct ICE
fallback. Record the limits of application-level interface monitoring; it is
not a substitute for a tested OS/VPN kill switch. Do not change VPN, firewall
or router settings automatically. A locally running server can remain
unreachable; show these as separate facts.

### G6. Keep discovery optional and controlled on the device

Operators optionally publish their own signed, expiring adverts to Nostr
relays they choose. Clients read from the user's configured independent
relays, verify adverts and let the user choose a transport operator. The
selected operator issues credentials directly to the client.

Do not add a ForgeSworn-curated operator list, central ranking, recommended
badge, directory, telemetry or discovery-specific default relay. Preserve
existing client relay choices. Choices and measurements stay on the device;
ordinary requests and traffic still reveal metadata to the selected operator
and discovery relays, which the privacy wording must explain.

Acceptance: invalid, stale and withdrawn adverts fail closed; discovery and
advertising remain off until explicitly chosen; no selection, failure or
usage report reaches ForgeSworn. Verify credential cleanup and relay-only
behaviour on failure.

Use the existing encrypted ephemeral access protocol where it fits:
`spry-link` kinds 24181/24182 carry signed NIP-44 requests/responses with
30-second expiry. They are not NIP-59 gift wraps. Public kind 31478 adverts
are a separate, expiring discovery protocol and currently describe an HTTPS
credential endpoint; anonymous public credentials over Nostr are not yet
implemented.

Ephemeral live requests avoid relying on relay storage, but need bounded
timeouts, deduplication, replay protection and explicit retry behaviour.
Discoverable adverts must still work for somebody who connects later.
Encryption protects content, not all metadata: relays can observe connections,
event kind, timing, public author/recipient tags and volume. Neither ephemeral
events nor expiration guarantees deletion from observers' copies. Never put
root secrets, room keys, reusable credentials or private endpoint lists in
public adverts. Review any protocol change across the operator and client;
do not silently reinterpret the existing advert format.

### G7. Explain operator responsibility before enabling hosting

Provide proportionate information before restricted hosting and a separate
explicit acknowledgement before public hosting. Explain exposure, resource
costs, metadata and local legal responsibility. The operator should check
applicable laws where they operate and serve users, and their ISP or mobile
provider's terms. A notice does not create an exemption or transfer an actual
ForgeSworn operating role to somebody else.

Proposed public-mode wording, subject to the implementation's actual behaviour
and maintainer review:

> Run a public relay on this device? Other people can send traffic through
> your connection, consuming bandwidth, data and battery. You control and
> operate this relay. Operating it may create legal duties where you operate
> and serve users. Check applicable laws and your connection provider's terms
> before enabling. Publishing an advert exposes your endpoint and may leave
> copies on other relays.

Supply operator guidance on credentials, limits, abuse response, privacy and
host/proxy logs. Do not promise that private use, encryption, a pseudonym or
disabled application logs settles legal classification or eliminates metadata.

### G8. Keep legal and acceptance evidence separate

Use jurisdiction-kit's [GB online-services note](https://github.com/forgesworn/jurisdiction-kit/blob/main/law/gb/online-services.md)
for the law: overall verified 28 September 2026, transport and telecoms updates
23 October, discovery update 25 October, review due 28 March 2027 or earlier
if a relevant watch item moves. `[P]` means primary text read; `[U]` means an
unresolved application, not a prohibition or a confirmed duty.

| Regime | Goal and remaining boundary |
|---|---|
| Online Safety Act, sections 2.2, 2.11 and 2.13 of the note | Preserve genuine software publication and operator independence. Provider-control and access-facility provisions are recorded `[P]`; their application to this TURN/discovery design remains `[U]`. Assess any underlying application-service role separately. |
| Communications Act and public-provider PECR, sections 7 and 4.1 | ForgeSworn supplies software without running the public forwarding service. Classify any actual operator's signal-conveyance and public-provider role separately `[U]`. |
| Investigatory Powers Act, section 5 | Do not promise exclusion from every telecommunications definition: the note records the wider definition and website-owner guidance `[P]`. |
| Data protection, section 3 | Minimise data and document actual defaults, metadata, logging and retention. Personal/household treatment depends on the facts, not a Private label. |

Before implementation release, refresh the [transport position](docs/legal/transport-position.md)
against code and deployment evidence, including the newer standalone service
and discovery paths. This goal record does not replace that assessment or
reactivate historical public-service assessments.

Keep code/CI, simulated networks, independent-network calls, physical devices,
signed releases, deployment and owner/maintainer acceptance as separate gates.
Record exact revisions and receipts; mark only the gate actually passed.

For Archipelago UI, prepare a review pack covering **Spry installation and
launch, embedded pairing, hosting settings, public-mode confirmation and relay
status/Stop controls**, wherever the implementation changes those screens.
Supply the exact build/URL, setup, test steps, expected results and useful
captures. Follow the workspace Archipelago UI baseline. No UI build is
produced by this documentation change; complete the pack for the implemented
revision and refresh it after material changes.

**Maintainer must review and approve UI work on Spry installation and launch,
embedded pairing, hosting settings, public-mode confirmation and relay
status/Stop controls before merging or approval. ZAT pending.**

Record explicit maintainer approval of the reviewed revision. General ship
instructions, CI and agent review do not replace it. Prepare the pack for
the owner; do not contact the maintainer without the owner's authorisation.

### G9. Treat privacy and performance as acceptance criteria

Keep all audio/video packets off Nostr relays. Nostr carries bounded
announcements, encrypted access control and application signalling. Preserve
end-to-end media encryption and keep media
keys with participants. Use operator-scoped identities and minimum public
metadata; do not link an operator identity to an account's social identity
unless the operator deliberately chooses it.

Hosting, advertising and public credential issuance remain separate choices.
Do not persist per-call traffic logs or capture packets by default. Explain
what the local process, OS, VPN, selected Nostr relays and transport operator
can observe; no application's logging setting proves that all those parties
keep no logs. Short-lived transport credentials remain local or travel only
inside the authenticated encrypted access exchange.

Call-content confidentiality and metadata protection are different gates. A
TURN media operator can observe network endpoints, temporary logins, timing,
sizes and volume without having the WebRTC media keys. An own Spry server
reduces reliance on a third-party TURN operator, but does not erase the VPN,
ISP, participant or Nostr observers' views. Room admission and endpoint security
remain necessary because a participant can receive and record playable media.

The inspected KithMoot roster currently exposes device pseudonyms and a
room/epoch tag outside its encrypted body; Nostr operators can group that
activity. Reducing this correlation needs separate compatible protocol work.
Do not claim encryption or ephemeral events remove the observable social graph.
Preserve authenticated SDP/fingerprints and fail-closed IP privacy while
reviewing improvements.

The KithMoot privacy candidate now requires an explicit saved opt-in for public
profile lookups and external profile pictures, preserving saved choices. This
reduces a path that disclosed participant account keys to profile Nostr relays.
It also rechecks expiring admission for active calls, ends local sessions when
their own grant expires, and preserves signed signal freshness while queued.
These are source changes with local generated-identity tests, not a deployment
or physical call acceptance claim.

A reader-first roster envelope 2 codec hides the device signature inside the
encrypted body and uses fresh outer keys. The session writer is still legacy;
old-client compatibility and safe activation remain separate work. The shared
room/epoch selector remains visible, so this is not group unlinkability. See
KithMoot's `docs/protocol/roster-envelope-2.md` and its independent synthetic
conformance vectors. Do not turn this staged codec into a claim that current
rooms have stopped exposing their roster metadata.

Prefer the existing native event loop and bounded buffers to duplicate relay
implementations. Keep the desktop supervisor outside the media path; it starts,
observes and stops the native process. Do not add continuous internet probes,
busy polling or an always-running hosting process to ordinary client use.

Acceptance: compare hosting off/on idle CPU, memory, wakeups and network use;
measure call throughput, latency, jitter, packet loss, sustained resource use
and Stop latency under load on the named hardware and VPN route. Check startup,
VPN reconnect, sleep/wake and failure without logging secrets or recording real
calls. Retain actual measurements and agreed budgets; do not call a design
performant or leak-free on the strength of unit tests alone.

### Starting point and delivery order

Baseline inspected at Spry `f2c56e56395cac41b634bd2096777a413b74fbbd` and
Archipelago Apps `7d98cc2b7a442ead2c1a3274aedd2cb9b65d5675`.

| Area | Starting point | Next evidence needed |
|---|---|---|
| Native core and standalone service | Implemented; see [embedding](docs/integration.md#embed-the-native-rust-server) and [standalone operation](docs/standalone.md). | A supported desktop hosting wrapper and platform lifecycle acceptance. |
| Public profile | Explicit opt-in, no default advert relays; private-node profile rejects public mode. See `crates/spry-service/src/public.rs` and [public mode](docs/public-mode.md). | Independent operator deployment and external-network acceptance. |
| Archipelago | The catalogue selects the private mesh profile in `apps/spry/manifest.yml` in the Archipelago Apps repository. Its public-mode package remains a separate design draft. | Implementation, isolation/transition tests and maintainer ZAT. |
| Android host | A hand-written C ABI and JNI shim (`crates/spry-ffi`, [embedding](docs/embedding.md)) run the supervised node in-process; the release workflow builds it for arm64-v8a and x86_64. The Kotlin class, foreground service and hosting lifecycle are future work in the Android app. | Device load of the packaged minified app, lifecycle integration and physical no-Play GrapheneOS acceptance. |
| Discovery | KithMoot source contains optional device-side discovery. This is separate from hosting a server on the device. | Version-specific client and operator interoperability evidence. |

Delivery order: preserve the publisher boundary and private operation; build
and qualify KithMoot desktop hosting, including the Proton route; complete the
Archipelago public-package design decisions in parallel where independent;
prototype Android private hosting and then reachable public hosting; refresh
legal wording and collect the acceptance evidence for each release. Each
phase may ship independently only after its own gates pass.

Open product decisions:

- [DECISION: Archipelago v1 switches between isolated profiles, as its existing
  draft proposes, or provides separate private/public instances. Simultaneous
  operation is not approved by this record.]
- [DECISION: KithMoot is the first desktop host; select its initially supported
  platforms, binary packaging and optional autostart behaviour. The Android
  host's owning application and supported versions remain open.]
- [DECISION: Public allocation, bandwidth and data limits, and whether operators
  may raise them. Do not turn the existing per-allocation cap into a claim of
  a total or monthly cap.]
- [DECISION: Public-package distribution route and treatment of direct-public-IP
  Archipelago hosts; retain the detailed package design's unresolved items.]
- [INPUT: Host/proxy/system logging and retention for each supported deployment
  before final operator notices are written.]

## Existing transport compatibility and acceptance

### First standalone implementation

- [x] Original Rust STUN/TURN parser with published integrity test vector.
- [x] Real UDP allocations and bidirectional relaying.
- [x] Coturn-compatible shared-secret REST credentials, signed responses,
  stateless address-bound nonces and expiry.
- [x] UDP, TCP and optional TLS client transports, with bounded stream buffers.
- [x] Permissions, ChannelBind, indications, refresh/delete and allocation retry.
- [x] Local Chromium relay-only data and decoded media over UDP/TCP/TLS.
- [x] M4 comparison against unmodified coturn, with method and raw results.
- [x] Native connected-UDP and direct-readiness-slot tuning, tested against
  a native baseline and coturn with resource costs recorded.
- [x] WASM protocol arena, actual execution and bounded buffer reuse test.
- [x] Public MIT source, source/secret review and CI readback.
- [x] Controlled bounded-port M4 UDP/TCP/TLS comparison against v0.2.0 and
  coturn, with a measured stream-readiness optimisation.
- [x] Actual KithMoot web application: device-selected credentials, relay-only
  generated media over UDP/TCP/TLS and no credential-service request.
- [x] Bounded local allocation churn, injected loss/jitter, credential expiry,
  slow-client recovery and 300 seconds of coverage-guided ASan fuzzing.

### Before replacing an existing deployment

- [x] Operator-selected bounded UDP relay port range and firewall/certificate plan.
- [ ] Applied firewall/NAT, trusted public certificate lifecycle and independent
  cross-network deployment acceptance; a local plan is not this evidence.
- [ ] Cross-network KithMoot web and physical native interoperability against
  a separately chosen operator, without a project-operated credential service.
- [ ] Packet-loss, jitter, blocked UDP, IPv6, long-lived refresh, reconnect,
  certificate validation/renewal and resource-exhaustion qualification.
- [ ] Broader RFC conformance and longer network/runtime fuzzing campaigns;
  the recorded bounded codec/auth campaign is not a security review.
- [ ] Independent security review, including nonce/auth state and relay targets.
- [ ] Static long-term user credentials if the target deployments require them.
- [ ] Decide whether supported coturn deployments need EVEN-PORT, reservation
  tokens, dual allocations, RFC 8489 SHA-256 auth or other extensions.
  Unsupported comprehension-required attributes currently receive 420.
- [x] Measure Linux receive batching and multiple independent processes before
  adding runtime paths; the development experiments retain their VM limits.
- [x] Measure a same-source M4 PGO trial; retain the ordinary release build
  because the small observed changes do not establish a useful gain.
- [ ] Repeat Linux performance and resource qualification on independent
  bare-metal hardware before generalising the virtual-machine observations.

TCP relay allocations (RFC 6062), DTLS client transport, database integrations,
OAuth, telnet/HTTP administration and clustering are outside the first release.
TURN over TCP/TLS still uses UDP sockets between the relay and its peers.
Do not silently remove transport support required by existing clients.

### Later integrations

- [ ] Complete Archy's remaining public-package, independent-network and
  maintainer-acceptance gates. Private packaging already exists; see the
  starting-point table above. No default hosted service.
- [ ] Swift/Kotlin boundary and physical no-Play GrapheneOS acceptance if a
  native app needs to host a relay, separately from ordinary TURN client use.
- [ ] Assess Sapflow transport needs without adding codecs, SRT or HLS to the
  forwarding core, or claiming unmodified clients already speak TURN.
