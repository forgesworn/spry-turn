# Compatibility and acceptance

## First standalone implementation

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
- [x] Private repository, source/secret review and CI readback.
- [x] Controlled bounded-port M4 UDP/TCP/TLS comparison against v0.2.0 and
  coturn, with a measured stream-readiness optimisation.
- [x] Actual KithMoot web application: device-selected credentials, relay-only
  generated media over UDP/TCP/TLS and no credential-service request.
- [x] Bounded local allocation churn, injected loss/jitter, credential expiry,
  slow-client recovery and 300 seconds of coverage-guided ASan fuzzing.

## Before replacing an existing deployment

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
- [ ] Measure Linux batching and multiple independent workers before adding
  platform-specific fast paths. macOS results cannot prove Linux performance.

TCP relay allocations (RFC 6062), DTLS client transport, database integrations,
OAuth, telnet/HTTP administration and clustering are outside the first release.
TURN over TCP/TLS still uses UDP sockets between the relay and its peers.
Do not silently remove transport support required by existing clients.

## Later integrations

- [ ] Archy operator-owned package, identity-independent transport credentials,
  deliberate opt-in exposure and resource limits. No default hosted service.
- [ ] Swift/Kotlin boundary and physical no-Play GrapheneOS acceptance if a
  native app needs to host a relay, separately from ordinary TURN client use.
- [ ] Assess Sapflow transport needs without adding codecs, SRT or HLS to the
  forwarding core, or claiming unmodified clients already speak TURN.
