# Changelog

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
