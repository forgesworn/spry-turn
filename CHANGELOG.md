# Changelog

## Unreleased

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
