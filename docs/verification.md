# Initial standalone verification

23 October 2026. Private MIT software project; no public relay, credential
endpoint, application service or Archy integration has been deployed.

- Rust fmt and all-feature clippy passed with warnings denied.
- Eight all-feature unit tests passed, including the published STUN vector,
  tampering, parsing bounds, nonce binding/expiry, rate accounting, private
  peer policy and stale-event isolation with bounded slot reuse.
- Minimal builds passed: one limits test without features; six codec/auth
  tests without the socket runtime.
- All 19 independent socket tests passed with the TLS build, including UDP,
  TCP, TLS, framing, credentials, quotas, expiry, permissions, indications,
  channel traffic and isolation across deallocation/reallocation.
- Chromium passed relay-only data round trips, decoded generated video and
  received audio at both endpoints over UDP, TCP and TLS. No real camera,
  microphone recording or production room was used. Browser TLS tests use
  explicit test-certificate bypass; the independent Python TLS client
  validates the generated certificate through its test CA.
- Actual WASM execution validated the STUN integrity vector and a million
  arena framing/parsing operations without linear-memory growth. Its timing
  is a protocol microbenchmark, not a network performance measurement.
- The final native ARM64 M4 comparison completed all 36 runs, 14.4 million
  forwarded packets, with no observed data loss, reordering or corruption.
  See [method, trade-offs and raw evidence](benchmarks.md).
- The staged source/credential scan passed without an ignore rule. Recorded
  checksum fields use explicit path/SHA-256 records; no test credentials,
  private endpoints, machine paths or actual media are committed.

GitHub hosting is private under `forgesworn/spry-turn`; publication to package
registries, image registries, public releases and Pages remains disabled or
absent. Hosted CI is separate evidence from the local checks above.

Retained local build evidence is ignored by Git:

- `.local/bin/spry-turn`: tested native executable with optional TLS enabled.
- `.local/wasm/`: generated WASM module and JavaScript/TypeScript bindings.
- `.local/evidence/m4-benchmark-source.tar.gz`: exact M4 benchmark source
  snapshot, identified by the committed build receipt. Rustfmt normalisation
  matches the reviewed Rust files. Repository ownership metadata subsequently
  changed to the ForgeSworn organisation without changing runtime source.

Task-owned test servers, browsers and M4 scratch builds are stopped/removed
at handover. Existing unrelated host services are preserved. Real-phone,
lossy-network, Linux performance, full coturn conformance and public operator
acceptance remain the explicit later gates in [GOALS.md](../GOALS.md).
