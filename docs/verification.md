# Standalone verification

## Bounded relay ports, local increment

The optional UDP relay-port range passed 22 independent socket tests with
the default TLS build, including a signed 508 on exhaustion, occupied-port
skipping, reuse after deallocation and continued forwarding by another
allocation. Chromium passed relay-only generated audio/video/data over
UDP, TCP and TLS, with selected local and remote relay ports asserted
inside the configured range. See the [bounded receipt](evidence/bounded-relay-ports-20261023.json).
The existing initial-release benchmark and hosted CI below do not qualify
this new runtime change. Public firewall/NAT, certificate lifecycle, Archy
installation and phone acceptance remain unverified.

## Initial implementation evidence

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

At the initial verification, GitHub hosting was private under
`forgesworn/spry-turn`. Publication to package
registries, image registries, public releases and Pages remains disabled or
absent. [Hosted CI](https://github.com/forgesworn/spry-turn/actions/runs/40015270709)
passed on Linux and macOS for implementation commit
`48d75adf51c73b1ef2a51a3cb663e424f2b4ea35`. That run predates the bounded-port
increment; hosted CI is separate evidence from the new local checks.

Retained local build evidence is ignored by Git:

- `.local/bin/spry-turn`: tested native executable with optional TLS enabled.
- `.local/wasm/`: generated WASM module and JavaScript/TypeScript bindings.
- `.local/evidence/m4-benchmark-source.tar.gz`: exact M4 benchmark source
  snapshot, identified by the committed build receipt. Rustfmt normalisation
  matches the reviewed Rust files. Repository ownership metadata subsequently
  changed to the ForgeSworn organisation without changing runtime source.

Task-owned test servers and browsers have stopped. The M4 scratch tree was
removed after evidence capture, and `cargo clean` removed 340.2 MiB of local
build output. Existing unrelated host services are preserved. Real-phone,
lossy-network, Linux performance, full coturn conformance and public operator
acceptance remain the explicit later gates in [GOALS.md](../GOALS.md).
