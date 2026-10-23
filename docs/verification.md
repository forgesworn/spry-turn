# Standalone verification

## v0.2.1 qualification

The stream-readiness optimisation passed ten all-feature Rust unit tests,
including actual TCP backpressure, queue draining, removal of writable
interest and subsequent progress. Twenty-seven independent socket tests
passed on macOS and native ARM64 Linux, including the five added malformed
input, integrity and expiry regressions. A later
[fixture startup correction](evidence/fixture-startup-0.2.1.json) adds five
independent subprocess regressions, giving **32 passing tests** on both
platforms. It reserves TCP/UDP together, keeps TLS separate and bounds
collision retries, startup reads and cleanup. The unchanged public API remains
at the v0.2.0 configuration shape.

On Apple M1, the [180-second churn run](evidence/stress-0.2.1.json) completed
30,137 allocations, 3,767 signed port-exhaustion responses and 337 refreshes
of a short-lived standing allocation. It exercised UDP/TCP/TLS, failed
authentication, private-peer rejection and resumed forwarding. Server
descriptors returned from nine to nine; process RSS rose from 2.08 to
4.19 MB. Its fixed regression budget and duration are not a leak proof.
The same receipt records seeded datagram loss, delay and reordering,
credential expiry/replacement, partial-stream reclamation, TCP/TLS paused
reader recovery and post-overload progress.

The [300-second ASan/libFuzzer campaign](evidence/fuzz-0.2.1.json) completed
15,241,706 inputs with zero crash artefacts, `cov=698` and `ft=1561`.
It records the target/core hashes, seed, toolchain and corpus digests.
This is coverage-guided codec/auth testing, not network-runtime fuzzing or
independent security acceptance.

The [hardened wrapper smoke run](evidence/fuzz-wrapper-0.2.1.json) adds a
separate 30 seconds and 344,105 inputs after lockfile preflight and process
cleanup changes. It also passed with zero crash artefacts. The earlier
300-second receipt retains the exact wrapper and parser hashes it tested.

The [actual KithMoot web application](evidence/kithmoot-web-0.2.1.json),
source `24038110`, passed generated bidirectional decoded video and audio
through spry-turn over UDP, TCP and TLS. Both browsers configured owner
credentials through Settings, selected relay candidates, omitted credentials
from invitations and made zero `/turn` requests. See the
[reproduction and limits](kithmoot-acceptance.md). Browser TLS bypasses its
test certificate; the native benchmark client separately validates a
generated certificate through its test trust store.

The [current comparison](qualification-0.2.1.md) contains complete M4 and
Linux matrices: 216 runs and 96,423,584 checked packets, plus a controlled
v0.2.0/v0.2.1/coturn tuning trial over all three client transports. It supersedes no
historical receipt: each identifies its own method and source. Public
firewall/NAT, trusted public certificate renewal, physical GrapheneOS and
Archy acceptance remain open. The existing independently operated private
coturn deployment was inspected read-only and remains unchanged.

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
