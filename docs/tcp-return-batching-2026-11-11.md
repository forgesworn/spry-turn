# Plain TCP return batching, 11 November 2026

The candidate integrates bounded plain TCP output batching and shared empty
storage against current main. It does not transplant the historical experiment's
parent, UDP socket tuning, EOF handling, TLS changes or scheduler changes.

## Source and mechanism

- Parent: `56232d52f0fbfd2f3795a50917890ed6c85e6dc9`.
- Measured candidate: `d89aa52920f32c19d6ec15a7af8459e9c251ebcb` (superseded by
  the fatal batch-flush accounting correction described below).
- One peer receive dispatch may queue up to 16 frames or 16,384 bytes before
  flushing plain TCP output. A larger frame flushes individually. Every dispatch
  exit flushes pending output, including expiry, revocation and socket errors.
  Nothing waits for a future datagram or timer to fill a batch.
- One server-owned empty `Vec` is lent to an eligible connection. A drained
  connection regains its own original storage. Pending output and the write
  cursor stay with their connection after backpressure; only empty vectors
  change owners. Closing a borrower frees its owned buffer.
- UDP clients and TLS clients retain their existing send paths. Authentication,
  permission checks, aggregate and per-allocation budgets, control reserve,
  overflow retry and writable-readiness handling remain in place.

The 16-frame/16-KiB limit is an **output-batch bound**, not a dispatch fairness
bound. The inherited peer receive loop still drains until `WouldBlock`.
Continuous-saturation fairness and Linux epoll behaviour need separate tests.
The shared vector follows the existing bounded queue growth policy; it is not
a strict 16-KiB cache. Backpressured connections can retain larger buffers.

The historical 33.8% RSS reduction compared shared storage against a separate
experimental batching parent. It is not a result against this current-main
parent and must not be attributed to this integration.

## Correctness checks

Six focused tests cover real UDP-to-TCP delivery of a 9,000-byte generated
payload without retaining connection growth; reuse across two connections;
pending and partial output ownership; close while borrowed; frame, byte and
dispatch-end flush boundaries; and UDP/TLS exclusions. Existing real-socket
overload, recovered-writability, control-reserve and TLS retry tests remain.

Validation of the **measured revision d89aa52**, before the subsequent batch
accounting correction:

- `npm run check` passed during implementation: generated documentation,
  KithMoot guard, formatting, workspace/all-feature Clippy and tests,
  no-default and turn-only tests.
- At exact d89aa52, formatting, TLS-library Clippy, a fresh release build,
  workspace/all-feature tests using that executable for subprocess tests,
  38 portable runtime/turn/TLS library tests and 42 wire tests passed.
  The Rust recheck total was 313 passed, one existing ignored.
- Task-owned source diff and comparison script: Gitleaks 8.30.1, no findings.
  The whole-source scan flagged the unchanged synthetic public-advert fixture's
  generated `nodeKey`; its fixture declares `synthetic: true`.

A subsequent review found that a fatal dispatch-final flush could count deferred
frames as forwarded without counting their drop. The correction tracks batch
frame counts and payload bytes, and settles them after flush/readiness outcome.
Successful writes and backpressure count as accepted, preserving existing
queued-output semantics; fatal flushes drop the newly unaccepted batch. Prior
accepted output is never recounted. A queue-cap retry first settles the current
batch. Four regression tests cover final failure, threshold failure, real
backpressure followed by failure, and fatal queue-cap retry. This correction
passed its own correctness recheck; the measurements below predate it.

The corrected source (`src/turn.rs` SHA-256
`c03cd79c45ac7f93a3c621c3bd9a4c6fc6b68f538f94ac03320b61dcddea5c96`) passed all ten
focused batching tests, formatting, workspace/all-target Clippy with warnings
denied, a fresh release build, the complete workspace/all-feature suite using
that executable, the portable runtime/turn/TLS library suite (41 tests), and
all 42 wire tests. The full Rust suites totalled 320 passed and one existing
ignored, excluding the separate ten-test focused run. No performance campaign
was rerun after the correction.

## Diagnostic socket results

All **40 timed rows passed**, checking **11,706,480 media forwards** including
warm-up and sequential probes. Each profile used four AB/BA pairs, four load
workers except the one-client profile, and a 100,000-round-trip floor. TCP128
and TCP512 used five-second phase floors; the other profiles used three seconds.
The compact [result summary](evidence/tcp-return-batching-2026-11-11.json) retains
source and binary hashes, all 40 scalar rows, profile counts, arm medians/ranges
and paired-ratio medians/ranges. No failed or adverse row was discarded or replaced.

The host was a native ARM64 Apple M1 running Darwin 23.6.0, using Rust 1.94.1
and ordinary release settings. Existing unrelated host work remained active.
Recorded one-minute load averages ranged from **25.8 to 66.6**, changing
substantially between treatments. The sequential slot excluded this task's
other builds and benchmarks; it did not isolate the physical host.

The table reports median paired changes, candidate relative to parent. Positive
CPU, RSS and p99 values mean more cost. These observations are **not a robust
causal speed or memory claim** under this contention.

| Profile | Useful throughput | CPU per verified forward | Post-throughput retained RSS | Sampled peak RSS | Loaded RTT p99 |
| --- | ---: | ---: | ---: | ---: | ---: |
| TCP, 128 clients, 1,200 B, window 8 | +12.3% | -16.5% | -19.2% | -0.9% | -4.4% |
| TCP, 512 clients, 1,200 B, window 8 | +35.0% | -18.0% | -26.7% | -1.1% | -32.6% |
| UDP, 128 clients, 1,200 B, window 8 | +1.6% | +5.6% | +1.3% | -3.5% | +12.9% |
| TLS, 16 clients, 1,200 B, window 8 | -24.2% | +15.3% | -14.2% | +10.6% | +133.8% |
| TCP, 1 client, 160 B, window 1 | -12.2% | +5.7% | -15.4% | +5.9% | +88.7% |

TCP128 parent throughput ranged from 42,475 to 79,188 packets/s, against
61,138 to 91,817 for the candidate. The TLS parent ranged from 51,789 to
198,438 packets/s even though TLS batching is excluded from the candidate.
This variation prevents treating the favourable TCP cells as qualification.
Post-throughput retained RSS reductions also do not establish reduced heap allocations:
sampled TCP peak residency barely changed, and system pressure affects RSS.

**Default adoption remains unqualified.** These results apply only to d89aa52
and must not be extrapolated to the subsequent accounting correction. The sparse TCP and TLS adverse cells
must remain visible. Compare the exact parent and candidate on an available,
controlled host at fixed offered rates, including sparse traffic, before
accepting a general improvement. Do not repeat these contended samples until
they happen to pass, and do not promote their closed-loop p99 values into an
equal-load latency result.

## Reproduce a matched socket comparison

Build each revision sequentially in the same worktree target directory. Preserve
the parent executable before rebuilding the candidate. Use the same native
loader for both. No coturn installation is needed for this paired comparison.

```sh
cargo build --locked --release --features tls --bin spry-turn --example load -j 2
# Preserve the parent before building the candidate in the same target tree.
python3 scripts/compare-pair.py \
  --parent .local/spry-parent --candidate target/release/spry-turn \
  --loader target/release/examples/load \
  --parent-source 56232d52f0fbfd2f3795a50917890ed6c85e6dc9 \
  --candidate-source d89aa52920f32c19d6ec15a7af8459e9c251ebcb \
  --transport tcp --clients 128 --size 1200 --window 8 \
  --pairs 4 --seconds 5 --packets 100000 --output .local/tcp-pair.json
```

The runner alternates AB/BA, pins executable hashes and rejects non-native
architectures. It verifies returned payloads, records every completed row and
retains a failed-run marker rather than silently replacing failed runs. Its
fixtures use generated credentials and loopback traffic, and stop on exit.

These are closed-loop socket measurements. They do not establish equal-offered-
rate latency, maximum capacity, WAN performance or sustained operation. CPU
includes process startup, allocation setup, warm-up, latency probes and resource
inspection; normalisation includes all verified media forwards. RSS is process
residency, excluding kernel/socket memory. `loaded_rss_bytes` is a retained
sample taken after the throughput phase, not a sample during throughput. Peak
RSS is a separate measurement sampled every 50 ms over the workload. The loader
supports at most 1,400-byte payloads; an 8,192-byte workload remains outside this
comparison even though the focused socket test covers one larger frame.

Task-owned raw logs, copied executables and intermediate receipts are removed
after recording the compact results. The repository retains this method and
summary, not generated traffic or credentials.
