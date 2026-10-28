# Shared TCP batch storage experiment

This is a measured patch proposal, not an implementation enabled in main.
The 26-line optimisation reuses empty batch storage between plain TCP client
connections. Four balanced comparisons against its exact cap16 parent showed
33.8% lower sampled loaded process RSS, 1.0% lower CPU per verified payload
forward and 1.4% more useful throughput at the original saturated workload.
P99 improved in two pairs and worsened in two. Equal-load latency and broader
adoption remain unqualified.

Current main at `2605a87455f6d94103b3ce56900ba381454e37eb` has newer TLS and
overflow recovery fixes but lacks cap16 batching. Integrating this experiment
requires reconciling those changes and validating the resulting source. Do not
replace current `src/turn.rs` with a reconstructed experiment snapshot.

## Source and test reconstruction

The base is public commit `6b9dd555f57f54d45a0c01b77dd1d68a4ce6f5a4`.
[manifest.json](manifest.json) binds every patch, intermediate source and the
113 unchanged build inputs. Only `Cargo.toml` and `src/turn.rs` differ between
that base and the measured parent. Parent and production candidate differ only
in `src/turn.rs`.

Apply the following patches in order in a dedicated checkout of that base:

1. [baseline.patch](baseline.patch) reconstructs the measured C2/cap16 parent,
   including output budgets, EOF draining, pending-stream pruning, UDP send
   buffer handling and bounded plain TCP batching. Its Cargo feature change
   makes the already pinned socket2 dependency available in portable runtime
   builds. These are experimental prerequisites, not part of the 26-line gain.
2. [reuse-buffer.patch](reuse-buffer.patch) is the exact measured optimisation.
3. [focused-tests.patch](focused-tests.patch) adds six storage regressions.
4. [qualification-tests.patch](qualification-tests.patch) restores the additional
   qualification tests and corrected TLS fixtures used in the actual 69-test
   default/TLS and 47-test portable runs. It changes test code only.

For the expected-red capacity regression, apply
[parent-regression.patch](parent-regression.patch) immediately after the baseline
instead of steps 2 to 4. This is the exact source used for the recorded parent
failure, not a newly inferred failure.

From the publishing repository, this command checks patch application, all
intermediate hashes, Rust formatting and result arithmetic using temporary
source files. It does not build, launch fixtures or modify a checkout:

```sh
python3 experiments/tcp-batch-buffer/verify.py
```

In a dedicated reconstructed checkout, the native library checks are:

```sh
cargo test --locked --features tls --lib
cargo test --locked --no-default-features --features runtime,turn,tls --lib
cargo clippy --locked --features tls --lib --tests -- -D warnings
```

Reuse that checkout's target directory and leave `CARGO_INCREMENTAL` unchanged.
Run these only when the measurement host is available. Generated socket and TLS
fixtures are local. The focused regressions cover real UDP-to-TCP delivery of a
9000-byte payload, two-client storage reuse, partial-output ownership, connection
close, queue/control reserve and TLS/UDP/draining exclusions. Synthetic ownership
tests do not themselves demonstrate socket backpressure; the qualification
overlay contains the separate real backpressure and continuation checks.

## Mechanism and transport semantics

These TCP clients still use UDP relay allocations. TCP or TLS describes the
client-to-server connection; it does not mean a TCP relay allocation. Unsupported
TCP relay requests remain rejected.

Cap16 queues up to 16 frames or 16,384 bytes within one peer receive dispatch,
then flushes at its boundary. It never waits for a future packet. Draining a
connection clears its Vec length but retains capacity. A prior diagnostic found
512 connections retaining 16 KiB each, or 8 MiB in total, despite no blocked or
yielded writes. The consumed-prefix compaction hypothesis had zero observed
opportunity in this workload.

The candidate lends one Server-owned empty Vec to an eligible plain TCP
connection whose output is empty and write cursor is zero. Existing framing,
queueing and flushing run unchanged. If the output drains, the connection gets
its original storage back. If a write blocks or yields, pending bytes and their
cursor remain with that connection. Closing a connection frees its owned buffer.
There is no extra payload copy, timer, dependency or unsafe code.

Authentication, permissions, quotas, control reserve, queue admission, partial
writes, stream continuation and EOF deadlines are unchanged by the optimisation.
TLS, UDP clients and draining connections are excluded. One additional storage
owner follows the existing bounded queue growth policy; it is not a strict
16 KiB cache, and blocked connections may retain larger buffers.

A separate instrumented candidate run delivered 1,485,072 verified round trips.
It observed 2,097,152 bytes of connection output capacity plus 9,632 bytes in the
shared buffer, or about 2.01 MiB combined. There were four growth events and no
pending bytes, blocked writes or yielded writes. Capacity is not RSS; allocator
page behaviour was not measured, and this diagnostic is excluded from timing.

## Paired measurement

[results.json](results.json) contains selected non-sensitive fields from both
controls and all eight timed rows, source/image identities via the manifest,
paired ratios and acceptance thresholds. It is not a raw benchmark transcript.
The original runner and loader are not included; their retained binary hashes
identify the measured inputs, so this package alone cannot replay exact timing.

The host was an Apple M4 Max with 16 cores and 64 GiB RAM. Both uninstrumented
ARM64 release images used Rust 1.94.1, the same locked dependencies and default
plus TLS features. The original IPv4 TCP workload retained 512 clients,
1200-byte payloads, window 8, four workers, a 200,000 loaded-round-trip floor and
at least 10 loaded seconds. Pair order was AB, BA, AB, BA. No failed timing row
was discarded or replaced. Both controls and all timed rows passed, verifying
23,811,488 payload forwards in total.

| Metric | Paired median change |
| --- | ---: |
| Sampled loaded and peak process RSS | -33.7975% |
| Idle process RSS | 0.0000% |
| Full server-lifetime CPU per all verified payload forwards | -0.9914% |
| Useful loaded-forward throughput | +1.3996% |
| Sampled loaded request RTT p99 | -1.4082% |

P99 improved in two pairs and worsened in two; its worst increase was 2.7407%.
These independently saturated runs achieved different rates. They establish a
memory trade-off, not a robust tail improvement, statistical significance, an
equal-load latency ranking or a fresh coturn comparison.

RSS is sampled process residency, excluding kernel memory. The frozen harness
did not retain individual RSS samples, so the reported peak cannot be replayed
from a sample series. Ordinary desktop processes remained; host admission checks
were point-in-time rather than continuous proof of an otherwise idle machine.

Recorded native validation also passed Clippy with warnings denied, five parent
lifetime integration tests, 40 UDP/TCP/TLS wire cases, three large-datagram cases
and 79 diagnostic library tests. These counts belong to the original isolated
qualification, not a new run on the publication branch. The additional wire
harnesses and diagnostic observer are not included in this source-only bundle.

## Acceptance and next measurements

All predeclared saturation guards passed: CPU and RSS candidate/parent median
ratios at most 1.00, every pair at most 1.03; throughput median at least 0.99,
every pair at least 0.97; p99 median at most 1.00, every pair at most 1.05. The
memory optimisation also exceeded the separate loaded-RSS median target of
at most 0.97. Delivery, source, sequence, latency coverage, finite nonbinding
quotas, retained resources and eight-second shutdown gates stayed unchanged.

Before adoption, compare the integrated candidate and its exact parent at the
already planned fixed offered rates near 75% and 90% of the slower capacity.
Retain the same useful CPU, memory, delivery and p99 guards, and require both
arms to meet the unchanged offered-rate gates. Also qualify UDP, TCP512 with
8192-byte payloads and TLS16 with 1200-byte payloads. Preserve windows, quotas,
durations and all failed rounds. No result is assumed for these pending checks.

For the remaining latency hypotheses, the smallest discriminating observations
are relay dispatch duration and pending-stream wait for scheduling fairness,
and plaintext writes plus encrypted record counts per verified forward for
TLS. The measured cap16 path bypasses TLS batching. A separate unqualified TLS
proposal is not included in this candidate or its claimed gains.
