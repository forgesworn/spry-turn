# Measured comparison

23 October 2026. The final, architecture-matched Apple M4 Max run shows
17–22% higher delivered-packet throughput than the coturn configuration
tested, about 19–23% less server CPU time for the complete workload, and
78–82% less process RSS. These are UDP loopback measurements, not a claim
about maximum WAN capacity, TLS performance or every coturn configuration.

## Final native ARM64 results

Medians of three runs per row. Both servers and the shared Rust load
generator were thin ARM64 executables. Each throughput run completed
200,000 round trips, counting 400,000 successfully forwarded data packets.
All 36 runs completed: 14.4 million forwarded packets with no observed
loss, reordering or corruption. Units below are decimal kB/MB/Gbit/s.

| Payload | Allocations | spry-turn packets/s | coturn packets/s | spry throughput gain | spry RSS MB | coturn RSS MB |
|---|---:|---:|---:|---:|---:|---:|
| 160 B | 1 | 274,471 | 224,479 | 22.3% | 1.72 | 7.96 |
| 160 B | 16 | 293,864 | 250,261 | 17.4% | 1.82 | 8.39 |
| 160 B | 128 | 302,206 | 252,816 | 19.5% | 2.03 | 11.42 |
| 1,200 B | 1 | 263,649 | 216,849 | 21.6% | 1.72 | 7.96 |
| 1,200 B | 16 | 282,584 | 242,327 | 16.6% | 1.82 | 8.45 |
| 1,200 B | 128 | 292,124 | 245,148 | 19.2% | 2.06 | 11.37 |

At 128 allocations and 1,200-byte payloads, aggregate forwarded payload
rate is 2.804 Gbit/s against 2.353 Gbit/s. Complete-run server CPU is
1.436 s against 1.797 s. That CPU accounting includes startup, allocation
setup, warm-up and the separate latency samples, not just the timed data
loop. It excludes the separate load-generator process.

| Payload | Allocations | spry RTT p50 / p99 µs | coturn RTT p50 / p99 µs |
|---|---:|---:|---:|
| 160 B | 1 | 39.7 / 173.8 | 36.0 / 258.7 |
| 160 B | 16 | 38.0 / 178.0 | 39.5 / 223.0 |
| 160 B | 128 | 37.2 / 48.2 | 39.3 / 48.3 |
| 1,200 B | 1 | 31.4 / 249.7 | 38.3 / 250.7 |
| 1,200 B | 16 | 38.8 / 229.8 | 41.3 / 224.4 |
| 1,200 B | 128 | 38.9 / 48.5 | 40.4 / 50.5 |

These are medians of per-run percentiles from 2,000 single-round-trip
samples taken before each throughput phase. Round trips include the client,
both relay directions and the echo peer; they are not isolated server
processing latency. Lower-load tail latency is visibly affected by host
scheduling. There is no claim of a latency improvement in every row.

## What changed

The server reserves space before received peer payloads and writes TURN
headers there, avoiding a second media-payload copy. Internal readiness
tokens use bounded, generation-tagged slots instead of hash lookups; stale
events cannot address a newly allocated client in a reused slot.

The main measured gain came from connected client-facing UDP sockets for
authenticated, concrete-IPv4 allocations. They preserve the original TURN
five-tuple and use connected send/receive while retaining normal allocation,
authentication and peer-permission rules. Wildcard/IPv6 listeners and failed
socket optimisations use the standard path. A separate faster-hash
experiment gave little benefit and its dependency was removed.

The [matched three-way experiment](evidence/m4-native-connected.json)
compared the portable native baseline, the connected variant and coturn in
alternating order. At 128 allocations/1,200 B their median rates were
246,541, 292,350 and 246,694 packets/s respectively. It supports attributing
the gain to the implementation change, rather than to changing architecture.

There is a resource trade-off. At 128 UDP allocations, the optimised server
holds **257 UDP sockets**, against **129** in the baseline and coturn.
Process RSS excludes kernel socket buffers and other kernel memory. Total
system memory for those sockets was not measured. File-descriptor budgets
must therefore account for two UDP sockets per optimised allocation, plus
listeners and any TCP/TLS connections.

## Method and limits

- Apple M4 Max, 16 logical CPUs, macOS 26.6.2 / Darwin 25.6.0. Existing host
  workloads were left running. Final-run load averages and every raw sample
  are recorded, not a claim of an otherwise empty machine.
- Rust 1.96, explicit `aarch64-apple-darwin` target, release optimisation,
  LTO, one codegen unit, aborting panics and stripped symbols. Generic ARM64
  target; no M4-only instruction tuning or profile-guided optimisation.
- Unmodified coturn 4.18.0 source, SHA-256 pinned by the preparation script,
  `-O3 -DNDEBUG`, database backends and Prometheus disabled, libevent 2.1.13
  and OpenSSL 3.6.4. One relay event loop (`relay-threads=0`); no TLS/DTLS,
  TCP relay allocations or administration in the measured workload.
- Same REST shared-secret authentication, allocation/user limits and
  1 GiB/s per-allocation bandwidth ceiling for both. The elevated ceiling
  avoids benchmarking the default bandwidth limiter. Both explicitly allow
  loopback peers only for these tests.
- Shared native Rust generator, 32 round trips in flight per worker; one
  load worker for one allocation, four for 16/128, rotating across their
  allocations. It checks sequence numbers, peer source and every returned
  payload byte. This closed-loop workload does not establish maximum server
  capacity or simulate 128 continuously saturated independent clients.
- Alternating server order, fresh processes and credentials for each run,
  4,096 process descriptor limit applied equally. RSS sampled every 50 ms;
  very short peaks can be missed. No off-machine test traffic.
- TLS is tested functionally by independent sockets and generated browser
  media; it is not included in these throughput figures. Long-duration,
  lossy-network, Linux, real-phone and Archy acceptance remain separate work.

The UDP/TCP executable is **402,912 bytes**. The measured coturn reference
is 487,032 bytes after `strip -x`; removing its remaining symbol information
gives 462,616 bytes. These executable sizes exclude coturn's required shared
libraries. The optional TLS build and WASM codec are separate artefacts;
the WASM framing test measures no network forwarding.

The first run series mistakenly used an x86_64 Rust executable and generator
under Rosetta against native coturn. Those figures are explicitly
superseded, retained in `evidence/m4-results*.json` for traceability, and are
not used above. A separate earlier attempt hit the generator's inherited
256-descriptor limit. The runner now records binary architectures, refuses
a mismatch when `--required-arch` is set, and sets the descriptor limit.

## Reproduce

Build on the machine being measured; choose the explicit native target.
The preparation script builds its reference and any missing pkg-config
helper inside the supplied scratch directory without installing a service.

```sh
cargo build --locked --release --target aarch64-apple-darwin \
  --bin spry-turn --example load
python3 scripts/prepare-coturn.py .local/reference
python3 scripts/compare.py \
  --spry target/aarch64-apple-darwin/release/spry-turn \
  --loader target/aarch64-apple-darwin/release/examples/load \
  --coturn .local/reference/coturn-4.18.0/bin/turnserver \
  --required-arch arm64 --runs 3 --clients 1 16 128 --sizes 160 1200 \
  --packets 200000 --output .local/m4-results.json
```

Raw [final results](evidence/m4-native-final.json),
[native baseline](evidence/m4-native-baseline.json),
[controlled tuning experiment](evidence/m4-native-connected.json),
[build receipt](evidence/m4-build.json) and
[reviewed source manifest](evidence/source-manifest.json) are the evidence.
No credentials, real endpoints, machine paths or media are included.
