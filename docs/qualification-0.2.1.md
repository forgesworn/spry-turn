# Standalone performance and reliability

This qualification measures the bounded-port standalone implementation in
v0.2.1. It is separate from the [original UDP comparison](benchmarks.md).
Every receipt identifies its executable and source; no result establishes
maximum WAN capacity or full coturn compatibility.

## Controlled M4 tuning

Three repetitions, 128 allocations, 1,200-byte payloads, four native load
workers and a 32-packet window per worker. Each throughput phase runs for
at least two seconds and completes at least 200,000 round trips. Server
order alternates, with fresh processes and credentials. Both servers use
the same bounded UDP relay-port range. All executables are native ARM64;
the Rust server includes optional TLS in every row.

| Client transport | v0.2.0 packets/s | v0.2.1 packets/s | coturn packets/s | v0.2.1 against coturn |
|---|---:|---:|---:|---:|
| UDP | 291,196 | 292,464 | 244,760 | +19.5% |
| TCP | 312,708 | 330,799 | 340,869 | -3.0% |
| TLS | 273,799 | 285,779 | 213,236 | +34.0% |

These are medians of delivered forwarding rates in the
[27-run controlled experiment](evidence/m4-tuning-0.2.1.json). No loss,
reordering or payload corruption was observed in completed runs. The UDP
peer leg remains UDP with every client transport. TLS negotiated TLS 1.3
and AES-256-GCM-SHA384 for both servers; the load client validates the
generated localhost certificate through an explicit test trust store.

The retained runtime change caches each stream's writable-interest state.
The event loop registers writable readiness when output becomes blocked,
then removes it after draining. It avoids a registration syscall for every
packet while keeping read interest active. No dependency, thread, unsafe
block or packet buffer was added. A real-socket unit test forces
backpressure, drains the queue, checks the transition back to read interest
and verifies later forwarding. The controlled medians improve spry-turn's
own TCP throughput by 5.8% and TLS throughput by 4.4%.

| Client transport | spry loaded RTT p99, µs | coturn loaded RTT p99, µs | spry process RSS, MB | coturn process RSS, MB |
|---|---:|---:|---:|---:|
| UDP | 836.7 | 1,006.3 | 2.24 | 11.35 |
| TCP | 778.5 | 1,010.4 | 12.21 | 11.70 |
| TLS | 872.2 | 1,273.6 | 14.89 | 20.43 |

Loaded RTT includes time queued behind the batch, both relay directions,
client work and the echo peer. It samples every 64th packet into bounded
per-worker reservoirs. The separately recorded sequential RTT is measured
before throughput; its small changes do not support a general latency-win
claim. Stream buffers cost memory: spry-turn's TCP RSS exceeds the tested
coturn configuration here. Decimal MB excludes kernel memory and shared
dependency files.

## Reproduce and interpret resources

Build the load generator with the same TLS feature and native target as
the server. Supply unmodified coturn built by the pinned preparation script.

```sh
cargo build --locked --release --features tls \
  --target aarch64-apple-darwin --bin spry-turn --example load
python3 scripts/prepare-coturn.py .local/reference
python3 scripts/compare.py \
  --spry target/aarch64-apple-darwin/release/spry-turn \
  --loader target/aarch64-apple-darwin/release/examples/load \
  --coturn .local/reference/coturn-4.18.0/bin/turnserver \
  --required-arch arm64 --runs 3 --clients 1 16 128 --sizes 160 1200 \
  --transports udp tcp tls --packets 200000 --min-seconds 2 \
  --output .local/qualification.json
```

Use `aarch64-unknown-linux-gnu` on native ARM64 Linux, or the actual native
target on another host. The runner refuses architecture mismatches when
`--required-arch` is supplied. `--baseline` adds a reviewed alternative
server, `--workers` controls generator concurrency and
`--coturn-relay-threads` records the reference configuration. These are
benchmark controls, not worker support in the server.

This is a closed-loop delivered-packet workload. More allocations do not
mean every allocation is independently saturated. Duration floors improve
sampling but do not establish maximum sustainable packets/s. CPU seconds
cover server startup, allocation setup, warm-up, both measurement phases
and resource inspection. Duration-floor runs can deliver different packet
counts, so total CPU alone cannot establish efficiency. The generator runs
in a separate process and is excluded from server CPU accounting.

RSS is sampled every 50 ms. Descriptor and socket-memory snapshots are
taken after throughput while all client connections and allocations remain
live, before releasing the generator. They are quiescent snapshots, not
peak socket memory. Linux attributes `ss -m -e` records to process-owned
socket inodes and aggregates each counter separately. In particular,
`rb`/`tb` are configured ceilings, not allocated memory. The counters do
not include every kernel object and must not be added to RSS to claim
total system memory. macOS reports this measurement as unavailable;
the extra connected UDP socket per allocation still needs a descriptor
and kernel-memory budget. See the [Linux ss manual](https://www.man7.org/linux/man-pages/man8/ss.8.html).

## Application and remaining acceptance

The actual [KithMoot web application](kithmoot-acceptance.md) has a separate
generated-media runner. It enters operator credentials through the real
Connections settings and checks that the client makes no `/turn` request.
Browser certificate bypass is explicitly distinct from the trusted test
TLS used by the native benchmark client.

Private cross-network operation, trusted public certificate lifecycle,
physical GrapheneOS calls, long-lived refresh/credential renewal and
independent security review remain separate gates. Archy and Sapflow
integration follow standalone qualification; no publisher-operated service
is added by this work.
