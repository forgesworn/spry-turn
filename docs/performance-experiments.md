# Performance experiments

These experiments inform later runtime changes. The shipping server keeps
its existing dependencies, one event loop and ordinary release build.

## Linux UDP receive batching

The separate development crate in `experiments/linux-batch` measures a
specific question: how much receive-call overhead can be amortised when
several UDP datagrams are already queued on one descriptor? It adds no
dependency or feature to the spry-turn runtime.

It uses pinned nix 0.31.3 with only `net` and `uio` features. Its safe
[`recvmmsg` API](https://docs.rs/nix/0.31.3/nix/sys/socket/fn.recvmmsg.html)
and preallocated `MultiHeaders` avoid introducing unsafe code here. The
call uses `MSG_DONTWAIT` and no kernel timeout: the documented Linux
timeout behaviour can otherwise leave a partly filled call blocked.

Run on Linux from the repository root, sharing the existing target tree:

```sh
cargo fmt --manifest-path experiments/linux-batch/Cargo.toml -- --check
cargo clippy --locked --manifest-path experiments/linux-batch/Cargo.toml \
  --target-dir target --all-targets -- -D warnings
cargo test --locked --manifest-path experiments/linux-batch/Cargo.toml \
  --target-dir target
cargo build --locked --release \
  --manifest-path experiments/linux-batch/Cargo.toml --target-dir target
target/release/spry-linux-batch-experiment --packets 65536 --runs 3 \
  > .local/linux-batch.jsonl
```

Every variant first queues the same 32-datagram offered window, then drains
it. A single `recv_from` baseline is compared with `recvmmsg` capacities
1, 8 and 32. Payloads are 160 and 1,200 bytes. One hot receiver socket is
contrasted with 32 receiver sockets holding one ready datagram each. These
are unconnected sockets; this does not measure spry-turn's connected-UDP
path. Order
rotates between repetitions. Warm-up traffic is excluded from reported
packet counts and timing. All sockets bind loopback on ephemeral ports;
there are no services, files containing credentials or fixture threads.
Each sample has a wall-time bound and stops on an unexpected receive result.

The receiver timer includes source, sequence and every payload-byte check,
but excludes sending and queue fill. Whole-workload time includes those
sender costs. Output is newline-delimited JSON: a method record followed
by raw samples. Receive-call counts are instrumented API calls, not an
independent `strace` measurement. Returned batch occupancy, payload arena,
I/O-view and header storage are reported. Header storage follows the pinned
dependency's structures and excludes allocator overhead. Socket receive
buffer limits are configuration values, **not measured kernel memory**.
Whole-process RSS and forwarding latency are not supplied by this tool.

This is a receive-queue microbenchmark, not maximum network throughput or a
spry-turn performance result. It deliberately arranges ready queues. Real
TURN allocations spread traffic across sockets; increasing batch capacity
cannot combine packets from different descriptors. Extra arena space and
header setup may cost more than the saved calls when queues hold only one
packet. Any integration must demonstrate an improvement in the actual
server, including fairness, p99 latency, full supported datagram sizes and
kernel memory, before changing the runtime.

### Recorded run

The coordinated Linux VM run completed all 48 samples: 3,145,728 measured
datagrams, with no observed source, ordering, length or payload failures.
The [receipt](evidence/linux-batch-0.2.1.json) and
[raw newline-delimited samples](evidence/linux-batch-0.2.1.jsonl) retain the
method, build identities and results.
The two focused tests also passed. The binary was built with Rust 1.94.1
for aarch64, using a two-vCPU container quota and a 2 GiB container memory
limit inside the configured 4 GiB VM. This is distinct from native M4 or
bare-metal Linux forwarding measurements.

The table shows median whole-workload cost reduction against `recv_from`,
including the sender. Positive values mean less elapsed time; negative
values mean more. Receiver-only timings and every raw sample are retained
in the experiment receipt.

| Ready receiver sockets | Payload | Batch 8 cost reduction | Batch 32 cost reduction | Packets per batch call, 8 / 32 |
|---|---:|---:|---:|---:|
| One hot socket | 160 B | 7.5% | -16.0% | 8 / 32 |
| One hot socket | 1,200 B | 17.7% | 23.6% | 8 / 32 |
| 32 sockets, one queued packet each | 160 B | -26.7% | -29.7% | 1 / 1 |
| 32 sockets, one queued packet each | 1,200 B | 14.0% | -30.6% | 1 / 1 |

Batch 8 reduced receiver-plus-validation time by 27–37% for one hot
socket. Larger capacity did not provide a consistent whole-workload gain.
With a single packet per socket, batch 32 still required one receive call
per packet and increased whole-workload cost by about 30%. Three runs in a
shared VM include scheduling noise; the mixed cells must remain visible.

The 1,200-byte receive arena grows from 1,200 bytes for the baseline to
9,600 bytes for batch 8 and 38,400 bytes for batch 32. The corresponding
preallocated header structures add 696 and 2,616 bytes, excluding allocator
overhead. Actual server support for full UDP datagrams would need a larger
arena or another deliberate buffer strategy.

The experiment remains outside the runtime. It identifies queue occupancy
as a requirement for a useful batching path; it does not establish that
spry-turn should batch every allocation or that the server became faster.

## Default and portable builds on Linux

The portable trial compares two builds of the **same 0.2.1 runtime and
loader source**, alongside unmodified coturn. Both spry builds include TLS
and the stream-interest optimisation. The default build also enables
`connected-udp` and `direct-index`; the portable build enables only
`runtime,turn,tls`. The receipt calls the portable variant `spry-baseline`
because that is the comparison script's optional second-binary label.
It is not the historical 0.2.0 source baseline.

The [build identities](evidence/linux-variants-0.2.1.json) record identical
release settings, generic aarch64 targets and unset `RUSTFLAGS`. Both
executables are 1,381,008 bytes. The original default executable and loader
were copied and hash-verified before rebuilding in the same target tree.

The [27 socket runs](evidence/linux-portable-0.2.1.json) completed
10,830,224 forwarded packets without an observed payload error. Each run
uses 128 allocations, four load workers, 1,200-byte payloads and an
8-packet window per worker. The throughput phase completes at least
200,000 round trips and lasts at least two seconds. Fresh server order
alternates across three repetitions per transport and variant.

These measurements ran in a two-vCPU, 2 GiB container inside a configured
4 GiB Docker Desktop LinuxKit VM. Existing physical-host workloads remained
running. This is a constrained VM observation, not isolated Linux hardware
performance. The ranges below retain the substantial variation between
repetitions; all rates are delivered forwarded packets per second.

| Client transport | Default median (range) | Portable median (range) | coturn median (range) |
|---|---:|---:|---:|
| UDP | 86,149 (68,986–121,028) | 67,539 (53,104–87,014) | 84,155 (83,311–212,893) |
| TCP | 127,926 (100,460–137,656) | 91,631 (77,892–96,418) | 103,053 (72,228–103,106) |
| TLS | 54,373 (39,376–82,748) | 45,436 (44,015–73,021) | 42,366 (31,027–47,489) |

All three medians favour the default in this trial. The wide ranges and
shared VM do not establish that feature selection caused those differences.
There is no measured case here for changing the shipped runtime to the
portable variant.

The descriptor trade-off is concrete. At 128 UDP allocations, the default
holds 257 UDP sockets and 262 descriptors, against 129 sockets and
134 descriptors for the portable build. Median process RSS is about
2.732 MB and 2.740 MB respectively. Quiescent Linux `ss` counter `f`
reports 1,052,672 and 528,384 bytes; it is one socket-memory accounting
field, not total kernel memory. The corresponding summed `rb` buffer
ceilings are about 54.9 MB and 27.6 MB: these are configured limits, not
resident allocations. TCP/TLS allocation socket counts are the same in
both builds. Neither the similar RSS nor these individual counters prove
equal total system memory.

To reproduce, preserve the first build before selecting portable features.
Use the checkout's existing target tree and a locally prepared coturn
reference as described in [the main comparison](benchmarks.md#reproduce).

```sh
cargo build --locked --release --target aarch64-unknown-linux-gnu \
  --features tls --bin spry-turn --example load
mkdir -p .local/variants
cp target/aarch64-unknown-linux-gnu/release/spry-turn .local/variants/spry-default
cp target/aarch64-unknown-linux-gnu/release/examples/load .local/variants/load
cargo build --locked --release --target aarch64-unknown-linux-gnu \
  --no-default-features --features runtime,turn,tls --bin spry-turn
cp target/aarch64-unknown-linux-gnu/release/spry-turn .local/variants/spry-portable
python3 scripts/compare.py \
  --spry .local/variants/spry-default --baseline .local/variants/spry-portable \
  --loader .local/variants/load \
  --coturn .local/reference/coturn-4.18.0/bin/turnserver \
  --required-arch arm64 --runs 3 --clients 128 --sizes 1200 \
  --transports udp tcp tls --window 8 --min-seconds 2 --packets 200000 \
  --output .local/linux-portable.json
```

## Independent process scaling

The [worker experiment receipt](evidence/linux-workers-0.2.1.json) compares
one and two independently addressed default spry-turn processes, then
repeats the same comparison with coturn. It adds no worker feature to the
server. The total workload remains 128 allocations and four load workers:
two processes receive 64 allocations and two workers each, with disjoint
relay-port ranges. Both servers use one relay event loop per process.

A readiness barrier releases the generators after all server probes pass.
Each generator then performs its own allocation setup, warm-up and
sequential latency sampling. Throughput phases are therefore not perfectly
aligned. The tool estimates each phase end from the arrival of its flushed
result line and subtracts the generator's reported duration for its start.
Aggregate rate divides all delivered packets by the enclosing interval
across those phases. It does not sum the individual process rates. Pipe
and scheduling delays introduce timing uncertainty; the receipt records
each estimated interval and its overlap.

Twelve groups, comprising 18 server-process runs, completed 6,422,416
forwarded packets without an observed payload error. The workload uses
UDP, 1,200-byte payloads and window 8, with three repetitions of each
server/process-count case. Each process receives its share of 200,000
minimum round trips and runs its throughput
phase for at least three seconds. The VM and container limits are the same
as the portable trial above.

| Server | Processes | Estimated aggregate median packets/s | Range |
|---|---:|---:|---:|
| spry-turn | 1 | 137,795 | 129,886–138,317 |
| spry-turn | 2 | 167,677 | 140,077–257,081 |
| coturn | 1 | 94,876 | 88,071–178,757 |
| coturn | 2 | 270,221 | 135,910–275,201 |

Two-process phase overlap is 92.8–99.7% for spry-turn and 80.8–98.9% for
coturn. These variable VM samples do not establish linear scaling or a
stable comparative advantage. Separately addressed processes also need
explicit client distribution; this experiment supplies no shared listener,
automatic failover or maximum-capacity result.

For spry-turn, the median sum of individual post-phase process RSS
snapshots grows from 2.736 MB to 5.329 MB. Descriptor counts grow from
262 to 268 and UDP sockets from 257 to 258. Those snapshots are not a
simultaneous whole-system peak. The summed `f` socket-memory counter grows
from 1,052,672 to 1,056,768 bytes; other kernel allocation structures remain
outside that counter. Complete server CPU time is 1.929 s and 2.381 s,
including startup and resource inspection. The duration floor produces
different delivered packet counts, so these CPU totals alone do not measure
CPU efficiency at equal work.

Use the preserved default executable and loader from the build commands
above. The [script](../scripts/worker-scaling.py) refuses to overwrite an
existing evidence file and stops its own server and generator processes
on completion or failure.

```sh
python3 scripts/worker-scaling.py \
  --spry .local/variants/spry-default --loader .local/variants/load \
  --coturn .local/reference/coturn-4.18.0/bin/turnserver \
  --required-arch arm64 --processes 1 2 --runs 3 \
  --clients 128 --workers 4 --packets 200000 \
  --size 1200 --window 8 --min-seconds 3 \
  --output .local/linux-workers.json
```

## Profile-guided optimisation

The [M4 PGO comparison](evidence/m4-pgo-0.2.1.json) uses the same source,
release settings and TLS feature as the ordinary build. Only the profile
compiler flags differ. A finite Rust embedding host trains the actual
server library with generated UDP/TCP/TLS traffic at both payload sizes,
then exits normally so LLVM can write its counters. Training covers six
workloads with 16 allocations. The profile is checked for nonzero execution
counters before use.

The 27-run comparison uses 128 allocations, 1,200-byte payloads, window 8,
three repetitions and the same duration/count floors as the main runner.
All runs passed payload checks. The receipt's `spry-turn` label means the
experimental PGO build; `spry-baseline` is the ordinary v0.2.1 release build.

| Client transport | Ordinary release packets/s | PGO packets/s | Difference |
|---|---:|---:|---:|
| UDP | 282,300 | 286,885 | +1.6% |
| TCP | 315,054 | 317,897 | +0.9% |
| TLS | 270,745 | 273,211 | +0.9% |

Those small median changes are within the scale of run variation; the
experiment does not establish a worthwhile general throughput gain. The
executable shrinks from 1,197,760 to 1,181,520 bytes. The shipping artefact
remains the ordinary release build, which does not depend on a workload
profile or a particular training machine. A different representative
workload or larger repeated study could justify revisiting that choice.

The [training receipt](evidence/pgo-training-0.2.1.json) and
[build/profile identity](evidence/qualification-builds-0.2.1.json) identify
the training host, loader, merged profile and compiler settings.
The first continuous-profile attempt produced files whose counters were
all zero. They were rejected, and no rates based on that profile are used
here. The finite host produced six raw files with a merged total count of
166,916,851 and maximum function count of 14,045,496. Compiler warnings
for unexercised functions are retained locally; this training is not full
path coverage or correctness qualification. A 32-packet-window attempt
also encountered coturn congestion; its partial receipt is linked from
the [main qualification](qualification-0.2.1.md#linux-arm64-virtual-machine).

Follow the [Rust PGO workflow](https://doc.rust-lang.org/rustc/profile-guided-optimization.html)
with the matching toolchain's `llvm-profdata`. Use a fresh private profile
directory and the checkout's existing target tree. Preserve the ordinary
server and loader before instrumentation, as in the portable experiment.
For example, on native Apple ARM64:

```sh
rustup component add llvm-tools-preview
mkdir .local/pgo
SPRY_PGO_DIR="$(pwd)/.local/pgo"
SPRY_LLVM_PROFDATA="$(rustc --print target-libdir)/../bin/llvm-profdata"
RUSTFLAGS="-Cprofile-generate=$SPRY_PGO_DIR" \
  cargo build --locked --release --target aarch64-apple-darwin \
  --features tls --example profile_server
LLVM_PROFILE_FILE="$SPRY_PGO_DIR/%p.profraw" \
  python3 scripts/train-pgo.py \
  --server target/aarch64-apple-darwin/release/examples/profile_server \
  --loader .local/variants/load --profile-dir "$SPRY_PGO_DIR" \
  --profdata-tool "$SPRY_LLVM_PROFDATA" --output .local/pgo-training.json
RUSTFLAGS="-Cprofile-use=$SPRY_PGO_DIR/merged.profdata -Cllvm-args=-pgo-warn-missing-function" \
  cargo build --locked --release --target aarch64-apple-darwin \
  --features tls --bin spry-turn
```

All other compiler flags must match between instrumentation and profile
use; keep any path-remapping flags in both stages. The finite host is
restricted to loopback and generated test credentials. Profiles and raw
logs remain private scratch. Compare the resulting binary against the
preserved ordinary build with the same native loader; it is still a
closed-loop workload rather than maximum network capacity.
