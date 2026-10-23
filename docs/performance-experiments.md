# Performance experiments

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
