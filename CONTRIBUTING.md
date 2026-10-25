# Contributing

Read [AGENTS.md](AGENTS.md) and [GOALS.md](GOALS.md). Keep the forwarding core
small, safe Rust and independent of media, application admission and hosted
services. Source and GitHub prereleases are public. Keep test fixtures
generated and free of private endpoints, credentials and media.

Use synthetic peers, credentials and media. Do not commit private endpoints,
real machine paths, keys or packet captures. Use this checkout's `target/`
and leave `CARGO_INCREMENTAL` unchanged.

## Documentation

```sh
npm run docs:generate
npm run check:docs
```

These commands use Node 24 built-ins, without `npm install`. Edit source
guides rather than generated `llms.txt` or `llms-full.txt`. The checker
validates generated context, local links, heading anchors and funding
destinations. See [maintaining documentation](docs/maintaining-docs.md).

## Native checks

```sh
cargo build --locked --release --features tls
SPRY_TEST_RELAY_BINARY=target/release/spry-turn npm run check
python3 tests/interop.py --tls
python3 tests/stress.py --tls --seconds 180 --output .local/stress.json
npm ci --ignore-scripts
npx playwright install chromium
python3 tests/browser.py --tls
```

`npm run check` runs documentation validation, Rust formatting, clippy with
warnings denied, all-feature tests and both minimal library test sets.
Build the release relay first: the service integration tests start that real
executable on generated loopback ports, obtain public credentials and verify
authenticated allocations. `SPRY_TEST_RELAY_BINARY` may select another build
from the same source tree; it is resolved relative to the workspace root.
An absent executable fails clearly rather than skipping the protocol checks.
The stress runner caps normal control traffic below admission limits and
tests a separate overload burst, expiry, churn and slow-client recovery.
Its seeded loss/jitter proxy is local qualification. A short soak and
coarse RSS samples do not prove absence of leaks or WAN acceptance.

Python orchestrates independent test sockets and browser fixtures; the
shipping server, library and socket load generator are Rust.

For coverage-guided ASan parser/auth fuzzing:

```sh
rustup toolchain install nightly-2025-12-05 --profile minimal
cargo install cargo-fuzz --version 0.13.2 --locked
python3 tests/fuzz.py --toolchain nightly-2025-12-05 --seconds 300 \
  --output .local/fuzz/receipt.json
```

The isolated [fuzz target](fuzz/README.md) has no effect on shipping
dependencies and reuses the checkout's `target/`. Its corpus and logs stay
under ignored `.local/fuzz/`. CI runs a bounded 30-second campaign; longer
manual runs are separate evidence. Test the actual KithMoot application with
the [operator acceptance runner](docs/kithmoot-acceptance.md).

For WASM build and actual execution, use [the API commands](docs/api.md#wasm-build).
Run an appropriate credential/source scan before pushing; never suppress a
finding without inspecting and resolving its cause. Current CI runs native
checks and interop on Linux/macOS and builds the WASM codec on Linux.

## Performance and cleanup

Performance claims require matched executable architectures, real socket
workloads, alternating server order and disclosed resource costs. Use
[the current benchmark method](docs/qualification-0.2.1.md); a framing microbenchmark
cannot establish network throughput. Preserve raw failure evidence alongside
successful runs and do not confuse loopback with production acceptance.

Stop task-owned servers and browsers and remove their fixtures. After a
safe merge, remove only build/scratch resources created by that task.
Preserve the explicitly named benchmark and verification evidence.
