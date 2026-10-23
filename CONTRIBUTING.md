# Contributing

Read [AGENTS.md](AGENTS.md) and [GOALS.md](GOALS.md). Keep the forwarding core
small, safe Rust and independent of media, application admission and hosted
services. Keep the repository, prerelease and fixtures private unless the
owner explicitly authorises public publication.

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
npm run check
cargo build --locked --release --features tls
python3 tests/interop.py --tls
npm ci --ignore-scripts
npx playwright install chromium
python3 tests/browser.py --tls
```

`npm run check` runs documentation validation, Rust formatting, clippy with
warnings denied, all-feature tests and both minimal library test sets.
Python orchestrates independent test sockets and browser fixtures; the
shipping server, library and socket load generator are Rust.

For WASM build and actual execution, use [the API commands](docs/api.md#wasm-build).
Run an appropriate credential/source scan before pushing; never suppress a
finding without inspecting and resolving its cause. Current CI runs native
checks and interop on Linux/macOS and builds the WASM codec on Linux.

## Performance and cleanup

Performance claims require matched executable architectures, real socket
workloads, alternating server order and disclosed resource costs. Use
[the existing benchmark method](docs/benchmarks.md); a framing microbenchmark
cannot establish network throughput. Preserve raw failure evidence alongside
successful runs and do not confuse loopback with production acceptance.

Stop task-owned servers and browsers and remove their fixtures. After a
safe merge, remove only build/scratch resources created by that task.
Preserve the explicitly named benchmark and verification evidence.
