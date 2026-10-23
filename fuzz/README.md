# Coverage-guided parser qualification

This development-only crate uses libFuzzer with AddressSanitizer. The release
server and WASM module do not depend on it. The target exercises borrowed STUN
attributes, integrity verification, malformed ChannelData and stream lengths,
address codecs, credentials and stateless nonces. Structured round trips keep
valid-message branches reachable alongside malformed input mutation.

Run from the repository root with cargo-fuzz and a compatible nightly installed:

```sh
python3 tests/fuzz.py --toolchain nightly --seconds 300 --seed 7411
```

The wrapper explicitly reuses this checkout's `target/`; do not set a new
`CARGO_TARGET_DIR`. It checks the isolated `fuzz/Cargo.lock`, seeds generated
fixtures, bounds execution and memory, and writes `.local/fuzz/receipt.json`.
Coverage, features, executed inputs and crash counts come from the actual
libFuzzer run. The detailed log, evolved corpus and any failure artefacts stay
under ignored `.local/fuzz/`. Preserve crash inputs for investigation; remove
task-owned generated data after recorded successful runs.

This is one in-process parser/auth target. It does not fuzz the socket runtime,
prove full RFC conformance, or replace independent security review.
