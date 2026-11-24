# Coverage-guided parser qualification

This development-only crate uses libFuzzer with AddressSanitizer. The release
server and WASM module do not depend on it. There are three targets:

| Target | Outside input it exercises |
|---|---|
| `wire` | Borrowed STUN attributes, integrity verification, malformed ChannelData and stream lengths, address codecs, credentials and stateless nonces. |
| `portmap` | PCP and NAT-PMP gateway replies, SSDP search replies, UPnP device descriptions and SOAP bodies, the bounded XML and URL parsers, the saved mapping record and platform routing tables. |
| `link` | Nostr events, public adverts, peer and standard cards, pairing links and NIP-44 payloads. |

Structured round trips keep valid-message branches reachable alongside
malformed input mutation; `link` signs its own events with a generated key so
the advert and card rules behind the signature check are reached.

Run from the repository root with cargo-fuzz and a compatible nightly installed:

```sh
python3 tests/fuzz.py --toolchain nightly --seconds 300 --seed 7411
python3 tests/fuzz.py --toolchain nightly --target portmap --seconds 300
python3 tests/fuzz.py --toolchain nightly --target link --seconds 300
```

For campaigns of many minutes add `--rss-limit-mb 2048`: the fuzzer process
itself grows with its corpus and the sanitiser's quarantine, and a 20-minute
`portmap` run reached the default 768 MB with no input at fault (the reported
input replayed alone in 38 MB).

`--target` defaults to `wire`. Each target keeps its own corpus, log and
artefact directory and records the hashes of the sources it covers.

The wrapper explicitly reuses this checkout's `target/`; do not set a new
`CARGO_TARGET_DIR`. It checks the isolated `fuzz/Cargo.lock`, seeds generated
fixtures, bounds execution and memory, and writes `.local/fuzz/receipt.json`.
Coverage, features, executed inputs and crash counts come from the actual
libFuzzer run. The detailed log, evolved corpus and any failure artefacts stay
under ignored `.local/fuzz/`. Preserve crash inputs for investigation; remove
task-owned generated data after recorded successful runs.

These are in-process parser targets. They do not fuzz the socket runtime, real
routers or relays, prove full RFC conformance, or replace independent security
review.
