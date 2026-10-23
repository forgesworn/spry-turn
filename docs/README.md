# spry-turn documentation

spry-turn is a standalone Rust STUN/TURN server, an embeddable native relay
and a WASM packet codec. It is an initial implementation with measured
performance and explicit compatibility gaps. The source and GitHub prereleases are public and MIT-licensed; there is no publisher-operated TURN service.

## Start here

| Task | Guide |
|---|---|
| Build and run locally | [Getting started](getting-started.md) |
| Connect WebRTC, native clients or an embedded host | [Integration](integration.md) |
| Find Rust types, Cargo features and WASM methods | [API reference](api.md) |
| Assess an existing coturn configuration | [Coturn compatibility](coturn-compatibility.md) |
| Configure addresses, credentials, TLS and resource limits | [Operations](operations.md) |
| Inspect current throughput, latency and resource measurements | [Standalone qualification](qualification-0.2.1.md), [historical benchmarks](benchmarks.md) |
| Reproduce optional performance experiments | [Batching, process scaling and PGO](performance-experiments.md) |
| Test the actual KithMoot web client with an owner-selected relay | [KithMoot acceptance](kithmoot-acceptance.md) |
| Check what passed and what remains unqualified | [Verification](verification.md), [acceptance checklist](../GOALS.md) |
| Report bugs or support development | [Support and donations](../SUPPORT.md) |

## Project references

- [Overview and quick commands](../README.md)
- [Release history](../CHANGELOG.md)
- [Security reporting and boundaries](../SECURITY.md)
- [Contributing and validation](../CONTRIBUTING.md)
- [Architecture and legal position](legal/transport-position.md)
- [MIT licence](../LICENSE), [dependency licences](../THIRD_PARTY_LICENSES.txt)
  and [RFC data notice](../NOTICE)

## AI and coding agents

[llms.txt](../llms.txt) is the concise navigation index.
[llms-full.txt](../llms-full.txt) is generated from the current maintained
guides, with canonical absolute links. Neither includes credentials,
private machine information or the raw benchmark archives. Public navigation files do not guarantee indexing by search engines or
language models.

Read [AGENTS.md](../AGENTS.md) before making changes. Documentation generation,
link validation and the release checklist are in
[Maintaining documentation](maintaining-docs.md).
