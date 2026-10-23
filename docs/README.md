# spry-turn documentation

spry-turn is a standalone Rust STUN/TURN server, an embeddable native relay
and a WASM packet codec. It is an initial implementation with measured
performance and explicit compatibility gaps. The repository and initial
GitHub release are private; there is no publisher-operated TURN service.

## Start here

| Task | Guide |
|---|---|
| Build and run locally | [Getting started](getting-started.md) |
| Connect WebRTC, native clients or an embedded host | [Integration](integration.md) |
| Find Rust types, Cargo features and WASM methods | [API reference](api.md) |
| Assess an existing coturn configuration | [Coturn compatibility](coturn-compatibility.md) |
| Configure addresses, credentials, TLS and resource limits | [Operations](operations.md) |
| Inspect measured M4 throughput, CPU and memory | [Benchmarks](benchmarks.md) |
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
private machine information or the raw benchmark archives. Access follows
repository visibility; no public crawling is enabled by adding these files.

Read [AGENTS.md](../AGENTS.md) before making changes. Documentation generation,
link validation and the release checklist are in
[Maintaining documentation](maintaining-docs.md).
