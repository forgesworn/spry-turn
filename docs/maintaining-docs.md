# Maintaining documentation and discovery

Maintained source lives in the Markdown guides linked from
[the documentation index](README.md). `scripts/docs.mjs` owns the catalogue,
generates both LLM files and checks all tracked Markdown/TXT navigation.
The generator uses Node built-ins; it adds no server runtime dependency.

## Edit, generate, check

1. Update the relevant source guide and any changed examples or limitations.
2. Add a new primary guide to the catalogue in `scripts/docs.mjs` and the
   documentation index.
3. Run `npm run docs:generate`, then `npm run check:docs`.
4. Commit source and generated files together. CI rejects stale output,
   missing local files, broken local heading fragments and mismatched
   donation destinations.

`llms.txt` is a concise Markdown navigation file following
[the llms.txt proposal](https://llmstxt.org/). `llms-full.txt` bundles the
maintained guides using canonical absolute GitHub links. Both carry the
version and important implementation/qualification boundaries. Raw benchmark
JSON, dependency licence dumps, machine paths and ignored fixtures are not
bundled. Generated links use the canonical `forgesworn/spry-turn` repository.

The checker is deterministic and offline. It validates repository links
and fragments, not external site availability or GitHub rendering of a
Sponsor button. Recheck external donation pages when changing recipients.

## Repository metadata and privacy

Keep the GitHub description, repository topics, Cargo description, keywords
and documentation URL accurate. `publish = false` and npm's `private: true`
continue to block package publication. The public repository's root
`llms.txt` provides navigation for readers and tools.
There is no claim of search-engine ranking, model training inclusion or
guaranteed ingestion.

The owner authorised public MIT source and the existing GitHub prereleases
on 23 October 2026. Source history, fixtures and release artefacts were checked
for secrets and private paths before changing visibility; tags and archive
bytes were retained. A public Pages site, package registries and hosted relay
operation remain separate scope. Donation links are informational
and never grant transport or application access.

## Ship checklist

Run [the required checks](../CONTRIBUTING.md), inspect the staged diff and
scan for secrets. Push a branch, merge its reviewed PR only after Linux/macOS
CI succeeds, then verify the merged head. Tag the reviewed commit and make
the GitHub release a prerelease while qualification remains incomplete. Verify the tag target, release
visibility and any downloaded asset checksums. Public packages, images,
Pages and a running TURN service require their own explicit scope.

Release builds must remap the builder's home-directory prefix before
packaging, so panic/source strings do not disclose private machine paths.
For example, supply `RUSTFLAGS="--remap-path-prefix=$HOME=/build"` to each
native and WASM release build. Scan the resulting binaries as well as
source. Include the MIT licence, dependency notices and a platform/scope
README in archives; publish SHA-256 checksums and a source-commit receipt.
