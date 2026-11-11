# v0.4.2 prerelease acceptance, 11 November 2026

The owner explicitly instructed: **“Publish Spry prerelease with documented
tradeoff”**, after disclosure that two valid final-source campaigns failed
the frozen sparse TCP CPU guard. This authorises the existing GitHub
prerelease channel; it does not change the measurement result or authorise a
hosted relay deployment.

The final runtime candidate was `3a843bbf1c0786bf91b5ca423e94e2526e567c2c`,
compared with baseline `56232d52f0fbfd2f3795a50917890ed6c85e6dc9` using the
unchanged protocol. All 48 rows and five pilots completed. With 128 and 512
clients, 1,200-byte packets and window 8, median paired throughput improved
53.61% and 35.30%; lifetime server CPU per verified forward fell 34.76% and
25.83%. Both sparse CPU pair failures remain binding measurement failures:
+0.220009 and +0.333664 percentage points of one core versus a +0.2-point
limit. All host-validity, work-integrity, scheduled-latency, loaded/control
and memory guards passed. The CPU quantity includes startup, setup, warm-up
and probes normalised by the offered sparse phase; it is not isolated
sparse-phase utilisation. No cause for the variation is established.

The owner accepted these disclosed limits for this prerelease. The reports
below retain the original publication hold at the time of each failed
measurement; this later explicit decision resolves that hold without
altering their receipts or thresholds:

- [First final-source failure and full receipt](tcp-v0.4.2-abff8fa-results-2026-11-11.md).
- [Singleton-path failure and full receipt](tcp-v0.4.2-3a843bb-results-2026-11-11.md).
- [Frozen protocol and guards](tcp-hosted-qualification-2026-11-11.md).

Commit `0a21eda8f8291fa5041230d6df181f6f8d26c235` subsequently corrected one
`cfg(test)` overload fixture. All source outside that test and every loader,
harness, imported interop helper, protocol and workflow byte remained
unchanged from the measured candidate. Later release-decision edits are
documentation only. No further performance campaign was run to turn the
failed guards green.

Ordinary correctness and release-platform checks still apply to the exact
composed source. Tagged archives must retain exact source identity,
checksums, licence notices and build provenance before publication. The
benchmark used Rust 1.94.1 on an AMD EPYC 7763 GitHub-hosted Linux runner;
release provenance records each actual compiler and build profile. Source
equivalence does not establish identical timing for release binaries built
with another compiler, target or flags. No WAN, production capacity,
loaded fixed-rate latency, energy or material memory improvement is claimed.
