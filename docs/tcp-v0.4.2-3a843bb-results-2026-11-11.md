# v0.4.2 singleton-path qualification attempt, 11 November 2026

**Failed: do not adopt this candidate on this evidence.** Two sparse TCP
pairs exceeded the frozen absolute CPU overhead guard. All 48 rows and five
baseline pilots remain in the [complete scalar receipt](evidence/tcp-v0.4.2-3a843bb-qualification-2026-11-11.json).

- Workflow: [43006992593](https://github.com/forgesworn/spry-turn/actions/runs/43006992593), first attempt, 27 minutes 11 seconds.
- Baseline: `56232d52f0fbfd2f3795a50917890ed6c85e6dc9`.
- Candidate: `3a843bbf1c0786bf91b5ca423e94e2526e567c2c`.
- The singleton peer-return path now sends the first admitted frame immediately; batch setup begins only after a second return. Large first frames borrow empty storage only when necessary. This actual source change followed the [failed abff8fa campaign](tcp-v0.4.2-abff8fa-results-2026-11-11.md).
- The [protocol](tcp-hosted-qualification-2026-11-11.md), loader, comparison code, thresholds and balanced pair order were unchanged. There was no unchanged timing retry.
- All host-validity and individual row guards passed. The failure is a performance guard. All 80,457,216 expected forwards were verified, and no sparse dispatch slots were missed.

Values below are median paired candidate/baseline changes. CPU is server
lifetime user+system CPU per verified forward, including startup, setup,
warm-up and probes. Retained RSS is sampled after throughput; peak RSS is a
separate 50-ms sampling series. Neither represents complete kernel memory.

| Profile | Useful throughput | CPU per verified forward | Retained RSS | Sampled peak RSS |
| --- | ---: | ---: | ---: | ---: |
| TCP 128 clients, 1,200 B, window 8 | +53.61% | -34.76% | -0.74% | -0.74% |
| TCP 512 clients, 1,200 B, window 8 | +35.30% | -25.83% | +1.03% | +1.03% |
| UDP 128 clients, 1,200 B, window 8 | -0.60% | +0.55% | -1.10% | -1.10% |
| TLS 16 clients, 1,200 B, window 8 | -0.46% | +0.49% | -0.64% | -0.64% |
| TCP one client, 160 B, window 1 | -0.09% | +0.48% | +1.57% | +1.57% |

Sparse TCP used one client, 160-byte packets, window 1 and 4,000 round trips
at 500/s. Its CPU quantity divides lifetime server CPU by the offered-phase
duration: it is normalised lifetime overhead, not isolated sparse-phase
utilisation. Each pair below was retained.

| Pair | Parent lifetime CPU | Candidate lifetime CPU | One-core CPU difference |
| --- | ---: | ---: | ---: |
| 1 | 0.298856 s | 0.316452 s | +0.220009 percentage points — fail |
| 2 | 0.323475 s | 0.295717 s | -0.347039 percentage points |
| 3 | 0.306225 s | 0.298350 s | -0.098453 percentage points |
| 4 | 0.279374 s | 0.306061 s | +0.333664 percentage points — fail |

The permitted per-pair increase was 0.2 percentage points. The median increase
was 0.060778 points; a passing median cannot replace the failed pair guards.
Scheduled p99 changed by median -1.19% (-2.70 microseconds), with worst ratio
1.1014; all latency guards passed. Sparse retained/peak RSS rose by median
5.04% (133,120 bytes), within the frozen 262,144-byte absolute tolerance.
Loaded single-client throughput's worst pair was -0.83%, and its CPU worst
pair was +1.70%. UDP and TLS median throughput/CPU regressions are retained
in the table despite passing their guards. Loaded closed-loop p99 is recorded
in the receipt but has no acceptance guard; no loaded-latency claim follows.

The runner exposed four AMD EPYC 7763 CPUs, Ubuntu image 20261101.360.1,
kernel 7.0.0-1017-azure and Rust 1.94.1. Host checks are bounded observations,
not a bare-metal guarantee. All row, host and six profile results were
independently recomputed from the saved receipt and matched exactly.

Separately, composed-tree macOS CI exposed a test assumption that an 8 KiB
peer frame must always drop after an earlier socket WouldBlock. Commit
`0a21eda8f8291fa5041230d6df181f6f8d26c235` changed only that `cfg(test)` function:
it sends a bounded non-reading burst until an actual drop, verifies queue
ownership and counters, drains every admitted frame intact, then proves
recovery. It keeps both ChannelData and DATA-indication paths. The original
failure was `turn::policy_tests::relay_overload_preserves_stream_and_resumes_both_framing_paths`,
at `src/turn.rs:2108`, on PR run 43006978284, job 130476775000, exit 101:
“retry may flush old bytes, but drop cannot truncate or partly queue a new frame”.
The queued-data assertion alone did not establish runtime corruption.
All source outside that one test, plus loader/harness/imported interop helpers,
protocol and workflow, was verified byte-identical to the measured commit.
The corrected test's normal local hook, fresh Linux/macOS CI, and all existing
native/Android release matrix jobs passed. No extra timing campaign was run
for this test-only correction.

The earlier passing receipt and both failed receipts remain separate and
unchanged. These measurements do not establish a cause for the sparse CPU
variation or justify weakening the guard. Release publication remains held.
