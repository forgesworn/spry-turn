# Post-0.4.2 hosted re-run of the TCP qualification, 24 November 2026

**Passed every guard, including the sparse TCP CPU guard that both 0.4.2
campaigns failed.** This is one further hosted run. It does not withdraw the
earlier failures, it is not bare-metal evidence, and the
[0.4.2 release decision](release-v0.4.2-acceptance-2026-11-11.md) is unchanged.
All 48 rows and five baseline pilots remain in the
[complete scalar receipt](evidence/tcp-main-cd9d027-qualification-2026-11-24.json).

- Workflow: [45319523673](https://github.com/forgesworn/spry-turn/actions/runs/45319523673), first attempt, about 27 minutes. It was dispatched once at the owner's request and not repeated.
- Baseline: `56232d52f0fbfd2f3795a50917890ed6c85e6dc9`, as before.
- Candidate: `cd9d0271e074dc786f12b601c37909fc7d9ad9c1` (`main`). Since v0.4.2 the relay source changed only in how an ephemeral listener is bound, how PEM files are read, and where its unit tests live; the forwarding path is the 0.4.2 one.
- The [protocol](tcp-hosted-qualification-2026-11-11.md), loader, comparison code, thresholds and balanced pair order were unchanged.
- Same runner class as the 0.4.2 campaigns: a shared hosted AMD EPYC 7763 virtual machine with four pinned CPUs, on a newer runner image.

Values below are median paired candidate/baseline changes, measured as in the
[earlier results](tcp-v0.4.2-3a843bb-results-2026-11-11.md).

| Profile | Useful throughput | CPU per verified forward | Retained RSS | Sampled peak RSS |
| --- | ---: | ---: | ---: | ---: |
| TCP 128 clients, 1,200 B, window 8 | +53.04% | -34.49% | +0.84% | +0.84% |
| TCP 512 clients, 1,200 B, window 8 | +36.10% | -26.35% | +0.81% | +0.81% |
| UDP 128 clients, 1,200 B, window 8 | -0.44% | +0.46% | +2.29% | +2.29% |
| TLS 16 clients, 1,200 B, window 8 | -1.13% | +1.20% | +0.00% | +0.00% |
| TCP one client, 160 B, window 1 | +0.09% | -0.30% | +3.24% | +3.24% |

Sparse TCP, one client at 500 round trips a second. The permitted per-pair
increase is 0.2 percentage points of one core.

| Pair | One-core CPU difference |
| --- | ---: |
| 1 | -0.012574 percentage points |
| 2 | +0.034074 percentage points |
| 3 | +0.091282 percentage points |
| 4 | -0.242282 percentage points |

The largest increase was 0.091282 points and the median 0.010750.

## What this does and does not show

The [3a843bb campaign](tcp-v0.4.2-3a843bb-results-2026-11-11.md) and this one
share the forwarding path. Their eight sparse pair differences range from
-0.347 to +0.334 points. That spread
is wider than the 0.2-point limit in both directions, which is consistent with
the [mechanism audit](sparse-cpu-mechanism-results-2026-11-11.md) finding no
source cause while being unable to exclude host noise. One pass no more proves
the candidate than the earlier failures proved a regression. The question
stays open until the independent bare-metal qualification listed in
[the goals](../GOALS.md).
