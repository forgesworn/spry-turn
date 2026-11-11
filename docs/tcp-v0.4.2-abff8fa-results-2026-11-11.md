# v0.4.2 qualification attempt, 11 November 2026

**Failed: do not adopt this candidate on this evidence.** The sparse TCP
absolute CPU overhead guard failed in two of four pairs. All 48 measured rows
and five baseline pilots remain in the [complete scalar receipt](evidence/tcp-v0.4.2-abff8fa-qualification-2026-11-11.json).

- Workflow: [43001764304](https://github.com/forgesworn/spry-turn/actions/runs/43001764304), first attempt, 18 minutes 50 seconds.
- Baseline: `56232d52f0fbfd2f3795a50917890ed6c85e6dc9`.
- Candidate: `abff8fa04dfbe36bfa67d351afb71eb8c3b5fa39`, including the UDP deallocation ordering fix.
- The [frozen protocol](tcp-hosted-qualification-2026-11-11.md), comparison code, loader, thresholds and balanced pair order were unchanged.
- All host-validity and individual row guards passed. The failure is a performance guard, not an invalid host or incomplete campaign.

Values below are median paired candidate/baseline changes. CPU is server
lifetime user+system CPU divided by all verified forwards, including setup,
warm-up and probes. Retained RSS is sampled after throughput; sampled peak
RSS is a separate 50-ms series. Neither includes full kernel memory.

| Profile | Useful throughput | CPU per verified forward | Retained RSS | Sampled peak RSS |
| --- | ---: | ---: | ---: | ---: |
| TCP 128 clients, 1,200 B, window 8 | +51.97% | -34.02% | -2.81% | -2.81% |
| TCP 512 clients, 1,200 B, window 8 | +43.41% | -30.19% | +0.00% | +0.00% |
| UDP 128 clients, 1,200 B, window 8 | +0.29% | -0.34% | +1.39% | +1.39% |
| TLS 16 clients, 1,200 B, window 8 | +0.38% | -0.38% | +0.10% | +0.10% |
| TCP one client, 160 B, window 1 | -0.05% | +0.52% | +7.59% | +7.59% |

Sparse TCP used one client, 160-byte packets, window 1 and 4,000 round trips
at 500/s. Lifetime server CPU divided by the offered phase duration rose by
0.259 and 0.362 percentage points of one core in pairs 2 and 3, exceeding the
predeclared 0.2-point bound. The median paired increase was 0.196 points.
This is normalised lifetime overhead, not isolated sparse-phase utilisation.
Scheduled p99 changed by median -0.59% (-1.00 microseconds), with worst ratio
1.061; its guards passed. No missed sparse dispatch slots or packet corruption
were reported.

The one-client loaded throughput worst pair was -4.50%; CPU median was +0.52%.
One-client retained/peak RSS ratios rose by median 7.59%, but their median
210,944-byte increase was within the frozen 262,144-byte tolerance; sparse
RSS rose 5.73% with 161,792-byte median increase. These adverse values are kept.

The runner was an Intel Xeon Platinum 8573C, four exposed CPUs, Ubuntu image
20261101.360.1, kernel 7.0.0-1017-azure, Rust 1.94.1. It differs from the 8370C
runner in the earlier passing campaign; that does not invalidate a passed
host-validity check or permit discarding a failed performance guard.

The earlier [passing result](tcp-hosted-results-2026-11-11.md) and its receipt
remain unchanged. No attribution to the UDP teardown fix is established:
the failed workload exercises sparse TCP. No unchanged timing retry or
threshold change was used to replace this result. Release publication is held.
