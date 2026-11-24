# Qualification of the peer-policy and control-budget change, 24 November 2026

**Both hosted runs failed guards. The owner accepted the change on
24 November 2026 with these results disclosed; neither result was relabelled
or rerun to pass.** The change restricts IPv6 peers to global unicast and
gives each client with an allocation its own control-request budget. It does
not touch the payload path (ChannelData, Send and Data indications).

- Candidate: `e63bca75aa83c4d961dc577c785dc626c728c521`.
- The [protocol](tcp-hosted-qualification-2026-11-11.md), loader, comparison
  code and thresholds were unchanged. Each comparison was dispatched once.
- Runner: the same shared hosted class as the earlier campaigns.

## Against the pre-batching baseline

[Workflow 45367982612](https://github.com/forgesworn/spry-turn/actions/runs/45367982612),
baseline `56232d52f0fbfd2f3795a50917890ed6c85e6dc9`, the baseline of every
earlier campaign. **Failed the sparse CPU guard.**
[Complete receipt](evidence/tcp-pr63-e63bca7-vs-pre-batching-2026-11-24.json).

| Profile | Useful throughput | CPU per verified forward | Retained RSS | Sampled peak RSS |
| --- | ---: | ---: | ---: | ---: |
| TCP 128 clients, 1,200 B, window 8 | +52.25% | -34.20% | +1.76% | +1.76% |
| TCP 512 clients, 1,200 B, window 8 | +35.34% | -25.91% | +1.26% | +1.26% |
| UDP 128 clients, 1,200 B, window 8 | -0.67% | +0.66% | +1.19% | +1.19% |
| TLS 16 clients, 1,200 B, window 8 | -2.54% | +2.61% | +1.78% | +1.78% |
| TCP one client, 160 B, window 1 | -0.40% | +0.97% | +2.58% | +2.58% |

Sparse TCP one-core CPU difference per pair, limit 0.2 percentage points:
+0.218895 (fail), -0.177571, -0.086752, +0.261681 (fail).

## Against `main`

[Workflow 45372857384](https://github.com/forgesworn/spry-turn/actions/runs/45372857384),
baseline `ed5a525e3ed603e05e9b71012f1a3588cd961c1d` (`main` before the
change). This isolates the change itself. **Failed the sparse CPU guard and
the memory guard on the 512-client profile.** It also reports "no predeclared
loaded TCP benefit": the harness qualifies a speed-up, and this change is not
one.
[Complete receipt](evidence/tcp-pr63-e63bca7-vs-main-2026-11-24.json).

| Profile | Useful throughput | CPU per verified forward | Retained RSS | Sampled peak RSS |
| --- | ---: | ---: | ---: | ---: |
| TCP 128 clients, 1,200 B, window 8 | +0.33% | -0.09% | +0.05% | +0.05% |
| TCP 512 clients, 1,200 B, window 8 | -0.06% | -0.00% | -0.99% | -0.99% |
| UDP 128 clients, 1,200 B, window 8 | +0.28% | -0.28% | -3.79% | -3.79% |
| TLS 16 clients, 1,200 B, window 8 | -0.00% | -0.02% | -2.15% | -2.15% |
| TCP one client, 160 B, window 1 | -0.40% | +0.79% | -2.20% | -2.20% |

Sparse TCP one-core CPU difference per pair: +0.104204, +0.399006 (fail),
-0.140449, -0.002110.

Retained RSS on the 512-client profile, candidate over baseline per pair:
0.9714, 0.9762, 1.1552 (fail: limit 1.15, +2,289,664 bytes), 1.0039. The
median fell by 0.99%.

## What this does and does not show

Loaded throughput and CPU are flat against `main` on every profile. The
change adds 32 bytes to each allocation, about 16 KB across 512 clients, so
it does not account for a 2.3 MB difference in one pair. The sparse pairs
swing in both directions by more than the limit, as in every hosted campaign,
including [one](tcp-main-cd9d027-results-2026-11-24.md) that passed on
effectively the same forwarding code.

That reading is an interpretation. The guards failed, shared hardware cannot
separate these effects from host noise, and the bare-metal qualification in
[the goals](../GOALS.md) remains the place to settle it. The owner accepted
the change knowing this, because it closes weaknesses in peer policy and
control-request fairness without altering the payload path.
