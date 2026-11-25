# Qualification of the request-budget change, 25 November 2026

**Both hosted runs failed the sparse CPU guard. The owner accepted the change
on 25 November 2026 with these results disclosed; neither result was
relabelled or rerun to pass.** The change gives address-verified sources and other UDP
sources separate control-request budgets with per-address allowances, and
shortens the relay nonce. It does not touch the payload path (ChannelData,
Send and Data indications).

- Candidate: `75d29a03aebc68288ec58bec2e90e4356c763d0a`.
- The [protocol](tcp-hosted-qualification-2026-11-11.md), loader, comparison
  code and thresholds were unchanged. Each comparison was dispatched once.
- Runner: the same shared hosted class as the earlier campaigns.
- Before dispatch, the pull request recorded that no loaded TCP benefit was
  expected and that a sparse CPU guard failure would be recorded, not rerun.

## Against `main`

[Workflow 45609517455](https://github.com/forgesworn/spry-turn/actions/runs/45609517455),
baseline `f194ddf16b8aa43773c4ced897c118fbe2463859` (`main` before the
change). This isolates the change itself. **Failed the sparse CPU guard.** It
also reports "no predeclared loaded TCP benefit": the harness qualifies a
speed-up, and this change is not one. The five loaded profiles passed every
guard.
[Complete receipt](evidence/tcp-pr75-75d29a0-vs-main-2026-11-25.json).

| Profile | Useful throughput | CPU per verified forward | Retained RSS | Sampled peak RSS |
| --- | ---: | ---: | ---: | ---: |
| TCP 128 clients, 1,200 B, window 8 | +0.24% | -0.19% | +1.15% | +1.15% |
| TCP 512 clients, 1,200 B, window 8 | +0.05% | -0.15% | -0.37% | -0.37% |
| UDP 128 clients, 1,200 B, window 8 | +0.62% | -0.61% | +0.78% | +0.78% |
| TLS 16 clients, 1,200 B, window 8 | +0.12% | -0.16% | +1.56% | +1.56% |
| TCP one client, 160 B, window 1 | -0.47% | +0.65% | +1.95% | +1.95% |

Sparse TCP one-core CPU difference per pair, limit 0.2 percentage points:
+0.231986 (fail), -0.103484, -0.104050, +0.243777 (fail).

## Against the pre-batching baseline

[Workflow 45609536954](https://github.com/forgesworn/spry-turn/actions/runs/45609536954),
baseline `56232d52f0fbfd2f3795a50917890ed6c85e6dc9`, the baseline of every
earlier campaign. **Failed the sparse CPU guard.** The five loaded profiles
passed every guard.
[Complete receipt](evidence/tcp-pr75-75d29a0-vs-pre-batching-2026-11-25.json).

| Profile | Useful throughput | CPU per verified forward | Retained RSS | Sampled peak RSS |
| --- | ---: | ---: | ---: | ---: |
| TCP 128 clients, 1,200 B, window 8 | +41.06% | -28.98% | +3.87% | +3.87% |
| TCP 512 clients, 1,200 B, window 8 | +40.42% | -28.65% | +0.22% | +0.22% |
| UDP 128 clients, 1,200 B, window 8 | -0.31% | +0.37% | +0.46% | +0.46% |
| TLS 16 clients, 1,200 B, window 8 | -1.06% | +1.05% | +0.61% | +0.61% |
| TCP one client, 160 B, window 1 | -0.10% | +0.78% | +1.31% | +1.31% |

Sparse TCP one-core CPU difference per pair: -0.153965, -0.297529,
+0.426830 (fail), -0.216312.

## What this does and does not show

Loaded throughput and CPU are flat against `main` on every profile, and
retained memory moved by less than 2%. The sparse pairs swing in both
directions by more than the limit, as in every hosted campaign.

That reading is an interpretation. The guard failed, and shared hardware
cannot separate these effects from host noise.

The harness also does not measure the new work. Its loader connects from
loopback and over TCP, which draw on the verified budget without a nonce
check. The unverified budget and the nonce check on UDP requests are covered
by unit tests only, and no per-packet cost is claimed for them. The
bare-metal qualification in [the goals](../GOALS.md) remains the place to
settle both points.
