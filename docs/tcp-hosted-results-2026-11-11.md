# Hosted TCP qualification result, 11 November 2026

**All predeclared guards passed in one campaign.** The candidate reduced server
CPU per verified forward in the two loaded TCP profiles. UDP, TLS, one-client
TCP and fixed-schedule sparse TCP stayed within the declared control bounds.
There is no material RSS improvement against current main in these measurements.

- [Workflow run 42981845140](https://github.com/forgesworn/spry-turn/actions/runs/42981845140), first attempt, 20 minutes 47 seconds.
- Parent: `56232d52f0fbfd2f3795a50917890ed6c85e6dc9`.
- Measured candidate: `cb430e7ff54a83c2a0a2c6fa451013c6524dc21d`, incorporating the final fatal-flush accounting fix.
- The follow-up `d621bf2` adds the guard tests to ordinary checks/CI; its runtime,
  loader, comparison scripts and qualification workflow are byte-identical to
  the measured revision.
- [Frozen protocol](tcp-hosted-qualification-2026-11-11.md) and
  [complete scalar receipt](evidence/tcp-hosted-qualification-2026-11-11.json).

The final workflow is manual-only on any selected ref, with checkout pinned
and Rust selected explicitly at 1.94.1. Those automation changes do not alter
the measured runtime, loader or Python comparison code and do not trigger a
second campaign. Ordinary checks continue to exercise the qualification guards.

The receipt retains all five parent-only pilots and all 48 paired rows, including
adverse values. The pilots froze each loaded profile at 1,000,000 round trips;
the sparse profile used 4,000 trips at 500/s. The final comparisons checked
**80,457,216 useful forwards**, including warm-up and latency probes. No row was
replaced, no threshold changed and no second campaign was run to obtain a pass.

## Paired results

Values are median candidate/parent changes. CPU is server lifetime user+system
CPU divided by all verified forwards, including setup and probes. Retained RSS
is sampled after the throughput phase; peak RSS is measured separately at
50-ms intervals. Both exclude complete kernel memory attribution.

| Profile | Useful throughput | CPU per verified forward | Retained RSS | Sampled peak RSS |
| --- | ---: | ---: | ---: | ---: |
| TCP 128 clients, 1,200 B, window 8 | +55.5% | -35.6% | -0.4% | -0.4% |
| TCP 512 clients, 1,200 B, window 8 | +42.7% | -29.8% | +1.4% | +1.4% |
| UDP 128 clients, 1,200 B, window 8 | -0.1% | +0.2% | -1.5% | -1.5% |
| TLS 16 clients, 1,200 B, window 8 | +0.6% | -0.7% | +0.1% | +0.1% |
| TCP one client, 160 B, window 1 | -1.2% | -0.2% | -0.7% | -0.7% |

The worst loaded TCP CPU ratios were 0.656 and 0.707. The worst one-client
throughput ratio was 0.981, inside its 0.85 per-pair guard; its median 0.988 was
inside the 0.97 guard. These small adverse control values remain in the result.
The optimisation is supported by the loaded CPU and throughput gains, not by
a memory-saving claim.

Sparse scheduled p99 changed by median **+0.4% (+0.91 microseconds)**. The worst
paired ratio was 1.129, inside the declared guard. The maximum absolute sparse
CPU increase was **0.109 percentage points of one core**, below the 0.2-point
bound. This normalises lifetime server CPU by the offered phase duration; it
does not isolate only the sparse phase. Closed-loop loaded p99 is retained as
diagnostic data and does not establish equal-offered-rate loaded latency.

## Host validity and limits

The hosted runner exposed four CPUs on an Intel Xeon Platinum 8370C, Linux
`7.0.0-1017-azure`, Ubuntu image `20261101.360.1`, with Rust 1.94.1. Every
pre-run idle and active-steal guard passed. The maximum pre-run host busy
fraction was 1.59%; measured steal was zero. Idle sleep overshoot p99 stayed
below 0.356 ms and its maximum below 0.511 ms. The shortest loaded wall/CPU
intervals were 8.818/8.912 seconds. Every sparse row met all 4,000 scheduled
sends without a missed interval; scheduled p99 ranged from 228 to 267 microseconds.

This is a same-runner loopback qualification with pinned executables and equal
useful work, plus a bounded sparse offered schedule. A hosted VM is not proof
of bare-metal isolation. The result does not establish WAN capacity, energy
savings, 8,192-byte throughput, fixed-rate loaded latency or continuous peer
receive fairness. The existing receive loop still drains until `WouldBlock`;
16 frames/16 KiB bounds each output batch rather than dispatch duration.

The earlier contended M1 results remain retained separately and are not combined
with this campaign. Local full checks and cross-platform ordinary CI also
passed; performance acceptance is limited to this protocol and its tolerances.
