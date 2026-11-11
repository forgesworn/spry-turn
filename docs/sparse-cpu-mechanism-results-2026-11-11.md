# Sparse CPU source/noise result

The [one predeclared campaign](https://github.com/forgesworn/spry-turn/actions/runs/43103230435)
completed all 24 native rows and four subsequent instruction-count rows, without
replacement, retry, corruption or missed dispatch slots. It took 19m35s.
The [complete scalar receipt](evidence/sparse-cpu-mechanism-0305df9-2026-11-11.json)
retains every observation and stable before/after input identity.

**Resolution:** this experiment does not demonstrate a material average sparse
CPU regression from v0.4.2 on this host. It does measure a small consistent
increase in whole-lifetime interpreted user instructions, alongside native CPU
variation large enough to exceed the old budget between identical executables.
There is no supported new poll, clock-read or scheduler-wakeup mechanism to fix.
Keep the existing loaded TCP improvement and the owner's accepted prerelease
trade-off; do not introduce a speculative runtime optimisation.

This resolves the present mechanism investigation, **not the failed frozen
qualification**. Its worst-pair sparse CPU bound remains unproven. Neither
failed campaign is reclassified, no threshold changes, and this receipt keeps
`qualification_pass: null` and `equivalence_claim: false`.

## Exact method and inputs

The independently reviewed [plan](sparse-cpu-mechanism-plan-2026-11-11.md) and
harness were committed before timing at
`0305df90523ec148094934d1eb127dc9df4b6be6`. Baseline source is
`56232d52f0fbfd2f3795a50917890ed6c85e6dc9`, released source
`4c58eece7566a1602475db79feefa3c1ae0c2604`. Runtime, original phase observer,
loader and frozen qualification files are unchanged. The source audit in the
plan explains the immediate singleton path and unchanged polling/clock sites.

One GitHub-hosted Ubuntu 24.04 runner, image `20261101.360.1`, exposed four
AMD EPYC 7763 CPUs on Linux `7.0.0-1017-azure`. Both relay executables and the
identical loader were built sequentially with Rust 1.94.1, locked dependencies,
release profile and TLS feature. The receipt binds source and executable hashes.
These are same-runner source builds, not the published Rust 1.99.1 downloads.

Every native row used one TCP client, 160-byte payload, window one, one worker,
16 warm-up trips, 2,000 probes and exactly 20,000 trips at 500/s. Phase CPU is
`/proc/PID/schedstat` runtime between the offered-work barriers, divided by the
loader's offered-phase wall time (39.9982–39.9983s). Lifetime `wait4` CPU is
retained separately. The old guard normalises lifetime CPU over a shorter
phase; these are different observations.

All host/useful-work checks passed. Minimum pre-row host idle was 98.746%;
maximum steal was zero; largest idle scheduler p99 was 0.170ms, maximum delay
0.200430ms. Native offered phases recorded 39,997–40,015 timeslices, approximately
two per round trip. Scheduler run-queue wait remained unavailable. Counters do
not independently count syscalls or prove identical kernel execution.

## All paired phase CPU differences

Values are signed **B minus A**, in percentage points of one CPU core. Source
pairs compare baseline A against release B; identical pairs use the same exact
release executable in both arms. The order was frozen before measurement.

| Pair | Comparison | Order | CPU difference | CPU-time difference |
| --- | --- | --- | ---: | ---: |
| 1 | Source | AB | +0.149712 | +59.884ms |
| 2 | Identical | BA | -0.009917 | -3.968ms |
| 3 | Source | BA | +0.076463 | +30.583ms |
| 4 | Identical | AB | -0.243459 | -97.380ms |
| 5 | Source | AB | +0.038707 | +15.482ms |
| 6 | Source | BA | -0.192960 | -77.181ms |
| 7 | Source | AB | -0.136880 | -54.749ms |
| 8 | Identical | AB | -0.298580 | -119.426ms |
| 9 | Source | AB | -0.152695 | -61.077ms |
| 10 | Source | BA | +0.055045 | +22.016ms |
| 11 | Source | BA | -0.162795 | -65.116ms |
| 12 | Identical | BA | -0.003253 | -1.301ms |

Eight source pairs give mean **-0.040675 points**, median -0.049086 and sample
standard deviation 0.133812. The predeclared two-sided df=7 Student interval is
**[-0.152545, +0.071195] points**. Its upper endpoint is below the unchanged
+0.2-point practical reference; it includes zero. This is a model-based mean
estimate assuming approximately normal independent paired errors. One shared
VM does not establish independence, equivalence or a worst-pair guarantee.
Every observed source pair fit the reference, including the +0.149712 adverse
pair; this is not execution of the frozen qualification.

The two largest identical-binary changes have magnitudes above 0.2 points.
They are negative signed differences and are not relabelled as failed positive
guards. Both occurred in AB controls; BA controls had smaller negative changes.
All four remain in the table. Source AB and BA means were -0.025289 and
-0.056062 points respectively. Later release rows generally used less CPU;
order/time effects and shared-host variability remain possibilities. The
controls are not subtracted from the source contrasts, and the observations
cannot prove that earlier adverse rows were caused by host noise.

## Independent user-instruction observation

Only after native timing, Valgrind 3.22.0 Callgrind ran four 4,000-trip rows in
ABBA order using the same exact stripped executables. Each row completed all
work with no missed slots or corruption. Whole-lifetime Ir counts were:

| Order | Source | User instructions |
| --- | --- | ---: |
| 1 | Baseline A | 29,087,325 |
| 2 | Release B | 29,722,419 |
| 3 | Release B | 29,715,064 |
| 4 | Baseline A | 29,106,088 |

The paired increases are **2.1834% and 2.0923%** (median 2.1378%). This supports
a small additional user-instruction cost across the instrumented relay lifetime;
it does not translate directly into native CPU time. Counts include readiness,
setup, probes and teardown; startup readiness may require different probe
counts. They exclude kernel instructions, have no Rust-function attribution
from these stripped binaries, and are not hardware cycles. The source adds
bookkeeping/branches while the measured scheduler counts show no material new
wake-up count. A kernel-cost, clock or spin regression is not established.

## Verification and retained limits

All nine new observer/interpretation fixtures passed on the measured Linux
runner, including its actual relay/loader transaction, after exact builds.
The existing phase-observer fixtures also passed. Locally, 33 Python fixtures
passed with four explicit binary-dependent skips; documentation, diff and
source-scoped secret checks passed. No fresh local Rust target or benchmark
was created; the authorised diagnostic-only push bypassed the documented local
hook and used hosted runtime checks.

PR-event Linux/macOS CI and the native/Android release build matrix passed on
the measured source. The duplicate push-event CI retained one existing
`closed_stdin_does_not_change_default_serve_lifetime` failure at
`tests/parent_lifetime.rs:50` (readiness channel disconnected); its macOS matrix
sibling was cancelled. This is separate from the valid performance campaign.
No failing CI row is deleted or silently represented as passing.

The existing fixture discarded startup stderr and unwrapped a disconnected
channel, so its original cause cannot be recovered from the saved log. A
test-only follow-up retains bounded child stderr and reports its exit state.
A deliberately occupied TCP listener verifies that startup bind errors are
reported. Twenty fixed repetitions of the parent-lifetime tests on each hosted
CI OS investigate recurrence using the existing target; no timing row is
repeated. The prospective reproduction on revision `fd94131` failed Linux
repetition 16 with **Address already in use (os error 98)** before readiness
([run 43106783971](https://github.com/forgesworn/spry-turn/actions/runs/43106783971));
its macOS matrix sibling was cancelled. Another concurrent CI run passed, and
neither result is removed. This identifies a bind collision in the reproduction,
while the first failure's discarded stderr leaves its cause unknown.

The runtime binds UDP first, then TCP to the same numeric port. An ephemeral
UDP port need not be free in the independent TCP namespace. The lifetime
fixture now preflights a shared UDP/TCP port, holding both guards during
selection, instead of asking UDP alone to choose one. Selection has a fixed
16-attempt cap; unexpected bind errors fail. The guards must be released before
the existing child API can bind, so a small intervening race remains possible
and captured startup failures are still fatal. There is no child-startup retry,
runtime change, or attribution of this bind collision to sparse CPU.

Temporary instrument profiles, credentials and fixture processes were removed
at job exit. The repository retains scalar rows, provenance and this analysis,
not packet traces, per-packet latency records, executables or Callgrind files.
No production host, phone, publication or deployment changed.
