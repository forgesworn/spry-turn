# Sparse CPU phase diagnostic results

The single [diagnostic run](https://github.com/forgesworn/spry-turn/actions/runs/43081179999)
completed all 16 predeclared rows on 11 November 2026. Every host and useful-work
validity check passed. This is **diagnostic completion, not performance
qualification**: the receipt keeps `qualification_pass: null`. Both earlier
failed performance campaigns and the owner's accepted prerelease trade-off stand.

The [complete scalar receipt](evidence/sparse-cpu-diagnostics-1e0b933-2026-11-11.json)
contains every row, all phase snapshots, the build manifest, binary/script hashes,
unchanged final input identities and host checks. No row was replaced or retried.
The [plan](sparse-cpu-diagnostics-2026-11-11.md) defines the boundaries and limits.

## Exact inputs and environment

- Original baseline: `56232d52f0fbfd2f3795a50917890ed6c85e6dc9`.
- Released source: `4c58eece7566a1602475db79feefa3c1ae0c2604`.
- Measured diagnostic loader/observer/workflow: `1e0b933fa0d767932d4c3264389fe073dfe185bb`.
- Compiler: Rust 1.94.1, release profile, locked dependencies, `tls` feature;
  sequential same-runner builds with recorded source and executable hashes.
- Runner image: `ubuntu-24.04`, version `20261101.360.1`, as recorded in
  the job setup log. GitHub-hosted AMD EPYC 9V74, four available CPUs,
  Linux `7.0.0-1017-azure`. This remains shared virtual infrastructure.
- Each row: one plain TCP client, 160-byte payload, window one, one worker,
  16 warm-up round trips, 2,000 probes, then 4,000 trips offered at 500/s.
- Minimum pre-run host idle: 99.251%; maximum observed steal: 0%; largest
  idle-probe scheduler p99: 0.148ms, maximum delay: 0.203ms. No offered dispatch
  slots were missed. Every row completed all useful work without corruption.
- `sched_schedstats` was disabled throughout. Run-queue wait is unavailable,
  recorded as null; CPU runtime and timeslices were available.

The final workflow removes only the temporary push trigger; documentation and
this receipt are added afterwards. The measured loader, observer, tests, imported
helpers and relay runtime are unchanged. The workflow change has not been timed.
The published v0.4.2 binaries used Rust 1.99.1; these measurements do not claim to
measure those downloads.

## Every paired CPU delta

Values are milliseconds of CPU, **B minus A**. Pairs run in AB, BA, AB, BA order.
The median is the ordinary median of the four signed paired differences. Negative
values mean B used less CPU. Scheduler-counter phase deltas and lifetime `wait4`
CPU are different observations; phase values do not include all lifetime work.

Release versus the identical release executable:

| CPU interval | Pair 1 | Pair 2 | Pair 3 | Pair 4 | Median |
| --- | ---: | ---: | ---: | ---: | ---: |
| Lifetime | -15.564 | +3.796 | -11.853 | +14.683 | -4.0285 |
| Setup | +0.006640 | +0.010815 | -0.009775 | -0.006079 | +0.000281 |
| Warm-up | +0.038446 | -0.003225 | +0.024987 | -0.000161 | +0.012413 |
| Probes | +0.653059 | +1.260788 | -10.998451 | +0.188330 | +0.420695 |
| Offered work | -16.277111 | +2.546296 | -0.879735 | +14.508573 | +0.833280 |

Original baseline (A) versus released source (B):

| CPU interval | Pair 1 | Pair 2 | Pair 3 | Pair 4 | Median |
| --- | ---: | ---: | ---: | ---: | ---: |
| Lifetime | -5.779 | +16.257 | +48.908 | -7.773 | +5.239 |
| Setup | -0.001281 | +0.022453 | -0.002423 | +0.007231 | +0.002975 |
| Warm-up | -0.081392 | -0.062082 | -0.065568 | -0.085436 | -0.073480 |
| Probes | +0.703067 | +5.622785 | -1.415462 | -0.053372 | +0.324848 |
| Offered work | -6.380834 | +10.710307 | +50.408415 | -7.656218 | +2.164736 |

For visibility, lifetime CPU divided by offered-work duration gives paired
one-core utilisation differences of -0.1946, +0.0474, -0.1482 and +0.1836
percentage points for release/release; baseline/release gives -0.0723, +0.2033,
+0.6115 and -0.0972 points. These are normalised **lifetime** observations from
the instrumented diagnostic, not isolated phase utilisation or a new execution of
the frozen +0.2-point performance guard. All adverse observations are retained.

## Interpretation

The largest positive baseline/release CPU difference is in offered work
(+50.408ms in pair 3), with a much smaller probe difference in that pair. Setup
and warm-up cannot account for it. Warm-up CPU is consistently slightly lower
for the release, but its median difference is only 0.073ms.

Identical release binaries also show substantial repeatability spread, including
-16.277 to +14.509ms in offered work. Baseline/release offered-work differences
have mixed signs; their median +2.165ms is within that A/A spread. The larger
positive pair remains a valid observation and is not relabelled as host invalid.
This bounded experiment locates the largest contrast but does not establish a
repeatable source mechanism or a statistically reliable average cost.

No clock-read, batching or other runtime change follows from this result. A next
runtime experiment needs a specific mechanism and its own behavioural tests,
followed by the unchanged full performance qualification. The diagnostic does
not justify weakening the sparse guard or removing the established loaded TCP
benefits.
