# Hosted Linux TCP qualification protocol

This prospective protocol qualifies PR #41 against exact parent
`56232d52f0fbfd2f3795a50917890ed6c85e6dc9`. It retains the previous contended
M1 results as diagnostic evidence. Those results are not qualification of the
subsequent accounting correction or of this run.

The branch-only `TCP performance qualification` workflow uses one fresh
`ubuntu-24.04` GitHub-hosted runner, Rust 1.94.1 and two Cargo jobs. It builds the
baseline then exact pushed candidate sequentially in the same target directory.
Only the three executables are copied. Both arms use the candidate's identical
loader. Source commits/tree IDs, runtime/toolchain, executable and script hashes
are recorded; executable/script identities are checked again after execution.
The workflow is bounded to 60 minutes. It uploads only the scalar JSON receipt
for three days, including failed/incomplete runs, and removes copied binaries.

GitHub-hosted means a fresh assigned runner, not guaranteed bare-metal isolation.
The protocol measures scheduler steal and idle scheduling delays, records CPU
and memory pressure, CPU affinity, runner image metadata and load averages. It
cannot exclude all hypervisor or frequency variation. No existing machine,
service or owner-held M4 is used.

## Work fixed before comparisons

One parent-only pilot of 500,000 trips runs for each loaded profile. All pilot
rows are retained. Each final count is frozen before any candidate measurement:
`max(1,000,000, ceil(500,000 * 6 / min(pilot wall, pilot server CPU) / 128) * 128)`.
A required count over 10,000,000 aborts before comparisons. This targets at least
six seconds of wall and server CPU, allowing substantial candidate gains while
requiring at least three seconds of each in every final loaded row. A short row
fails qualification; it does not trigger a replacement or workload retuning.

| Profile | Clients | Payload | Window | Workers | Trips |
| --- | ---: | ---: | ---: | ---: | --- |
| TCP loaded | 128 | 1,200 B | 8 | 4 | Frozen from pilot |
| TCP loaded | 512 | 1,200 B | 8 | 4 | Frozen from pilot |
| UDP control | 128 | 1,200 B | 8 | 4 | Frozen from pilot |
| TLS control | 16 | 1,200 B | 8 | 4 | Frozen from pilot |
| TCP one client | 1 | 160 B | 1 | 1 | Frozen from pilot |
| TCP sparse | 1 | 160 B | 1 | 1 | Exactly 4,000 at 500/s |

Each profile runs four paired comparisons in order AB, BA, AB, BA: two complete
ABBA blocks, 48 final rows. A is parent and B is candidate. The same useful work
is verified in each arm. Each server process starts fresh. There are no row
replacements, outlier removals or repeated campaigns to obtain a pass.

The sparse sender follows absolute deadlines from one phase start. It never
moves its schedule after a slow response. It records every packet's send RTT,
schedule-to-completion RTT and dispatch lateness, with a 4,096-sample reservoir
(the 4,000-packet profile retains all observations). More than 1% of sends at
least one interval late invalidates the fixed-rate qualification. Its elapsed
phase must be between the last scheduled send and 1% plus 10 ms beyond that
point. This is a bounded sequential scheduled probe, not an unconstrained
open-loop capacity generator. Overload or scheduler delays fail the validity
gate instead of silently hiding coordinated omission.

## Binding guards declared before timing

Before each pilot and final row, a three-second idle probe must observe at least
95% host CPU idle, at most 0.5% scheduler steal, sleep overshoot p99 at most 10 ms
and maximum at most 50 ms. Active workload steal must also remain at most 0.5%.
An invalid pilot aborts. Invalid paired rows remain recorded and prevent adoption.
All payloads must arrive intact and in order, with exact declared trip counts.

For each loaded profile, candidate/parent useful throughput must have median
ratio at least 0.97 and every pair at least 0.85. Server CPU per verified forward
must have median at most 1.05 and every pair at most 1.15. Both retained RSS and
sampled peak RSS must have median at most 1.05 and every pair at most 1.15, with
an absolute 256-KiB allowance for process/allocator noise. Sparse CPU uses the
absolute increase in server CPU divided by phase wall time: no pair may add
more than 0.002 of one CPU core (0.2 percentage points). This avoids ratios of
near-idle CPU counts. CPU uses `wait4` user+system microsecond fields, stored to
six decimal places, and includes setup, warm-up, probes and resource inspection.

Sparse schedule-to-completion p99 must not worsen by both more than 10% and
100 microseconds at the median; no pair may worsen by both more than 25% and
250 microseconds. All controls are binding. Closed-loop loaded p99 remains
diagnostic because its offered rate is not fixed between treatments.

At least one loaded TCP profile must demonstrate median CPU per verified forward
at least 5% lower or retained RSS at least 10% lower. All validity and control
guards must also pass. Failing guards require investigation and a warranted fix
or removal of the optimisation; they are not waived by favourable cells.

`loaded_rss_bytes` is a post-throughput retained sample with allocations held
open. Sampled peak RSS is separately observed every 50 ms. Neither includes all
kernel memory or establishes allocation counts. The observations cover local
loopback traffic, the listed payloads and useful-work levels, not WAN capacity,
8,192-byte throughput, arbitrary sustained receive fairness or power consumption.
