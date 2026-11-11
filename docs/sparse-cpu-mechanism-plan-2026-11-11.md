# Sparse CPU mechanism experiment

This is one prospective source/noise investigation of v0.4.2, not another
execution of the frozen qualification. Both failed campaigns and the accepted
prerelease trade-off remain unchanged. It changes no runtime, dependency,
production service, phone workload, security policy or qualification threshold.
The existing [diagnostic](sparse-cpu-diagnostic-results-2026-11-11.md) remains
valid: its adverse +50.408ms offered-phase contrast is retained.

## Hypotheses and source audit

The exact original baseline is `56232d52f0fbfd2f3795a50917890ed6c85e6dc9`;
the released source is `4c58eece7566a1602475db79feefa3c1ae0c2604`. The
`poll_once` event loop, poll deadline, stream continuation queue, interest
updates and per-receive `Instant::now` placement are unchanged between them.
The release adds dispatch bookkeeping, a first-return branch and a capacity
condition. A 164-byte singleton frame fits the existing 4,096-byte connection
buffer; it is sent immediately, without a new look-ahead receive, batch
classification, buffer loan or delayed flush. A second admitted return enables
batching. This is a source-path observation, not a measured zero-cost claim:
code layout, instruction/cache cost and kernel execution remain possibilities.

All 16 prior diagnostic offered phases recorded 8,000–8,006 relay timeslices.
The largest positive baseline/release contrast had exactly 8,003 in both
arms. That contrast does not show additional scheduler timeslices; timeslices
alone cannot prove identical syscalls or exclude kernel/wakeup variation.

The experiment tests whether longer equal-work source contrasts show a
consistent material mean CPU increase, how identical-binary drift compares,
and whether interpreted user-instruction counts show a source cost independent
of native CPU timing. It may remain inconclusive. It cannot establish a hard
worst-pair bound or identify kernel instructions through Callgrind.

## Fixed work and resource budget

Use the existing manual `Sparse CPU phase diagnostics` workflow on the exact
reviewed branch revision with input `campaign=mechanism`. One fresh
`ubuntu-24.04` GitHub-hosted x86-64 runner builds baseline, release and loader
sequentially with Rust 1.94.1, locked dependencies, ordinary release profile,
TLS feature and two Cargo jobs, sharing its checkout's target. Record source,
compiler, profile and executable SHA-256 in the existing manifest and validate
them before and after execution. Loader/runtime and frozen qualification files
must match their pinned predecessors. Published v0.4.2 downloads use another
compiler and are outside this measurement.

Each native row performs one TCP allocation, 16 warm-up trips, 2,000 probes,
then exactly **20,000 trips at 500/s** with 160-byte payload, window one and one
worker. The offered phase lasts about 40 seconds. The unchanged +0.2
percentage-point reference is therefore approximately **80ms** of phase CPU,
versus 16ms in the earlier eight-second experiment. Phase CPU is cumulative
`/proc/PID/schedstat` runtime divided by that row's offered-phase wall time;
unit nanoseconds do not establish accuracy. Lifetime `wait4` CPU is retained
separately and never substituted for phase CPU. Additional voluntary and
involuntary context-switch counters are cumulative `/proc/PID/status` fields.
Run-queue wait remains null when scheduler statistics are disabled.

Exactly 12 pairs, 24 native rows: eight baseline/release pairs and four
identical-release pairs. A is baseline only in source pairs; B is release;
both use the identical release executable in control pairs. In each three-pair
stratum there are two source pairs and one control. The fixed randomised
balanced order is:

| Pair | Comparison | Execution order |
| --- | --- | --- |
| 1 | Source | AB |
| 2 | Identical | BA |
| 3 | Source | BA |
| 4 | Identical | AB |
| 5 | Source | AB |
| 6 | Source | BA |
| 7 | Source | AB |
| 8 | Identical | AB |
| 9 | Source | AB |
| 10 | Source | BA |
| 11 | Source | BA |
| 12 | Identical | BA |

The table was generated before measurement with Python `random.Random(20261111)`:
shuffle `['source','source','identical']` independently four times, concatenate,
then sample balanced AB/BA multisets independently for source and identical
stages. The committed table is authoritative; no randomisation occurs at run
time. The eight source **pairs** are the sample units; 16 source rows or
individual packets are not independent replicates.

Before every row run the existing three-second idle probe. Existing host,
schedule and useful-work checks apply unchanged: idle at least 95%, steal at
most 0.5%, idle scheduler p99 at most 10ms and maximum at most 50ms; exact work,
no corruption, no more than 1% missed scheduled sends and bounded offered wall
time. The 4,096-sample latency reservoir is a sample of the longer phase; it
does not retain every packet latency. Stop at a failed validity check, retain
all completed rows and the failure, and do not replace, retry or trim rows.
An invalid campaign is inconclusive, not evidence that the host caused an
otherwise valid adverse observation.

After all native timing, run four additional **Callgrind** rows in ABBA order,
4,000 offered trips each, with the same exact ordinary release executables and
loader. [Callgrind's Ir counter](https://valgrind.org/docs/manual/cl-manual.html)
counts executed user instructions and changes execution; its time is never a
native performance measurement. Whole-lifetime counts include setup, probes,
readiness and teardown and exclude kernel instructions. Both arms perform the
same media work, but startup readiness can require a different number of probes;
whole-lifetime instruction differences therefore include this nuisance and are
not purely attributable to source changes. The binaries strip Rust symbols, so do not attribute totals
to a named Rust function or infer hardware cycles from them. Retain each scalar
count and offered-schedule misses, never discard an adverse count. No syscall
count claim follows from Ir or scheduler timeslices.

Expected budget: about 17 minutes native rows including idle probes, 1–3 minutes
instruction observations, plus sequential builds and package installation;
45-minute workflow cap. No owner-held host or production traffic. Generated
loopback credentials and Callgrind files stay temporary; upload only scalar
receipts/build manifest for three days, and copy compact evidence into the repo
before expiry. Fixtures and wrappers close and are removed on success/failure.

## Predeclared interpretation

Retain every signed B-minus-A phase CPU ratio, CPU nanoseconds, timeslice
contrast, and all A/A differences. Report the source mean, median, range,
sample standard deviation and two-sided 95% Student interval with **df=7**:
`mean +/- 2.364624251 * sample_sd / sqrt(8)`. This interval is model-based:
approximately normal, independent paired errors are assumed, and dependence
within one shared VM is unverified. Do not describe it as a distribution-free
confidence guarantee or treat the four A/A pairs as a subtractable correction.
Report any order or time pattern, and retain inconclusive classification when
uncertainty crosses the +0.002 one-core practical reference.

If the interval's lower endpoint exceeds +0.002, label this mean estimate
`estimated_mean_above_budget`; if its upper endpoint is below +0.002, label it
`estimated_mean_below_budget`; otherwise `mean_budget_unresolved`. Also report
whether the interval excludes zero, and whether each observed source pair fits
the reference. A below-budget estimate is **not equivalence**, a guaranteed
per-pair bound, or qualification of the published binary. A/A spread and
Callgrind direction inform mechanism investigation; they do not waive adverse
native rows or calibrate a pass.

No optimisation follows automatically. A runtime change requires a specific
supported mechanism and behavioural tests, independent review, then the
**unchanged complete frozen qualification** covering loaded TCP, sparse
CPU/latency, UDP/TLS controls, useful work, host validity, CPU and RSS. This
receipt always has `qualification_pass: null` and `equivalence_claim: false`.
