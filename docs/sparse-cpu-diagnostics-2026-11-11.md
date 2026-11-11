# Sparse CPU phase diagnostic plan

This diagnostic investigates the accepted v0.4.2 prerelease trade-off. It is not
another performance qualification or an optimisation. The two failed frozen
campaigns and the [owner's prerelease decision](release-v0.4.2-acceptance-2026-11-11.md)
remain unchanged. No relay runtime, dependency, security policy, deployment or
infrastructure setting changes in this task.

## Source and measurement boundary

The baseline is `56232d52f0fbfd2f3795a50917890ed6c85e6dc9`; the released source is
`4c58eece7566a1602475db79feefa3c1ae0c2604`. The diagnostic loader uses the exact
workflow commit. All three executables are built sequentially on the same
GitHub-hosted `ubuntu-24.04` runner with Rust **1.94.1**, locked dependencies,
release profile and the `tls` feature. The build step records each actual clean
checkout SHA, compiler, target and copied executable SHA-256. The runner requires
that manifest and validates its sources, compiler, profile and binary hashes.
This establishes build provenance through the reviewed workflow; arbitrary
externally supplied manifests are not independent attestations of source.

The released download was built with Rust 1.99.1. These diagnostics use 1.94.1 to
match the earlier failed qualification; they do not measure the published binary.
The runtime tree must match the released source. The frozen qualification
script, comparison helper, protocol document and qualification workflow must
remain byte-identical to v0.4.2. The diagnostic workflow is separate. Its initial
push trigger is restricted to the task branch and relevant source paths; remove
that trigger before merge, retaining manual reproduction. Record the measured
commit and hashes if a later workflow-only cleanup changes HEAD.

## Fixed experiment

One runner executes both stages, with no concurrent builds or diagnostics:

1. Release versus itself: four pairs, order AB, BA, AB, BA. Both arms use the
   identical copied release executable. This measures repeatability before
   interpreting a source comparison.
2. Original baseline versus release: four pairs in the same order.

That is exactly 16 rows, without pilot tuning, replacement rows or automatic
retry. Every row uses one plain TCP client, 160-byte payloads, window one, one
worker, 16 warm-up round trips, 2,000 untimed latency probes and 4,000 scheduled
round trips at 500/s. The offered phase is about eight seconds. All results and
failures are retained. The existing three-second idle probe, scheduler delay,
steal and useful-work checks apply without modification. A failed validity check
stops the remaining campaign and retains the completed rows and failed condition.
A GitHub runner is shared virtual infrastructure, not a bare-metal guarantee.

The observer reads per-task `/proc/PID/schedstat`: scheduled CPU time, run-queue
wait and timeslice count. It requires exactly one relay thread, stable process
start time, and non-regressing counters. Values have nanosecond units; that does
not establish nanosecond accuracy. It records `/proc/sys/kernel/sched_schedstats`.
When disabled, run-queue wait is **unavailable**, never a measured zero. A setting
change or unsupported process topology fails the observation. It never enables
scheduler statistics or changes host settings.

The opt-in loader pauses before setup, after setup, after warm-up, before offered
work and after offered work. The observer snapshots counters before acknowledging
each boundary. A missing acknowledgement fails within five seconds; an invalid
acknowledgement or EOF fails immediately. Phase deltas separate setup, warm-up,
probes and offered work. Additional ready and pre-release snapshots expose work
outside those intervals; lifetime `wait4` CPU remains a separate value including
readiness, setup, warm-up, probes, offered work and teardown.

The barriers, counter reads and loader acknowledgement threads perturb
scheduling. The observer does not run the normal 50ms RSS sampler or socket-memory
inspection. Phase and lifetime values therefore cannot replace or be directly
substituted into the original qualification guard. The original loader mode still
emits its original single result and does not create diagnostic threads. The
receipt deliberately has `qualification_pass: null` and `adoption_claim: false`.

## Interpretation and next gate

Retain every paired phase difference and the A/A spread. An apparent difference
within A/A variability is not a demonstrated source cost. If a consistent phase
cost appears, inspect that phase's source and propose one bounded runtime
experiment with an explicit mechanism and behavioural tests. No clock-read or
batching change is justified by the existing aggregate evidence alone.

Any proposed optimisation still needs the unchanged complete frozen
qualification: loaded TCP, sparse fixed-rate CPU/latency, UDP/TLS controls,
useful work, host validity, CPU and RSS. Diagnostics do not relax the +0.2
percentage-point one-core sparse CPU bound or turn either prior failure green.
No new runtime candidate or pass claim is part of this change.

## Validation and operation

The Python fixtures cover boundary ordering and missing data, observation-before-
ack ordering, failing acknowledgements, prefetched trailing stdout, process
identity/thread changes, disabled or malformed counters, counter regression and
source/compiler/binary provenance mismatches. Normal repository checks run these
fixtures. CI additionally builds the loader and tests invalid, EOF and missing
acknowledgements against its actual process, before any network work.

The separate GitHub job uses read-only repository permission and pinned checkout
and artifact actions. Workload traffic is loopback only, with generated fixture
credentials; no secrets or operator hosts are required. There are no new hosted
services, caches or deployments. Builds reuse that checkout's `target/` and use
two jobs. Artifacts retain scalar receipts and the build manifest for three days;
copy the compact evidence into the repository before expiry. Temporary binaries
are removed at job exit, and all fixture processes are closed on failure.

Local correctness checks use the task worktree's own target on the Mac mini.
No diagnostic benchmark or build runs on the M4 carrying the separate phone soak.

Local validation on 11 November: formatting, all-target/all-feature clippy,
workspace tests, minimal-feature tests, TURN-only tests, 42 UDP/TCP/TLS interop
tests and the source-scoped secret scan passed. All 24 Python fixtures passed
with the actual built loader, including a complete five-boundary TCP transaction
and unchanged ordinary-result fields. The first workspace attempt stopped at the
existing missing-release-binary prerequisite in the fresh worktree; building that
binary resolved the prerequisite without source changes. No local performance
measurement was run. Fixture processes and private temporary directories were
closed and removed. Remote diagnostic results remain pending.
