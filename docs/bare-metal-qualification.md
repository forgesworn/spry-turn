# Bare-metal qualification

This runbook settles the open item in [the goals](../GOALS.md): repeat the
Linux performance qualification on independent bare-metal hardware. The
hosted runs could not separate three accepted sparse TCP CPU guard failures
from host noise:

- [the 0.4.2 release decision](release-v0.4.2-acceptance-2026-11-11.md);
- [the peer-policy and control-budget change](tcp-pr63-results-2026-11-24.md);
- [the request-budget change](tcp-pr75-results-2026-11-25.md).

The hosted loader also never exercised the request-budget change's UDP nonce
check, because it connects from loopback. This runbook adds a
control-request protocol that does.

One command runs every campaign once. A failed campaign is a result: keep its
receipt, do not rerun it to obtain a pass, and leave acceptance to the owner.

## The machine

- A dedicated Linux machine, x86-64 or arm64, not a virtual machine or a shared
  host. Stop other workloads first: every row starts with an idle probe, and
  the host guards are the same as in the
  [hosted protocol](tcp-hosted-qualification-2026-11-11.md).
- At least four cores. The control-request probe keeps one busy.
- Root access once, to make the benchmarking range local (see below).
- Nothing is exposed to a network. The relays listen only on `127.0.0.1` and
  `198.18.0.1`, and all traffic stays on the machine.

## Prepare

```sh
git clone https://github.com/forgesworn/spry-turn.git
cd spry-turn
git checkout <commit to qualify>
rustup toolchain install 1.94.1 --profile minimal
sudo ip route add local 198.18.0.0/16 dev lo
```

The toolchain is the one the hosted campaigns pinned. Python 3, a C linker,
`openssl` (for the TLS profile's test certificate) and `file` must be
installed, along with `ps` (procps), which the TCP harness uses to sample
memory.

The route makes every address in `198.18.0.0/16`, the benchmarking range of
RFC 2544, local to the machine. The control-request probe needs this because
the relay treats loopback sources as already verified. The route lasts until
reboot; remove it sooner with `sudo ip route del local 198.18.0.0/16 dev lo`.

## Run

```sh
python3 scripts/bare-metal.py
```

The script refuses to start unless the checkout is clean, the toolchain is
installed, the benchmarking range is local and at least four cores are
usable. Then it:

1. builds each baseline in a temporary worktree and the candidate in the
   checkout, all with `--locked --release --features tls`;
2. runs the [TCP protocol](tcp-hosted-qualification-2026-11-11.md) against
   `56232d52f0fbfd2f3795a50917890ed6c85e6dc9` (the baseline of every hosted
   campaign) and against `f194ddf16b8aa43773c4ced897c118fbe2463859` (`main`
   before the request-budget change);
3. runs the control-request protocol below against
   `f194ddf16b8aa43773c4ced897c118fbe2463859`;
4. removes the worktree and executables and writes `summary.json` beside the
   receipts in `.local/bare-metal/<UTC date and time>/`.

The candidate includes every earlier change, so the first TCP comparison
covers 0.4.2, the peer-policy change and the request-budget change together.
Each hosted TCP campaign took 33 to 47 minutes including its two builds.
Use `--tcp-baseline <sha>` (repeatable) and `--control-baseline <sha>` to
choose other baselines, or `--skip-tcp` to run only the control campaign.

Every TCP campaign also reports "no predeclared loaded TCP benefit". That
protocol was written to qualify a speed-up, and none of these changes claims
one; the hosted results pages read it the same way. Read the other guards on
their own.

## Control-request protocol

This protocol was declared before any bare-metal measurement. It bounds what
per-source request budgets and the nonce check add to ordinary control
traffic: a pass shows the added cost is below the guard, not its exact size. It is not a flood: every rate is inside every budget of both arms, so
both answer every request and do the same useful work. Refusals under
overload are covered by unit tests, not here.

Each row starts a fresh relay listening on `198.18.0.1`. The probe
(`examples/control_probe.rs`) binds 1,000 UDP sockets to consecutive source
addresses from `198.18.1.0`. Before timing, each source sends one Allocate
without credentials and keeps the nonce from the challenge, in both modes.
The probe then sends Binding requests on an absolute schedule, rotating
across the sources. It spins between sends rather than sleeping, because a
sleep can overshoot by a whole slot, so it keeps one core busy while it runs. A second thread reads every
socket as soon as it is readable, so the sender never waits for an answer.
An answer that arrives after the next request was due still counts and is
recorded as late. After the last request, the probe stops once no answer has
arrived for 200 ms.

| Profile | Requests | Rate | Per source | Nonce on each request |
| --- | ---: | ---: | ---: | --- |
| `bare` | 30,000 | 1,000/s | 1/s | No: the new code uses the budget for unverified sources |
| `nonce` | 30,000 | 1,000/s | 1/s | Yes: the new code checks it and uses the verified budget |

The smallest shared budget in either arm is 2,000 a second. The smallest
per-source allowance is 5 a second, for unverified sources in the candidate.
Those allowances live in 4,096 hashed slots, so sources can share one; at
1 a second each, six sources would have to share a slot before any request
was refused.

Each profile runs four pairs in the order AB, BA, AB, BA, where A is the
baseline and B the candidate. There are no row replacements, outlier
removals or repeated campaigns.

Binding guards, declared before timing:

- the same host guards as the TCP protocol, checked before and during each row;
- every request answered exactly once, with no unexpected answers;
- at most 1% of requests sent one interval or more late, and the phase
  ending between the last scheduled send and 1% plus 10 ms after it;
- at most 1% of answers arriving after the next request was due, so a row
  disturbed in a way the host guards miss is labelled as such;
- no pair may add more than 0.002 of one CPU core. That is the increase in
  relay CPU (`wait4` user plus system, over the relay's lifetime) divided by
  the probe phase's wall time, the same bound as the sparse TCP guard.

CPU per request and the probe's round-trip p99 are recorded as diagnostics
only. The round trip runs from send to receipt in the probe, so it
includes the probe's own scheduling.

This protocol does not measure floods, refusal paths, IPv6 /64 grouping,
TCP or TLS sources (verified without a nonce) or WAN conditions.

## Record the results

- Copy each receipt to `docs/evidence/` with a dated name, and write a results
  page in the style of [the request-budget results](tcp-pr75-results-2026-11-25.md).
- Before committing, check the receipts: they record the CPU model, kernel,
  toolchain and executable hashes, and must not contain host names, other
  addresses or local paths.
- Record failures as they are and say whether the owner accepts them. Update
  the goal in [the goals](../GOALS.md) either way.
