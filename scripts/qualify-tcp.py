#!/usr/bin/env python3
"""One predeclared, Linux-only paired qualification; never replaces failed rows."""
import argparse
import hashlib
import json
import math
import re
import os
from pathlib import Path
import platform
import resource
import statistics
import subprocess
import sys
import time

from compare import binary_identity, cpu_brand, run_one

PARENT = "56232d52f0fbfd2f3795a50917890ed6c85e6dc9"
PAIRS = 4
PROFILES = [
    dict(name="tcp128", transport="tcp", clients=128, packets=1_000_000, size=1200, window=8, workers=4, rate=0),
    dict(name="tcp512", transport="tcp", clients=512, packets=1_000_000, size=1200, window=8, workers=4, rate=0),
    dict(name="udp128", transport="udp", clients=128, packets=1_000_000, size=1200, window=8, workers=4, rate=0),
    dict(name="tls16", transport="tls", clients=16, packets=1_000_000, size=1200, window=8, workers=4, rate=0),
    dict(name="tcp1", transport="tcp", clients=1, packets=200_000, size=160, window=1, workers=1, rate=0),
    dict(name="tcp1_sparse", transport="tcp", clients=1, packets=4000, size=160, window=1, workers=1, rate=500),
]
GUARDS = {
    "idle_fraction_min": 0.95, "steal_fraction_max": 0.005,
    "idle_scheduler_p99_ms_max": 10, "idle_scheduler_max_ms_max": 50,
    "missed_dispatch_fraction_max": 0.01,
    "loaded_seconds_min": 3, "pilot_target_seconds": 6, "pilot_trip_count": 500000,
    "loaded_trip_cap": 10000000, "sparse_cpu_one_core_delta_max": 0.002,
    "throughput_median_min": 0.97, "throughput_pair_min": 0.85,
    "cpu_median_max": 1.05, "cpu_pair_max": 1.15,
    "rss_median_max": 1.05, "rss_pair_max": 1.15, "rss_absolute_tolerance_bytes": 262144,
    "sparse_p99_median_ratio_max": 1.10, "sparse_p99_median_delta_us_max": 100,
    "sparse_p99_pair_ratio_max": 1.25, "sparse_p99_pair_delta_us_max": 250,
    "benefit_cpu_ratio_max": 0.95, "benefit_retained_rss_ratio_max": 0.90,
}


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def snapshot():
    lines = Path("/proc/stat").read_text().splitlines()
    cpu = [int(x) for x in lines[0].split()[1:9]]
    return {"cpu_ticks": cpu, "load": os.getloadavg(),
            "context_switches": int(next(x.split()[1] for x in lines if x.startswith("ctxt "))),
            "cpu_pressure": Path("/proc/pressure/cpu").read_text().strip(),
            "memory_pressure": Path("/proc/pressure/memory").read_text().strip(),
            "monotonic": time.monotonic()}


def cpu_delta(before, after):
    ticks = [b - a for a, b in zip(before["cpu_ticks"], after["cpu_ticks"])]
    total = sum(ticks)
    if total <= 0 or min(ticks) < 0:
        raise RuntimeError("invalid host CPU observation")
    return {"idle_fraction": (ticks[3] + ticks[4]) / total,
            "steal_fraction": ticks[7] / total,
            "context_switches": after["context_switches"] - before["context_switches"]}


def idle_probe():
    before = snapshot()
    delays = []
    end = time.monotonic() + 3
    while time.monotonic() < end:
        start = time.monotonic()
        time.sleep(0.01)
        delays.append(max(0, time.monotonic() - start - 0.01) * 1000)
    after = snapshot()
    delays.sort()
    return {"before": before, "after": after, **cpu_delta(before, after),
            "scheduler_p99_ms": delays[len(delays) * 99 // 100],
            "scheduler_max_ms": max(delays)}


def host_failures(idle, active):
    failures = []
    if idle["idle_fraction"] < GUARDS["idle_fraction_min"]:
        failures.append("pre-run host not idle")
    if max(idle["steal_fraction"], active["steal_fraction"]) > GUARDS["steal_fraction_max"]:
        failures.append("scheduler steal exceeded bound")
    for name in ("p99", "max"):
        if idle[f"scheduler_{name}_ms"] > GUARDS[f"idle_scheduler_{name}_ms_max"]:
            failures.append(f"idle scheduler {name} exceeded bound")
    return failures


def pilot_count(row):
    duration = min(row["seconds"], row["server_cpu_seconds"])
    if duration <= 0:
        raise ValueError("pilot has no measurable work")
    count = max(1_000_000, math.ceil(GUARDS["pilot_trip_count"] * GUARDS["pilot_target_seconds"] / duration / 128) * 128)
    if count > GUARDS["loaded_trip_cap"]:
        raise ValueError("pilot requires work beyond declared cap")
    return count


def row_failures(row, profile):
    failures = []
    if row["round_trips"] != profile["packets"] or row["loss_or_corruption"] != 0:
        failures.append("useful work or integrity mismatch")
    if row["offered_round_trips_per_second"] != profile["rate"]:
        failures.append("offered rate mismatch")
    if not profile["rate"] and min(row["seconds"], row["server_cpu_seconds"]) < GUARDS["loaded_seconds_min"]:
        failures.append("loaded CPU or wall interval below minimum")
    if profile["rate"]:
        if row["missed_dispatch_slots"] / profile["packets"] > GUARDS["missed_dispatch_fraction_max"]:
            failures.append("sparse sender missed offered schedule")
        if row["loaded_latency_observations"] != profile["packets"]:
            failures.append("sparse latency observations incomplete")
        expected = (profile["packets"] - 1) / profile["rate"]
        if not expected <= row["seconds"] <= expected * 1.01 + 0.01:
            failures.append("sparse elapsed time outside offered schedule")
    return failures


def evaluate_profile(rows, profile):
    """All paired guards are binding; no adverse pair is trimmed or replaced."""
    if len(rows) != PAIRS * 2:
        return {"pass": False, "failures": ["incomplete profile"], "metrics": {}}
    pairs = []
    for pair in range(1, PAIRS + 1):
        arms = {row["server"]: row for row in rows if row["pair"] == pair}
        if set(arms) != {"parent", "candidate"}:
            return {"pass": False, "failures": ["missing paired arm"], "metrics": {}}
        pairs.append((arms["parent"], arms["candidate"]))
    metrics, failures = {}, []
    for metric in ("packets_per_second", "cpu_seconds_per_verified_forward", "loaded_rss_bytes",
                   "peak_sampled_rss_bytes", "loaded_round_trip_p99_us", "scheduled_round_trip_p99_us"):
        if metric == "scheduled_round_trip_p99_us" and not profile["rate"]:
            continue
        ratios = [c[metric] / p[metric] for p, c in pairs]
        deltas = [c[metric] - p[metric] for p, c in pairs]
        metrics[metric] = {"ratios": ratios, "median_ratio": statistics.median(ratios),
                           "minimum_ratio": min(ratios), "maximum_ratio": max(ratios),
                           "deltas": deltas, "median_delta": statistics.median(deltas)}
    if not profile["rate"]:
        ratio = metrics["packets_per_second"]
        if ratio["median_ratio"] < GUARDS["throughput_median_min"] or ratio["minimum_ratio"] < GUARDS["throughput_pair_min"]:
            failures.append("throughput guard")
    if profile["rate"]:
        utilisation_deltas = [c["server_cpu_seconds"] / c["seconds"] - p["server_cpu_seconds"] / p["seconds"] for p, c in pairs]
        metrics["sparse_cpu_one_core_utilisation_delta"] = {"deltas": utilisation_deltas, "median": statistics.median(utilisation_deltas), "maximum": max(utilisation_deltas)}
        if max(utilisation_deltas) > GUARDS["sparse_cpu_one_core_delta_max"]:
            failures.append("sparse absolute CPU overhead guard")
    else:
        cpu = metrics["cpu_seconds_per_verified_forward"]
        if cpu["median_ratio"] > GUARDS["cpu_median_max"] or cpu["maximum_ratio"] > GUARDS["cpu_pair_max"]:
            failures.append("CPU per verified forward guard")
    for metric in ("loaded_rss_bytes", "peak_sampled_rss_bytes"):
        value = metrics[metric]
        median_bad = value["median_ratio"] > GUARDS["rss_median_max"] and value["median_delta"] > GUARDS["rss_absolute_tolerance_bytes"]
        any_bad = any(r > GUARDS["rss_pair_max"] and d > GUARDS["rss_absolute_tolerance_bytes"]
                      for r, d in zip(value["ratios"], value["deltas"]))
        if median_bad or any_bad:
            failures.append(f"{metric} guard")
    if profile["rate"]:
        value = metrics["scheduled_round_trip_p99_us"]
        median_bad = (value["median_ratio"] > GUARDS["sparse_p99_median_ratio_max"]
                      and value["median_delta"] > GUARDS["sparse_p99_median_delta_us_max"])
        any_bad = any(r > GUARDS["sparse_p99_pair_ratio_max"] and d > GUARDS["sparse_p99_pair_delta_us_max"]
                      for r, d in zip(value["ratios"], value["deltas"]))
        if median_bad or any_bad:
            failures.append("fixed-rate scheduled p99 guard")
    return {"pass": not failures, "failures": failures, "metrics": metrics}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for arm in ("parent", "candidate", "loader"):
        parser.add_argument(f"--{arm}", type=Path, required=True)
    parser.add_argument("--candidate-source", required=True)
    parser.add_argument("--parent-source", default=PARENT)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if platform.system() != "Linux" or args.output.exists():
        parser.error("requires Linux and a fresh output path; failed receipts must be preserved")
    if not re.fullmatch(r"[0-9a-f]{40}", args.parent_source):
        parser.error("parent source must be a full commit SHA")
    head = subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip()
    if head != args.candidate_source or subprocess.check_output(["git", "status", "--porcelain", "--untracked-files=no"], text=True):
        parser.error("candidate checkout must be exact and clean")
    paths = {arm: getattr(args, arm).resolve() for arm in ("parent", "candidate", "loader")}
    identities = {arm: binary_identity(path) for arm, path in paths.items()}
    native = "arm64" if platform.machine() in ("arm64", "aarch64") else platform.machine()
    if any(value["architectures"] != [native] for value in identities.values()):
        parser.error("executables must have the native architecture")
    soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    resource.setrlimit(resource.RLIMIT_NOFILE, (min(hard, max(soft, 4096)) if hard >= 0 else max(soft, 4096), hard))
    scripts = {name: digest(name) for name in ("scripts/qualify-tcp.py", "scripts/compare.py", "examples/load.rs", "tests/interop.py", ".github/workflows/perf-tcp.yml")}
    receipt = {"schema": 1, "source": {"parent": args.parent_source, "candidate": head}, "binaries": identities,
               "scripts": scripts, "method": {"pairs": PAIRS, "order": "AB, BA, AB, BA", "profiles": PROFILES,
               "guards": GUARDS, "no_replacement_rows": True, "pilot": "one parent-only 500k-trip run per loaded profile; freeze counts targeting 6s min(CPU,wall), cap10M before paired measurements", "cpu_scope": "server lifetime including setup, warm-up, probes and resource inspection",
               "rss_scope": "loaded is post-throughput retained RSS; peak is separate 50ms sampled process RSS, excludes kernel memory",
               "scope": "same-runner loopback; closed-loop loaded comparisons plus bounded fixed-schedule sparse probe, not WAN capacity or bare-metal isolation"},
               "host": {"cpu": cpu_brand(), "kernel": platform.release(), "affinity": sorted(os.sched_getaffinity(0)),
               "rustc": subprocess.check_output(["rustc", "--version"], text=True).strip(),
               "cpu_timer": "os.wait4 rusage user+system seconds, microsecond fields; stored to six decimals",
               "clock_ticks_per_second": os.sysconf("SC_CLK_TCK"),
               "runner": {name: os.environ.get(name) for name in ("RUNNER_OS", "RUNNER_ARCH", "ImageOS", "ImageVersion", "GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT")}},
               "pilots": [], "runs": [], "profile_results": [], "failures": []}
    receipt["source_trees"] = {arm: subprocess.check_output(["git", "rev-parse", source + "^{tree}"], text=True).strip() for arm, source in receipt["source"].items()}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    def save():
        args.output.write_text(json.dumps(receipt, indent=2) + "\n")
    save()
    active = None
    try:
        # All parent-only pilot counts are frozen before the first paired row.
        for profile in PROFILES:
            if profile["rate"]:
                continue
            active = {"phase": "pilot", "profile": profile["name"], "arm": "parent"}
            idle = idle_probe()
            before = snapshot()
            row = run_one("parent", paths["parent"], paths["loader"], profile["clients"], GUARDS["pilot_trip_count"],
                          profile["size"], profile["window"], profile["transport"], workers=profile["workers"])
            after = snapshot()
            active_cpu = cpu_delta(before, after)
            row.update(idle_probe=idle, host_active={"before": before, "after": after, **active_cpu})
            if row.get("kernel_socket_memory"):
                row["kernel_socket_memory"].pop("per_socket_counters", None)
            row["failures"] = host_failures(idle, active_cpu)
            if row["round_trips"] != GUARDS["pilot_trip_count"] or row["loss_or_corruption"]:
                row["failures"].append("pilot useful-work mismatch")
            receipt["pilots"].append({"profile": profile["name"], **row})
            save()
            if row["failures"]:
                raise RuntimeError("pilot host validity or useful work failed; no paired campaign")
            profile["packets"] = pilot_count(row)
        receipt["frozen_profile_sha256"] = hashlib.sha256(json.dumps(PROFILES, sort_keys=True).encode()).hexdigest()
        save()
        for profile in PROFILES:
            for pair in range(1, PAIRS + 1):
                for arm in (("parent", "candidate") if pair % 2 else ("candidate", "parent")):
                    active = {"profile": profile["name"], "pair": pair, "arm": arm}
                    idle = idle_probe()
                    before = snapshot()
                    row = run_one(arm, paths[arm], paths["loader"], profile["clients"], profile["packets"],
                                  profile["size"], profile["window"], profile["transport"], workers=profile["workers"], rate=profile["rate"])
                    after = snapshot()
                    row.update(profile=profile["name"], pair=pair, idle_probe=idle,
                               host_active={"before": before, "after": after, **cpu_delta(before, after)})
                    row["all_verified_forwards"] = 2 * (row["round_trips"] + profile["clients"] * 16 + 2000)
                    row["cpu_seconds_per_verified_forward"] = row["server_cpu_seconds"] / row["all_verified_forwards"]
                    row["failures"] = host_failures(idle, row["host_active"]) + row_failures(row, profile)
                    if row.get("kernel_socket_memory"):
                        row["kernel_socket_memory"].pop("per_socket_counters", None)
                    receipt["runs"].append(row)
                    save()
                    print(json.dumps({**active, "throughput": row["packets_per_second"], "failures": row["failures"]}), flush=True)
            rows = [row for row in receipt["runs"] if row["profile"] == profile["name"]]
            result = {"profile": profile["name"], **evaluate_profile(rows, profile)}
            receipt["profile_results"].append(result)
            save()
        if any(row["failures"] for row in receipt["runs"]):
            receipt["failures"].append("host validity, offered schedule or useful-work guard failed; no adoption")
        if any(not result["pass"] for result in receipt["profile_results"]):
            receipt["failures"].append("paired non-regression guard failed; no adoption")
        loaded_tcp = [result for result in receipt["profile_results"] if result["profile"] in ("tcp128", "tcp512")]
        if not any(result["metrics"]["cpu_seconds_per_verified_forward"]["median_ratio"] <= GUARDS["benefit_cpu_ratio_max"]
                   or result["metrics"]["loaded_rss_bytes"]["median_ratio"] <= GUARDS["benefit_retained_rss_ratio_max"] for result in loaded_tcp):
            receipt["failures"].append("no predeclared loaded TCP benefit")
    except BaseException as error:
        receipt["failure"] = {"active": active, "exception_type": type(error).__name__, "completed_rows": len(receipt["runs"])}
        receipt["failures"].append("incomplete campaign")
        raise
    finally:
        receipt["binaries_after"] = {arm: binary_identity(path) for arm, path in paths.items()}
        receipt["scripts_after"] = {name: digest(name) for name in scripts}
        if receipt["binaries_after"] != identities or receipt["scripts_after"] != scripts:
            receipt["failures"].append("executable or harness identity changed")
        receipt["pass"] = not receipt["failures"] and len(receipt["runs"]) == len(PROFILES) * PAIRS * 2
        save()
    return 0 if receipt["pass"] else 1


if __name__ == "__main__":
    sys.exit(main())
