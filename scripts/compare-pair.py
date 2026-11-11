#!/usr/bin/env python3
"""Bounded AB/BA socket comparison of two Spry builds, without a coturn build."""
import argparse
import json
import os
from pathlib import Path
import platform
import re
import resource
import statistics

from compare import binary_identity, cpu_brand, run_one


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--parent", type=Path, required=True)
    parser.add_argument("--candidate", type=Path, required=True)
    parser.add_argument("--loader", type=Path, required=True)
    parser.add_argument("--parent-source", required=True)
    parser.add_argument("--candidate-source", required=True)
    parser.add_argument("--transport", choices=["udp", "tcp", "tls"], default="tcp")
    parser.add_argument("--clients", type=int, default=128)
    parser.add_argument("--size", type=int, default=1200)
    parser.add_argument("--window", type=int, default=8)
    parser.add_argument("--pairs", type=int, default=4)
    parser.add_argument("--seconds", type=float, default=5)
    parser.add_argument("--packets", type=int, default=100000)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if not (1 <= args.clients <= 512 and 8 <= args.size <= 1400
            and 1 <= args.window <= 64 and 2 <= args.pairs <= 8
            and args.pairs % 2 == 0 and 1 <= args.seconds <= 30
            and args.clients <= args.packets <= 10000000):
        parser.error("invalid bounded workload or unbalanced pair count")
    for source in (args.parent_source, args.candidate_source):
        if not re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", source):
            parser.error("source identities must be commit or manifest SHA-256 hashes")
    if args.output.exists():
        parser.error("output already exists; preserve failed runs")
    paths = {name: getattr(args, name).resolve() for name in ("parent", "candidate", "loader")}
    identities = {name: binary_identity(path) for name, path in paths.items()}
    native = "arm64" if platform.machine() in ("arm64", "aarch64") else platform.machine()
    if any(identity["architectures"] != [native] for identity in identities.values()):
        parser.error("all three executables must match the native host architecture")
    soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    desired = 4096 if hard == resource.RLIM_INFINITY else min(hard, 4096)
    resource.setrlimit(resource.RLIMIT_NOFILE, (max(soft, desired), hard))
    receipt = {
        "schema": 1,
        "source": {"parent": args.parent_source, "candidate": args.candidate_source},
        "binaries": identities,
        "machine": {"cpu": cpu_brand(), "system": platform.system(),
                    "release": platform.release(), "load_before": os.getloadavg()},
        "method": {"pairs": args.pairs, "order": "AB, BA, repeated",
                   "transport": args.transport, "clients": args.clients,
                   "payload_bytes": args.size, "window": args.window,
                   "seconds_floor": args.seconds, "round_trip_floor": args.packets,
                   "workers": min(args.clients, 4),
                   "limits": "Closed-loop saturation, not equal offered rate or capacity. "
                   "CPU includes setup, warm-up, latency and resource inspection; normalisation "
                   "includes every verified forward. RSS excludes kernel memory. "
                   "Existing host workloads remain. No failed run is replaced."},
        "runs": [],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    try:
        for pair in range(args.pairs):
            for name in (("parent", "candidate") if pair % 2 == 0 else ("candidate", "parent")):
                row = run_one(name, paths[name], paths["loader"], args.clients,
                              args.packets, args.size, args.window, args.transport,
                              args.seconds, min(args.clients, 4))
                row["pair"] = pair + 1
                row["all_verified_forwards"] = 2 * (row["round_trips"] + args.clients * 16 + 2000)
                row["cpu_seconds_per_verified_forward"] = row["server_cpu_seconds"] / row["all_verified_forwards"]
                receipt["runs"].append(row)
                args.output.write_text(json.dumps(receipt, indent=2) + "\n")
                print(f"pair {pair + 1} {name}: {row['packets_per_second']:.0f} packets/s", flush=True)
        receipt["paired_median_candidate_parent_ratios"] = {}
        for metric in ("packets_per_second", "loaded_rss_bytes", "peak_sampled_rss_bytes",
                       "cpu_seconds_per_verified_forward", "loaded_round_trip_p99_us"):
            ratios = []
            for pair in range(1, args.pairs + 1):
                rows = {r["server"]: r for r in receipt["runs"] if r["pair"] == pair}
                ratios.append(rows["candidate"][metric] / rows["parent"][metric])
            receipt["paired_median_candidate_parent_ratios"][metric] = statistics.median(ratios)
    except BaseException as error:
        receipt["failure"] = {"exception_type": type(error).__name__, "completed_rows": len(receipt["runs"])}
        raise
    finally:
        receipt["machine"]["load_after"] = os.getloadavg()
        args.output.write_text(json.dumps(receipt, indent=2) + "\n")


if __name__ == "__main__":
    main()
