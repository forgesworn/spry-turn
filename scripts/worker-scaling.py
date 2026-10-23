#!/usr/bin/env python3
"""Compare one and two independent relay processes with a fixed total workload.

This measures separately addressed servers, not built-in worker support,
SO_REUSEPORT distribution, maximum capacity or transparent client failover.
"""
import argparse
import concurrent.futures
import importlib.util
import json
import math
import os
from pathlib import Path
import platform
import queue
import re
import resource
import threading
import time
import types


def load_compare():
    spec = importlib.util.spec_from_file_location("spry_compare", Path(__file__).with_name("compare.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def run_group(compare, name, binary, loader, processes, clients, workers, packets, size,
              window, min_seconds, relay_ports):
    """Reuse the reviewed runner; synchronise readiness without editing it."""
    original_server, original_queue = compare.Server, compare.queue
    ready = threading.Barrier(processes, timeout=15)
    context = threading.local()
    arrivals = {}
    arrival_lock = threading.Lock()
    origin = time.perf_counter()

    class ReadyServer(original_server):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            try:
                ready.wait()
            except BaseException:
                self.close()
                raise

    class ArrivalQueue(queue.Queue):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self.index = context.index

        def put(self, item, block=True, timeout=None):
            # compare.run_one receives one flushed JSON line at the end of the
            # loaded phase, before the bounded resource-observation handshake.
            # Record pipe arrival; do not infer timing from later /proc/lsof work.
            with arrival_lock:
                arrivals[self.index] = time.perf_counter()
            return super().put(item, block=block, timeout=timeout)

    compare.Server = ReadyServer
    compare.queue = types.SimpleNamespace(Queue=ArrivalQueue, Empty=queue.Empty)

    def worker(index):
        context.index = index
        first, last = map(int, relay_ports.split(":"))
        width = (last - first + 1) // processes
        local_ports = f"{first + index * width}:{last if index + 1 == processes else first + (index + 1) * width - 1}"
        data = compare.run_one(name, binary, loader, clients // processes, packets // processes,
            size, window, "udp", min_seconds, workers // processes, local_ports)
        end = arrivals[index] - origin
        start = end - data["seconds"]
        return {"index": index + 1, "relay_ports": local_ports,
            "estimated_phase_start_seconds": round(start, 6),
            "estimated_phase_end_seconds": round(end, 6), "measurement": data}

    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=processes) as pool:
            results = list(pool.map(worker, range(processes)))
    finally:
        # All futures have finished and each run_one has closed its own children.
        compare.Server, compare.queue = original_server, original_queue

    starts = [row["estimated_phase_start_seconds"] for row in results]
    ends = [row["estimated_phase_end_seconds"] for row in results]
    span = max(ends) - min(starts)
    overlap = max(0.0, min(ends) - max(starts))
    forwarded = sum(row["measurement"]["delivered_forwarded_packets"] for row in results)
    return {"server": name, "processes": processes, "total_allocations": clients,
        "requested_total_load_workers": workers,
        "actual_total_load_workers": sum(row["measurement"]["load_workers"] for row in results),
        "payload_bytes": size, "window_per_load_worker": window,
        "delivered_forwarded_packets": forwarded,
        "estimated_enclosing_phase_seconds": round(span, 6),
        "estimated_overlapping_phase_seconds": round(overlap, 6),
        "estimated_overlap_fraction": round(overlap / span, 6),
        "estimated_aggregate_packets_per_second": round(forwarded / span, 1),
        "estimated_aggregate_payload_mbps": round(forwarded * size * 8 / span / 1e6, 1),
        "complete_server_cpu_seconds": round(sum(row["measurement"]["server_cpu_seconds"] for row in results), 6),
        "process_results": results}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--spry", type=Path, required=True)
    parser.add_argument("--coturn", type=Path, required=True)
    parser.add_argument("--loader", type=Path, required=True)
    parser.add_argument("--required-arch", choices=["arm64", "x86_64"])
    parser.add_argument("--source-id")
    parser.add_argument("--processes", type=int, choices=[1, 2], nargs="+", default=[1, 2])
    parser.add_argument("--runs", type=int, default=3)
    parser.add_argument("--clients", type=int, default=128)
    parser.add_argument("--workers", type=int, default=4)
    parser.add_argument("--packets", type=int, default=200000)
    parser.add_argument("--size", type=int, default=1200)
    parser.add_argument("--window", type=int, default=8)
    parser.add_argument("--min-seconds", type=float, default=3)
    parser.add_argument("--relay-ports", default="49160:49999")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    ports = re.fullmatch(r"([0-9]{1,5}):([0-9]{1,5})", args.relay_ports)
    if not (1 <= args.runs <= 10 and 1 <= args.clients <= 512 and 1 <= args.workers <= min(64, args.clients)
            and args.clients <= args.packets <= 100000000 and 8 <= args.size <= 1400 and 1 <= args.window <= 64
            and math.isfinite(args.min_seconds) and 0 <= args.min_seconds <= 60 and ports
            and 0 < int(ports[1]) <= int(ports[2]) <= 65535
            and int(ports[2]) - int(ports[1]) + 1 >= args.clients):
        parser.error("invalid finite workload bounds or relay-port range")
    if any(args.clients % n or args.workers % n or args.packets % n for n in args.processes):
        parser.error("clients, workers and packets must divide evenly across every process count")
    if args.source_id and not re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", args.source_id):
        parser.error("source-id must be a git commit or source-manifest SHA-256")
    if args.output.exists():
        parser.error("output already exists; preserve earlier evidence and choose another path")
    soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    desired = 4096 if hard == resource.RLIM_INFINITY else min(hard, 4096)
    resource.setrlimit(resource.RLIMIT_NOFILE, (max(soft, desired), hard))
    compare = load_compare()
    args.spry, args.coturn, args.loader = (path.resolve() for path in (args.spry, args.coturn, args.loader))
    identities = {name: compare.binary_identity(path)
                  for name, path in (("spry-turn", args.spry), ("coturn", args.coturn), ("loader", args.loader))}
    host_arch = "arm64" if platform.machine() in ("arm64", "aarch64") else platform.machine()
    required = args.required_arch or host_arch
    if required != host_arch or any(row["architectures"] != [required] for row in identities.values()):
        parser.error("all benchmark executables must match the native host architecture")
    output = {"schema": 1, "source_id": args.source_id, "binaries": identities,
        "machine": {"cpu": compare.cpu_brand(), "system": os.uname().sysname,
            "release": os.uname().release, "logical_cpus": os.cpu_count(),
            "process_descriptor_limit": resource.getrlimit(resource.RLIMIT_NOFILE)[0],
            "load_before": os.getloadavg()},
        "method": {"transport": "UDP ChannelData over loopback in both directions",
            "total_allocations": args.clients, "requested_total_load_workers": args.workers,
            "process_counts": args.processes, "minimum_seconds_per_process_phase": args.min_seconds,
            "coturn_relay_threads_per_process": 0, "relay_ports": args.relay_ports,
            "synchronisation": "All server readiness probes finish at a barrier before loaders launch. Each loader independently performs allocation setup, warm-up and sequential latency before its throughput phase.",
            "aggregate_timing": "Estimate each phase end from its flushed result-line arrival, then subtract the loader-reported elapsed seconds for phase start. Aggregate rate divides all delivered packets by the enclosing interval across all process phases; it is not the sum of individual rates. Pipe/scheduling delay adds uncertainty. Overlap fraction is recorded; inspect low overlap before drawing conclusions.",
            "limits": "Separately addressed processes with evenly partitioned allocations, client load workers and disjoint UDP relay-port ranges (to avoid cross-process port reuse). This does not implement shared-port multiworker support, request distribution, failover, maximum sustainable capacity or WAN acceptance. Each process has its own load-generator process and echo peers. Default per-process resource limits are retained, so aggregate configured server quotas increase with process count. CPU includes the complete server lifetime; RSS peaks and quiescent kernel socket snapshots are per process, not simultaneous total-memory measurements. Same-host generators and VM scheduling may limit scaling."}, "runs": []}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    current = None
    try:
        for repeat in range(args.runs):
            counts = args.processes if repeat % 2 == 0 else list(reversed(args.processes))
            for count in counts:
                servers = [("spry-turn", args.spry), ("coturn", args.coturn)]
                if repeat % 2:
                    servers.reverse()
                for name, binary in servers:
                    current = {"server": name, "processes": count, "repeat": repeat + 1}
                    row = run_group(compare, name, binary, args.loader, count, args.clients, args.workers,
                        args.packets, args.size, args.window, args.min_seconds, args.relay_ports)
                    row["repeat"] = repeat + 1
                    output["runs"].append(row)
                    args.output.write_text(json.dumps(output, indent=2) + "\n")
                    print(json.dumps({key: value for key, value in row.items() if key != "process_results"}), flush=True)
    except BaseException as error:
        # Subprocess exceptions can contain temporary paths. Keep the evidence
        # receipt path-free; the live command traceback remains local diagnostics.
        output["failures"] = [{**(current or {}), "exception_type": type(error).__name__}]
        raise
    finally:
        output["machine"]["load_after"] = os.getloadavg()
        args.output.write_text(json.dumps(output, indent=2) + "\n")


if __name__ == "__main__":
    main()
