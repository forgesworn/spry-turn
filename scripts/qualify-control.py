#!/usr/bin/env python3
"""Predeclared, Linux-only paired control-request qualification; never replaces failed rows.

Each row starts a fresh relay on 198.18.0.1 and runs the fixed-rate control
probe from 1,000 source addresses in 198.18.0.0/16, which must be local, for
example after `sudo ip route add local 198.18.0.0/16 dev lo`. The measured
cost is the relay's own CPU, so the comparison shows what per-source request
budgets and the nonce check add to ordinary control traffic. It is not a flood
and stays inside every budget of both arms.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import re
import resource
import secrets
import socket
import statistics
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, str(Path(__file__).resolve().parent))
from compare import binary_identity, cpu_brand, finish  # noqa: E402

_spec = importlib.util.spec_from_file_location("qualify_tcp", Path(__file__).resolve().parent / "qualify-tcp.py")
qualify_tcp = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(qualify_tcp)

# `main` before the request-budget change (#75).
PARENT = "f194ddf16b8aa43773c4ced897c118fbe2463859"
PAIRS = 4
SERVER = "198.18.0.1"
FIRST_SOURCE = "198.18.1.0"
SOURCES = 1000
PROFILES = [
    dict(name="bare", mode="bare", sources=SOURCES, requests=30000, rate=1000),
    dict(name="nonce", mode="nonce", sources=SOURCES, requests=30000, rate=1000),
]
GUARDS = {
    "idle_fraction_min": 0.95, "steal_fraction_max": 0.005,
    "idle_scheduler_p99_ms_max": 10, "idle_scheduler_max_ms_max": 50,
    "missed_dispatch_fraction_max": 0.01,
    "control_cpu_one_core_delta_max": 0.002,
}
SCRIPTS = ("scripts/qualify-control.py", "scripts/qualify-tcp.py", "scripts/compare.py", "examples/control_probe.rs")


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def sources_are_local():
    """True when the relay address and every probe source can be bound."""
    first = int.from_bytes(socket.inet_aton(FIRST_SOURCE), "big")
    for address in (SERVER, FIRST_SOURCE, socket.inet_ntoa((first + SOURCES - 1).to_bytes(4, "big"))):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
            try:
                probe.bind((address, 0))
            except OSError:
                return False
    return True


def free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
        probe.bind((SERVER, 0))
        return probe.getsockname()[1]


def binding(transaction):
    return (0x0001).to_bytes(2, "big") + (0).to_bytes(2, "big") + (0x2112A442).to_bytes(4, "big") + transaction


class Relay:
    """A fresh relay listening only on the benchmarking address."""

    def __init__(self, binary):
        self.temp = tempfile.TemporaryDirectory(prefix="spry-control-")
        self.log = (Path(self.temp.name) / "startup.log").open("w+")
        self.port = free_port()
        self.process = subprocess.Popen(
            [str(binary), "serve", "--listen", f"{SERVER}:{self.port}", "--bytes-per-second", "1073741824",
             "--max-connections", "1024", "--relay-ports", "49160:49999"],
            env={**os.environ, "SPRY_TURN_SECRET": secrets.token_hex(32)}, stdout=self.log, stderr=self.log)
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
                probe.bind((SERVER, 0))
                probe.settimeout(0.1)
                for attempt in range(100):
                    if self.process.poll() is not None:
                        break
                    transaction = attempt.to_bytes(12, "big")
                    probe.sendto(binding(transaction), (SERVER, self.port))
                    try:
                        reply = probe.recv(2048)
                        if reply[:2] == b"\x01\x01" and reply[8:20] == transaction:
                            return
                    except (socket.timeout, ConnectionRefusedError):
                        pass
            # Do not copy server logs into evidence: they can contain paths or configuration.
            raise RuntimeError("relay did not become ready; inspect local temporary logs while debugging")
        except BaseException:
            self.close()
            raise

    def close(self):
        if self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                self.process.kill(); self.process.wait()
        self.log.close()
        self.temp.cleanup()


def run_one(name, binary, probe, profile):
    relay = Relay(binary)
    try:
        time.sleep(0.15)
        command = [str(probe), f"{SERVER}:{relay.port}", "--mode", profile["mode"], "--first-source", FIRST_SOURCE,
                   "--sources", str(profile["sources"]), "--requests", str(profile["requests"]), "--rate", str(profile["rate"])]
        timeout = 60 + profile["requests"] / profile["rate"] * 2
        result = subprocess.run(command, capture_output=True, text=True, timeout=timeout)
        if result.returncode:
            raise RuntimeError(f"{name} probe failed: {result.stderr.strip()}")
        data = json.loads(result.stdout.splitlines()[-1])
        cpu = finish(relay)
        data.update(server=name, server_cpu_seconds=round(cpu, 6))
        return data
    finally:
        relay.close()


def row_failures(row, profile):
    failures = []
    for key in ("mode", "sources", "requests"):
        if row[key] != profile[key]:
            failures.append(f"{key} mismatch")
    if row["offered_requests_per_second"] != profile["rate"]:
        failures.append("offered rate mismatch")
    if row["answered"] != profile["requests"] or row["unanswered"] or row["unexpected_responses"]:
        failures.append("useful work mismatch")
    if row["missed_dispatch_slots"] / profile["requests"] > GUARDS["missed_dispatch_fraction_max"]:
        failures.append("probe missed offered schedule")
    expected = (profile["requests"] - 1) / profile["rate"]
    if not expected <= row["seconds"] <= expected * 1.01 + 0.01:
        failures.append("probe elapsed time outside offered schedule")
    return failures


def evaluate_profile(rows):
    """The paired CPU guard is binding; no adverse pair is trimmed or replaced."""
    if len(rows) != PAIRS * 2:
        return {"pass": False, "failures": ["incomplete profile"], "metrics": {}}
    pairs = []
    for pair in range(1, PAIRS + 1):
        arms = {row["server"]: row for row in rows if row["pair"] == pair}
        if set(arms) != {"parent", "candidate"}:
            return {"pass": False, "failures": ["missing paired arm"], "metrics": {}}
        pairs.append((arms["parent"], arms["candidate"]))
    utilisation = [c["server_cpu_seconds"] / c["seconds"] - p["server_cpu_seconds"] / p["seconds"] for p, c in pairs]
    per_request = [c["cpu_seconds_per_request"] / p["cpu_seconds_per_request"] for p, c in pairs]
    p99 = [c["round_trip_p99_us"] / p["round_trip_p99_us"] if p["round_trip_p99_us"] else None for p, c in pairs]
    metrics = {
        "cpu_one_core_utilisation_delta": {"deltas": utilisation, "median": statistics.median(utilisation),
                                           "maximum": max(utilisation)},
        "cpu_seconds_per_request": {"ratios": per_request, "median_ratio": statistics.median(per_request)},
        # Diagnostic only: the probe's round trip includes its own scheduling.
        "round_trip_p99_us": {"ratios": p99},
        "late_answers": {"parent": [p["late_answers"] for p, _ in pairs], "candidate": [c["late_answers"] for _, c in pairs]},
    }
    failures = []
    if max(utilisation) > GUARDS["control_cpu_one_core_delta_max"]:
        failures.append("control-request absolute CPU overhead guard")
    return {"pass": not failures, "failures": failures, "metrics": metrics}


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    for arm in ("parent", "candidate", "probe"):
        parser.add_argument(f"--{arm}", type=Path, required=True)
    parser.add_argument("--candidate-source", required=True)
    parser.add_argument("--parent-source", default=PARENT)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if platform.system() != "Linux" or args.output.exists():
        parser.error("requires Linux and a fresh output path; failed receipts must be preserved")
    if not re.fullmatch(r"[0-9a-f]{40}", args.parent_source):
        parser.error("parent source must be a full commit SHA")
    if len(os.sched_getaffinity(0)) < 4:
        parser.error("needs at least four usable cores: the probe keeps one busy")
    if not sources_are_local():
        parser.error("198.18.0.0/16 is not local; run `sudo ip route add local 198.18.0.0/16 dev lo` first")
    head = subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip()
    if head != args.candidate_source or subprocess.check_output(["git", "status", "--porcelain", "--untracked-files=no"], text=True):
        parser.error("candidate checkout must be exact and clean")
    paths = {arm: getattr(args, arm).resolve() for arm in ("parent", "candidate", "probe")}
    identities = {arm: binary_identity(path) for arm, path in paths.items()}
    native = "arm64" if platform.machine() in ("arm64", "aarch64") else platform.machine()
    if any(value["architectures"] != [native] for value in identities.values()):
        parser.error("executables must have the native architecture")
    soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    need = SOURCES + 256
    resource.setrlimit(resource.RLIMIT_NOFILE, (min(hard, max(soft, need)) if hard >= 0 else max(soft, need), hard))
    scripts = {name: digest(name) for name in SCRIPTS}
    receipt = {"schema": 1, "kind": "spry-control-qualification", "source": {"parent": args.parent_source, "candidate": head},
               "binaries": identities, "scripts": scripts,
               "method": {"pairs": PAIRS, "order": "AB, BA, AB, BA", "profiles": PROFILES, "guards": GUARDS,
                          "no_replacement_rows": True, "server": SERVER, "first_source": FIRST_SOURCE,
                          "cpu_scope": "relay lifetime including startup, one challenge per source and shutdown",
                          "scope": "fixed-rate UDP Binding requests from 1,000 local benchmarking addresses at 1 a second each; "
                                   "within every request budget of both arms; not a flood, WAN or capacity measurement"},
               "host": {"cpu": cpu_brand(), "kernel": platform.release(), "affinity": sorted(os.sched_getaffinity(0)),
                        "rustc": subprocess.check_output(["rustc", "--version"], text=True).strip(),
                        "cpu_timer": "os.wait4 rusage user+system seconds, microsecond fields; stored to six decimals"},
               "runs": [], "profile_results": [], "failures": []}
    receipt["source_trees"] = {arm: subprocess.check_output(["git", "rev-parse", source + "^{tree}"], text=True).strip()
                               for arm, source in receipt["source"].items()}
    args.output.parent.mkdir(parents=True, exist_ok=True)

    def save():
        args.output.write_text(json.dumps(receipt, indent=2) + "\n")
    save()
    active = None
    try:
        for profile in PROFILES:
            for pair in range(1, PAIRS + 1):
                for arm in (("parent", "candidate") if pair % 2 else ("candidate", "parent")):
                    active = {"profile": profile["name"], "pair": pair, "arm": arm}
                    idle = qualify_tcp.idle_probe()
                    before = qualify_tcp.snapshot()
                    row = run_one(arm, paths[arm], paths["probe"], profile)
                    after = qualify_tcp.snapshot()
                    row.update(profile=profile["name"], pair=pair, idle_probe=idle,
                               host_active={"before": before, "after": after, **qualify_tcp.cpu_delta(before, after)})
                    row["cpu_seconds_per_request"] = row["server_cpu_seconds"] / (row["requests"] + row["setup_requests"])
                    row["failures"] = qualify_tcp.host_failures(idle, row["host_active"]) + row_failures(row, profile)
                    receipt["runs"].append(row)
                    save()
                    print(json.dumps({**active, "cpu_seconds": row["server_cpu_seconds"], "failures": row["failures"]}), flush=True)
            rows = [row for row in receipt["runs"] if row["profile"] == profile["name"]]
            receipt["profile_results"].append({"profile": profile["name"], **evaluate_profile(rows)})
            save()
        if any(row["failures"] for row in receipt["runs"]):
            receipt["failures"].append("host validity, offered schedule or useful-work guard failed; no adoption")
        if any(not result["pass"] for result in receipt["profile_results"]):
            receipt["failures"].append("paired control-request CPU guard failed; no adoption")
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
