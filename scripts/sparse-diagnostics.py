#!/usr/bin/env python3
"""Opt-in Linux phase attribution; never replaces the frozen performance gate."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import queue
import re
import subprocess
import threading
import time

from compare import Server, binary_identity, cpu_brand, finish

PHASES = ("before_setup", "after_setup", "after_warmup", "before_work", "after_work")
PROFILE = dict(name="tcp1_sparse", clients=1, packets=4000, size=160, window=1,
               transport="tcp", workers=1, rate=500)
BASELINE = "56232d52f0fbfd2f3795a50917890ed6c85e6dc9"
RELEASE = "4c58eece7566a1602475db79feefa3c1ae0c2604"
COUNTERS = ("cpu_ns", "runqueue_ns", "timeslices")


class DiagnosticError(ValueError):
    """Only fixed, non-sensitive protocol failures may enter a receipt."""


def parse_schedstat(text):
    fields = text.split()
    if len(fields) != 3 or any(not re.fullmatch(r"[0-9]+", value) for value in fields):
        raise DiagnosticError("unsupported schedstat counters")
    result = dict(zip(COUNTERS, map(int, fields)))
    if not result["cpu_ns"] or not result["timeslices"]:
        raise DiagnosticError("scheduler runtime counters unavailable")
    return result


class SchedulerObserver:
    """Require the relay's single thread; never mislabel one task as a process."""
    def __init__(self, pid, proc=Path("/proc")):
        self.pid = pid
        self.root = proc / str(pid)
        self.previous = None
        self.start_ticks = None
        self.proc = proc
        self.schedstats_enabled = None

    def snapshot(self, phase):
        before = time.monotonic_ns()
        setting = (self.proc / "sys/kernel/sched_schedstats").read_text().strip()
        if setting not in ("0", "1"):
            raise DiagnosticError("unsupported scheduler statistics setting")
        enabled = setting == "1"
        if self.schedstats_enabled is not None and enabled != self.schedstats_enabled:
            raise DiagnosticError("scheduler statistics setting changed")
        self.schedstats_enabled = enabled
        tasks = sorted(path.name for path in (self.root / "task").iterdir())
        if tasks != [str(self.pid)]:
            raise DiagnosticError("unsupported relay thread topology")
        # stat's comm field may contain spaces and parentheses.
        def start_time():
            text = (self.root / "stat").read_text().rsplit(")", 1)
            fields = text[1].split() if len(text) == 2 else []
            if len(fields) < 20 or not fields[19].isdigit():
                raise DiagnosticError("unsupported process identity counters")
            return int(fields[19])
        start_ticks = start_time()
        counters = parse_schedstat((self.root / "schedstat").read_text())
        if sorted(path.name for path in (self.root / "task").iterdir()) != tasks:
            raise DiagnosticError("relay thread topology changed during snapshot")
        if start_time() != start_ticks:
            raise DiagnosticError("relay process identity changed during snapshot")
        if self.start_ticks is not None and start_ticks != self.start_ticks:
            raise DiagnosticError("relay process identity changed")
        if self.previous and any(counters[name] < self.previous[name] for name in COUNTERS):
            raise DiagnosticError("scheduler counters regressed")
        self.start_ticks, self.previous = start_ticks, counters
        return dict(phase=phase, **{**counters, "runqueue_ns": counters["runqueue_ns"] if enabled else None},
                    observed_start_ns=before, observed_end_ns=time.monotonic_ns(), thread_count=1,
                    sched_schedstats=int(enabled),
                    runqueue_unavailable=None if enabled else "kernel scheduler statistics disabled")


def read_protocol(next_line, acknowledge, snapshot):
    """Validate all barriers before accepting the original final JSON result."""
    observations = []
    for phase in PHASES:
        line = next_line()
        if not line or len(line) > 65536:
            raise DiagnosticError("missing or oversized diagnostic marker")
        marker = json.loads(line)
        if marker != {"event": "spry-load-phase-v1", "phase": phase}:
            raise DiagnosticError(f"expected diagnostic boundary {phase}")
        observations.append(snapshot(phase))
        acknowledge()  # Never release a boundary whose observation failed.
    line = next_line()
    if not line or len(line) > 65536:
        raise DiagnosticError("missing or oversized final workload result")
    result = json.loads(line)
    if not isinstance(result, dict) or "event" in result or "round_trips" not in result:
        raise DiagnosticError("expected final workload result")
    return result, observations


def phase_intervals(observations):
    if [row["phase"] for row in observations] != list(PHASES):
        raise DiagnosticError("incomplete diagnostic phase sequence")
    result = []
    for before, after in zip(observations, observations[1:]):
        deltas = {name: after[name] - before[name] if before[name] is not None and after[name] is not None else None
                  for name in COUNTERS}
        if any(value is not None and value < 0 for value in deltas.values()):
            raise DiagnosticError("diagnostic interval counters regressed")
        result.append(dict(start=before["phase"], end=after["phase"], **deltas))
    return result


def release_loader(process):
    """Keep stdout on one TextIOWrapper: communicate can bypass prefetched text."""
    process.stdin.write("\n")
    process.stdin.flush()
    process.wait(timeout=3)
    trailing = process.stdout.read(65537)
    if process.returncode or trailing:
        raise DiagnosticError("diagnostic loader failed or emitted trailing output")


def validate_manifest(manifest, identities, source, rustc):
    expected = dict(baseline=BASELINE, release=RELEASE, loader=source)
    if manifest.get("schema") != 1 or set(manifest.get("builds", {})) != set(expected):
        raise DiagnosticError("missing diagnostic build provenance")
    for name, sha in expected.items():
        build = manifest["builds"][name]
        if (build.get("source") != sha or build.get("sha256") != identities[name]["sha256"]
                or build.get("rustc") != rustc or build.get("profile") != "release"
                or build.get("features") != ["tls"] or build.get("locked") is not True
                or build.get("target") != ("example:load" if name == "loader" else "bin:spry-turn")):
            raise DiagnosticError("diagnostic build provenance mismatch")
    return manifest


def run_one(binary, loader):
    fixture = Server(binary, coturn=False, tls=False)
    process = reader = None
    try:
        observer = SchedulerObserver(fixture.process.pid)
        ready = observer.snapshot("server_ready")
        command = [str(loader), f"127.0.0.1:{fixture.port}", "1", "4000", "160", "1",
                   "--transport", "tcp", "--workers", "1", "--rate", "500",
                   "--diagnostic-phases", "1", "--resource-hold-ms", "30000"]
        process = subprocess.Popen(command, env={**os.environ, "SPRY_TURN_SECRET": fixture.secret},
                                   stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, text=True)
        output = queue.Queue(maxsize=len(PHASES) + 1)
        def read_lines():
            for _ in range(len(PHASES) + 1):
                line = process.stdout.readline(65537)
                output.put(line)
                if not line:
                    break
        reader = threading.Thread(target=read_lines, daemon=True)
        reader.start()
        deadline = time.monotonic() + 90
        def next_line():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise DiagnosticError("diagnostic workload exceeded finite timeout")
            try:
                return output.get(timeout=remaining)
            except queue.Empty:
                raise DiagnosticError("diagnostic workload exceeded finite timeout") from None
        def acknowledge():
            process.stdin.write("+")
            process.stdin.flush()
        result, observations = read_protocol(next_line, acknowledge, observer.snapshot)
        if process.poll() is not None:
            raise DiagnosticError("loader exited before resource release")
        final = observer.snapshot("before_release")
        reader.join(timeout=1)
        if reader.is_alive():
            raise DiagnosticError("diagnostic reader did not finish")
        release_loader(process)
        cpu = finish(fixture)
        result.update(server_cpu_seconds=cpu, scheduler_ready=ready,
                      scheduler_before_release=final, phase_snapshots=observations,
                      phase_intervals=phase_intervals(observations))
        return result
    finally:
        if process is not None:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    process.kill(); process.wait()
            if reader:
                reader.join(timeout=1)
            for stream in (process.stdin, process.stdout, process.stderr):
                stream.close()
        fixture.close()


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("baseline", "release", "loader", "output", "manifest"):
        parser.add_argument(f"--{name}", type=Path, required=True)
    args = parser.parse_args()
    if platform.system() != "Linux" or args.output.exists():
        parser.error("requires Linux and a fresh receipt; failed receipts must be retained")
    if subprocess.check_output(["git", "status", "--porcelain", "--untracked-files=no"], text=True):
        parser.error("diagnostic checkout must be clean")
    rustc = subprocess.check_output(["rustc", "--version"], text=True).strip()
    if not rustc.startswith("rustc 1.94.1 "):
        parser.error("diagnostic attribution is pinned to Rust 1.94.1")
    spec = importlib.util.spec_from_file_location("frozen_qualification", Path(__file__).with_name("qualify-tcp.py"))
    frozen = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(frozen)
    for name in ("scripts/qualify-tcp.py", "scripts/compare.py",
                 "docs/tcp-hosted-qualification-2026-11-11.md", ".github/workflows/perf-tcp.yml",
                 "tests/interop.py", "tests/test_qualify_tcp.py"):
        if Path(name).read_bytes() != subprocess.check_output(["git", "show", f"{RELEASE}:{name}"]):
            parser.error("frozen qualification inputs differ from the release")
    paths = {name: getattr(args, name).resolve() for name in ("baseline", "release", "loader")}
    identities = {name: binary_identity(path) for name, path in paths.items()}
    native = "arm64" if platform.machine() in ("arm64", "aarch64") else platform.machine()
    if any(item["architectures"] != [native] for item in identities.values()):
        parser.error("all executables must be native")
    source = subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip()
    manifest = validate_manifest(json.loads(args.manifest.read_text()), identities, source, rustc)
    scripts = {name: digest(name) for name in ("scripts/sparse-diagnostics.py", "scripts/compare.py",
                "scripts/qualify-tcp.py", "examples/load.rs", "tests/interop.py",
                "tests/test_sparse_diagnostics.py", ".github/workflows/sparse-diagnostics.yml",
                "docs/sparse-cpu-diagnostics-2026-11-11.md")}
    receipt = dict(schema=1, kind="sparse-cpu-phase-diagnostic", qualification_pass=None,
                   complete=False, sources=dict(baseline=BASELINE, release=RELEASE, loader=source),
                   binaries=identities, build_manifest=manifest, scripts=scripts,
                   host=dict(cpu=cpu_brand(), kernel=platform.release(), rustc=rustc,
                             affinity=sorted(os.sched_getaffinity(0))),
                   method=dict(profile=PROFILE, pairs=4, order="AB, BA, AB, BA",
                       stages=["release_vs_itself", "baseline_vs_release"],
                       scheduler_units="nanoseconds; unit does not establish nanosecond accuracy",
                       scope="diagnostic barriers perturb scheduling; phase counters are not the frozen wait4 guard",
                       frozen_guards_unchanged=True, adoption_claim=False), runs=[], failures=[])
    args.output.parent.mkdir(parents=True, exist_ok=True)
    def save():
        args.output.write_text(json.dumps(receipt, indent=2) + "\n")
    save()
    active = None
    try:
        for stage in receipt["method"]["stages"]:
            arms = {"A": paths["release"] if stage == "release_vs_itself" else paths["baseline"],
                    "B": paths["release"]}
            for pair in range(1, 5):
                for arm in (("A", "B") if pair % 2 else ("B", "A")):
                    active = dict(stage=stage, pair=pair, arm=arm)
                    idle = frozen.idle_probe()
                    before = frozen.snapshot()
                    row = run_one(arms[arm], paths["loader"])
                    after = frozen.snapshot()
                    host = frozen.cpu_delta(before, after)
                    row.update(**active, idle_probe=idle, host_active=host,
                               validity_failures=frozen.host_failures(idle, host) + frozen.row_failures(row, PROFILE))
                    receipt["runs"].append(row)
                    save()
                    if row["validity_failures"]:
                        raise DiagnosticError("diagnostic host or useful-work validity failed")
        receipt["complete"] = True
    except Exception as error:
        # Record a bounded class and phase; logs may contain fixture secrets.
        receipt["failures"].append(dict(kind=type(error).__name__, active=active,
            reason=str(error) if isinstance(error, DiagnosticError) else "unexpected diagnostic failure; inspect task-local logs"))
    finally:
        try:
            receipt["binaries_after"] = {name: binary_identity(path) for name, path in paths.items()}
            receipt["scripts_after"] = {name: digest(name) for name in scripts}
            if receipt["binaries_after"] != identities or receipt["scripts_after"] != scripts:
                raise DiagnosticError("diagnostic input identity changed")
        except Exception as error:
            receipt["complete"] = False
            receipt["failures"].append(dict(kind="final_identity_check_failed", error_class=type(error).__name__))
        save()
    if not receipt["complete"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
