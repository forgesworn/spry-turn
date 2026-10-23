#!/usr/bin/env python3
"""Train an instrumented finite embedding host, allowing normal profile exit."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import time

import compare


def validate_profile(tool, directory):
    raw = sorted(directory.glob("*.profraw"))
    if not raw:
        raise RuntimeError("no raw profile files were produced")
    merged = directory / "merged.profdata"
    subprocess.run([str(tool), "merge", "-o", str(merged), *map(str, raw)],
                   check=True, timeout=30, capture_output=True, text=True)
    summary = subprocess.run([str(tool), "show", str(merged)], check=True,
                             timeout=10, capture_output=True, text=True).stdout
    counts = {}
    for key, label in (("maximum_function_count", "Maximum function count"),
                       ("total_count", "Total count")):
        found = re.search(rf"^{label}: ([0-9]+)$", summary, re.MULTILINE)
        if not found or int(found[1]) == 0:
            raise RuntimeError("profile contains no usable execution counters")
        counts[key] = int(found[1])
    return {"raw_files": len(raw), "merged_sha256": hashlib.sha256(merged.read_bytes()).hexdigest(),
            **counts, "nonzero_counters_verified": True}


def finish_normally(fixture):
    # LLVM writes the profile at normal exit. Sending SIGTERM to the real
    # standalone service does not run its exit handlers and loses counters.
    deadline = time.monotonic() + 8
    process = fixture.process
    while time.monotonic() < deadline:
        pid, status, usage = os.wait4(process.pid, os.WNOHANG)
        if pid:
            process.returncode = os.waitstatus_to_exitcode(status)
            if process.returncode:
                raise RuntimeError("finite profile host did not exit successfully")
            return usage.ru_utime + usage.ru_stime
        time.sleep(0.02)
    raise RuntimeError("finite profile host exceeded its exit deadline")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--server", type=Path, required=True)
    parser.add_argument("--loader", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--profile-dir", type=Path)
    parser.add_argument("--profdata-tool", type=Path)
    args = parser.parse_args()
    if bool(args.profile_dir) != bool(args.profdata_tool):
        parser.error("--profile-dir and --profdata-tool must be supplied together")
    args.server, args.loader = args.server.resolve(), args.loader.resolve()
    output = {"schema": 1, "purpose": "PGO training, not a performance comparison",
              "server": compare.binary_identity(args.server),
              "loader": compare.binary_identity(args.loader), "runs": [], "complete": False}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    original_finish = compare.finish
    previous_duration = os.environ.get("SPRY_PROFILE_SECONDS")
    compare.finish = finish_normally
    os.environ["SPRY_PROFILE_SECONDS"] = "5"
    try:
        for transport in ("udp", "tcp", "tls"):
            for size in (160, 1200):
                row = compare.run_one("finite-profile-host", args.server, args.loader,
                                      16, 10_000, size, 8, transport, 1)
                output["runs"].append(row)
                args.output.write_text(json.dumps(output, indent=2) + "\n")
        if args.profile_dir:
            output["profile"] = validate_profile(args.profdata_tool.resolve(), args.profile_dir.resolve())
        output["complete"] = True
    finally:
        compare.finish = original_finish
        if previous_duration is None:
            os.environ.pop("SPRY_PROFILE_SECONDS", None)
        else:
            os.environ["SPRY_PROFILE_SECONDS"] = previous_duration
        args.output.write_text(json.dumps(output, indent=2) + "\n")
    print(json.dumps({"complete": True, "training_runs": len(output["runs"])}))


if __name__ == "__main__":
    main()
