#!/usr/bin/env python3
"""Run the whole bare-metal qualification on one dedicated Linux machine.

Run it from a clean checkout of the commit to qualify. It builds each baseline
in a temporary worktree and the candidate in the checkout, with the toolchain
the hosted campaigns used, then runs every campaign once:

- the TCP protocol (scripts/qualify-tcp.py) against each TCP baseline;
- the control-request protocol (scripts/qualify-control.py) against its baseline.

A failed campaign is a result, not a reason to rerun: every receipt is kept and
the summary lists each one's failures. See docs/bare-metal-qualification.md.
"""
import argparse
import datetime
import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import sys

TOOLCHAIN = "1.94.1"
# The baseline of every hosted campaign, and `main` before the request-budget change.
TCP_BASELINES = ["56232d52f0fbfd2f3795a50917890ed6c85e6dc9", "f194ddf16b8aa43773c4ced897c118fbe2463859"]
CONTROL_BASELINE = "f194ddf16b8aa43773c4ced897c118fbe2463859"


def run(command, **kwargs):
    print("+ " + " ".join(str(part) for part in command), flush=True)
    return subprocess.run(command, check=True, **kwargs)


def output(command):
    return subprocess.check_output(command, text=True).strip()


def build_relay(root, env):
    run(["cargo", "build", "--locked", "--release", "--features", "tls", "--bin", "spry-turn"], cwd=root, env=env)
    return root / "target/release/spry-turn"


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--tcp-baseline", action="append", help="full commit SHA; repeatable (default: %s)" % ", ".join(TCP_BASELINES))
    parser.add_argument("--control-baseline", default=CONTROL_BASELINE, help="full commit SHA")
    parser.add_argument("--skip-tcp", action="store_true", help="run only the control-request campaign")
    parser.add_argument("--output-dir", type=Path, help="default: .local/bare-metal/<UTC date and time>")
    args = parser.parse_args()
    tcp_baselines = [] if args.skip_tcp else (args.tcp_baseline or TCP_BASELINES)
    for sha in tcp_baselines + [args.control_baseline]:
        if not re.fullmatch(r"[0-9a-f]{40}", sha):
            parser.error(f"baseline must be a full commit SHA: {sha}")
    if platform.system() != "Linux":
        parser.error("the qualification protocols require Linux")
    repo = Path(output(["git", "rev-parse", "--show-toplevel"]))
    os.chdir(repo)
    candidate = output(["git", "rev-parse", "HEAD"])
    if output(["git", "status", "--porcelain", "--untracked-files=no"]):
        parser.error("the checkout must be clean: it is the candidate")
    for sha in tcp_baselines + [args.control_baseline]:
        if subprocess.run(["git", "cat-file", "-e", sha + "^{commit}"], capture_output=True).returncode:
            parser.error(f"baseline {sha} is not in this clone; fetch it first")
    if shutil.which("rustup") is None or TOOLCHAIN not in output(["rustup", "toolchain", "list"]):
        parser.error(f"install the pinned toolchain first: rustup toolchain install {TOOLCHAIN} --profile minimal")
    # Check the benchmarking addresses before spending time on builds.
    sys.path.insert(0, str(repo / "scripts"))
    import importlib.util
    spec = importlib.util.spec_from_file_location("qualify_control", repo / "scripts/qualify-control.py")
    control = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(control)
    if not control.sources_are_local():
        parser.error("198.18.0.0/16 is not local; run `sudo ip route add local 198.18.0.0/16 dev lo` first")
    if len(os.sched_getaffinity(0)) < 4:
        parser.error("needs at least four usable cores: the control-request probe keeps one busy")

    stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    out = (args.output_dir or repo / ".local/bare-metal" / stamp).resolve()
    if out.exists() and any(out.iterdir()):
        parser.error(f"{out} is not empty; receipts are never overwritten")
    bin_dir, worktree = out / "bin", out / "worktree"
    bin_dir.mkdir(parents=True)
    env = {**os.environ, "RUSTUP_TOOLCHAIN": TOOLCHAIN, "CARGO_INCREMENTAL": "0"}
    results = []
    try:
        run(["git", "worktree", "add", "--detach", str(worktree), candidate])
        for sha in dict.fromkeys(tcp_baselines + [args.control_baseline]):
            run(["git", "checkout", "--quiet", "--detach", sha], cwd=worktree)
            shutil.copy2(build_relay(worktree, env), bin_dir / f"spry-turn-{sha}")
        run(["cargo", "build", "--locked", "--release", "--features", "tls", "--bin", "spry-turn",
             "--example", "load", "--example", "control-probe"], env=env)
        shutil.copy2(repo / "target/release/spry-turn", bin_dir / "candidate")
        shutil.copy2(repo / "target/release/examples/load", bin_dir / "load")
        shutil.copy2(repo / "target/release/examples/control-probe", bin_dir / "control-probe")
        campaigns = [("tcp", sha) for sha in tcp_baselines] + [("control", args.control_baseline)]
        for kind, sha in campaigns:
            receipt = out / f"{kind}-{candidate[:7]}-vs-{sha[:7]}.json"
            if kind == "tcp":
                command = [sys.executable, "scripts/qualify-tcp.py", "--loader", bin_dir / "load"]
            else:
                command = [sys.executable, "scripts/qualify-control.py", "--probe", bin_dir / "control-probe"]
            command += ["--parent", bin_dir / f"spry-turn-{sha}", "--candidate", bin_dir / "candidate",
                        "--parent-source", sha, "--candidate-source", candidate, "--output", receipt]
            print("+ " + " ".join(str(part) for part in command), flush=True)
            code = subprocess.run(command, env=env).returncode
            data = json.loads(receipt.read_text()) if receipt.exists() else {}
            results.append({"campaign": kind, "baseline": sha, "exit": code, "receipt": receipt.name,
                            "pass": data.get("pass", False), "failures": data.get("failures", ["no receipt"]),
                            "profile_failures": {r["profile"]: r["failures"] for r in data.get("profile_results", []) if r["failures"]}})
    finally:
        if worktree.exists():
            subprocess.run(["git", "worktree", "remove", "--force", str(worktree)])
        shutil.rmtree(bin_dir, ignore_errors=True)
    summary = {"candidate": candidate, "toolchain": TOOLCHAIN, "campaigns": results}
    (out / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    print(json.dumps(summary, indent=2))
    print(f"Receipts are in {out}. Record them as they are; do not rerun a failed campaign.")
    return 0 if results and all(r["pass"] for r in results) else 1


if __name__ == "__main__":
    sys.exit(main())
