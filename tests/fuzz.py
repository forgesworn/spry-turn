#!/usr/bin/env python3
"""Bounded, genuine libFuzzer coverage run; generated corpus stays ignored."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import time

from interop import attr, packet, COOKIE, TRANSPORT, USERNAME, PEER


def positive(value):
    result = int(value)
    if not 1 <= result <= 86_400:
        raise argparse.ArgumentTypeError("must be between 1 and 86400")
    return result


def seed_corpus(directory):
    directory.mkdir(parents=True, exist_ok=True)
    values = [b"", b"\0", b"\x80\0\0\0", b"\x40\0\0\0",
              b"\x4f\xff\0\x01a\0\0\0", b"\0" * 20]
    for method in (1, 3, 4, 6, 8, 9):
        for fields in ([], [(TRANSPORT, b"\x11\0\0\0")],
                       [(USERNAME, b"1000:generated"), (PEER, b"\0\x01\0\0" + b"\0" * 4)]):
            values.append(packet(method, fields, tid=bytes(12)))
            values.append(packet(method, fields, key=b"generated fuzz key", tid=bytes(12)))
    # A valid envelope without FINGERPRINT permits structural attribute mutation.
    for size in (0, 1, 3, 4, 20, 256, 4096, 65_400):
        body = attr(USERNAME, bytes(size))
        values.append(b"\0\x01" + len(body).to_bytes(2, "big") + COOKIE.to_bytes(4, "big") + bytes(12) + body)
    for value in values:
        if value:
            (directory / hashlib.sha256(value).hexdigest()).write_bytes(value)


def corpus_identity(directory):
    contents = sorted(hashlib.sha256(path.read_bytes()).hexdigest()
                      for path in directory.iterdir() if path.is_file())
    return {"files": len(contents),
            "sha256": hashlib.sha256("\n".join(contents).encode()).hexdigest()}


def stop_group(process):
    # cargo-fuzz starts the instrumented executable as a child. Reap cargo and
    # stop the whole task-owned group even if cargo exits before its child.
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    try:
        process.wait(timeout=3)
    except subprocess.TimeoutExpired:
        pass
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    process.wait(timeout=3)


def run_bounded(command, root, stream, timeout, quiet=False):
    process = subprocess.Popen(command, cwd=root,
                               stdout=subprocess.DEVNULL if quiet else stream,
                               stderr=stream, start_new_session=True)
    try:
        return process.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        stop_group(process)
        return 124
    except BaseException:
        stop_group(process)
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--seconds", type=positive, default=180)
    parser.add_argument("--seed", type=positive, default=7411)
    parser.add_argument("--toolchain", default="nightly")
    parser.add_argument("--output", type=Path, default=Path(".local/fuzz/receipt.json"))
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    scratch = root / ".local/fuzz"
    corpus, artifacts = scratch / "corpus/wire", scratch / "artifacts"
    seed_corpus(corpus)
    initial_corpus = corpus_identity(corpus)
    source_paths = tuple(map(Path, ("src/lib.rs", "src/limits.rs", "src/wire.rs", "src/auth.rs", "Cargo.toml",
                                    "fuzz/fuzz_targets/wire.rs", "fuzz/Cargo.lock",
                                    "fuzz/Cargo.toml", "tests/fuzz.py", "tests/interop.py")))
    source_hashes = {str(path): hashlib.sha256((root / path).read_bytes()).hexdigest()
                     for path in source_paths}
    artifacts.mkdir(parents=True, exist_ok=True)
    before = {p.name for p in artifacts.iterdir()}
    log = scratch / "wire.log"
    command = ["cargo", f"+{args.toolchain}", "fuzz", "run", "--target-dir", str(root / "target"),
               "--sanitizer", "address", "wire", str(corpus), "--",
               f"-max_total_time={args.seconds}", f"-seed={args.seed}", "-max_len=65536",
               "-timeout=5", "-rss_limit_mb=768", "-print_final_stats=1",
               f"-artifact_prefix={artifacts}{os.sep}"]
    started = time.monotonic()
    with log.open("w") as stream:
        try:
            # Reject a stale lock before cargo-fuzz builds the isolated project.
            status = run_bounded(["cargo", f"+{args.toolchain}", "metadata", "--locked",
                                  "--format-version", "1", "--manifest-path", "fuzz/Cargo.toml"],
                                 root, stream, timeout=30, quiet=True)
            if status == 0:
                status = run_bounded(command, root, stream, timeout=args.seconds + 600)
        except KeyboardInterrupt:
            status = 130
    content = log.read_text(errors="replace")
    done = re.findall(r"#(\d+)\s+DONE\s+cov:\s*(\d+)\s+ft:\s*(\d+).*?exec/s:\s*(\d+)", content)
    executions = re.findall(r"stat::number_of_executed_units:\s*(\d+)", content)
    peak_rss = re.findall(r"stat::peak_rss_mb:\s*(\d+)", content)
    new_artifacts = sorted({p.name for p in artifacts.iterdir()} - before)
    source_unchanged = all(hashlib.sha256((root / path).read_bytes()).hexdigest() == source_hashes[str(path)]
                           for path in source_paths)
    receipt = {
        "schema": 1, "engine": "libFuzzer", "coverage_guided": True,
        "target": "fuzz/fuzz_targets/wire.rs", "sanitizer": "address",
        "toolchain": args.toolchain, "seed": args.seed, "requested_seconds": args.seconds,
        "elapsed_seconds_including_build": round(time.monotonic() - started, 3),
        "returncode": status, "completed": status == 0 and bool(done) and not new_artifacts and source_unchanged,
        "executions": int(executions[-1]) if executions else None,
        "coverage_edges": int(done[-1][1]) if done else None,
        "coverage_features": int(done[-1][2]) if done else None,
        "final_executions_per_second": int(done[-1][3]) if done else None,
        "corpus_files": sum(p.is_file() for p in corpus.iterdir()),
        "initial_corpus": initial_corpus, "final_corpus": corpus_identity(corpus),
        "new_crash_artifact_count": len(new_artifacts),
        "fuzzer_peak_rss_mb": int(peak_rss[-1]) if peak_rss else None,
        "source_sha256": [{"path": path, "sha256": digest} for path, digest in source_hashes.items()],
        "source_unchanged_during_run": source_unchanged,
        "limits": "Parser/auth/codec in process; no network/runtime fuzzing or independent security review.",
    }
    output = args.output if args.output.is_absolute() else root / args.output
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(receipt, indent=2) + "\n")
    print(json.dumps(receipt, indent=2))
    if not receipt["completed"]:
        print("Fuzzing did not complete; inspect the ignored .local/fuzz/wire.log and artifacts.")
        raise SystemExit(1)


if __name__ == "__main__":
    main()
