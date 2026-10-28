#!/usr/bin/env python3
"""Package already checked Linux executables; never compile or start a service."""
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tarfile


ROOT = Path(__file__).resolve().parents[1]


def output(*args):
    return subprocess.check_output(args, cwd=ROOT, text=True).strip()


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def elf_metadata(path):
    header = output("readelf", "--file-header", str(path))
    fields = {}
    for label in ("Class", "Data", "Machine"):
        fields[label.lower()] = re.search(rf"^\s*{label}:\s*(.+)$", header, re.M)[1]
    if fields["class"] != "ELF64" or fields["machine"] != "Advanced Micro Devices X86-64":
        raise RuntimeError("Expected a Linux x86_64 ELF executable")
    program = output("readelf", "--program-headers", str(path))
    interpreter = re.search(r"Requesting program interpreter: ([^\]]+)", program)
    if not interpreter:
        raise RuntimeError("Expected a dynamically linked GNU/Linux executable")
    dynamic = output("readelf", "--dynamic", str(path))
    versions = sorted(set(re.findall(r"\bGLIBC_(\d+(?:\.\d+)+)\b",
                                    output("readelf", "--version-info", str(path)))),
                      key=lambda version: tuple(map(int, version.split("."))))
    if not versions:
        raise RuntimeError("Expected explicit GLIBC symbol requirements")
    return {**fields, "interpreter": interpreter[1],
            "neededLibraries": sorted(set(re.findall(r"\(NEEDED\).*\[([^\]]+)\]", dynamic))),
            "requiredGlibcVersions": versions, "minimumGlibc": versions[-1]}


def main():
    # The source archive and binaries must describe the same committed checkout.
    subprocess.run(["git", "diff", "--quiet", "HEAD", "--"], cwd=ROOT, check=True)
    commit = output("git", "rev-parse", "HEAD")
    if os.environ.get("GITHUB_SHA") != commit or os.environ.get("RUNNER_OS") != "Linux":
        raise RuntimeError("Run only in Linux CI at the recorded GitHub commit")
    host = re.search(r"^host: (.+)$", output("rustc", "-vV"), re.M)[1]
    if host != "x86_64-unknown-linux-gnu":
        raise RuntimeError("Expected the native Linux x86_64 GNU toolchain")
    name = f"spry-standalone-linux-x86_64-{commit}"
    destination = ROOT / ".local/linux-artifact"
    destination.mkdir(parents=True, exist_ok=False)
    package = destination / name
    (package / "bin").mkdir(parents=True)
    (package / "docs").mkdir()
    binaries = {}
    for binary in ("spry-turn", "spry-node"):
        source = ROOT / "target/release" / binary
        if not source.is_file() or not os.access(source, os.X_OK):
            raise RuntimeError(f"Missing release executable: {binary}")
        data = source.read_bytes()
        for private_path in (str(ROOT), str(Path.home() / ".cargo")):
            if private_path.encode() in data:
                raise RuntimeError(f"Unmapped build path in {binary}")
        binaries[f"bin/{binary}"] = {"sha256": sha256(source), **elf_metadata(source)}
        shutil.copy2(source, package / "bin" / binary)
    for filename in ("LICENSE", "NOTICE", "THIRD_PARTY_LICENSES.txt", "Cargo.lock", "README.md"):
        shutil.copy2(ROOT / filename, package / filename)
    for filename in ("standalone.md", "public-mode.md"):
        shutil.copy2(ROOT / "docs" / filename, package / "docs" / filename)
    source_archive = package / "source.tar.gz"
    subprocess.run(["git", "archive", "--format=tar.gz", "--prefix=source/",
                    "--output", str(source_archive), "HEAD"], cwd=ROOT, check=True)
    manifest = {
        "schemaVersion": 1, "kind": "checked-linux-ci-artefact-not-release",
        "repository": "https://github.com/forgesworn/spry-turn", "gitCommit": commit,
        "workflowRunId": os.environ["GITHUB_RUN_ID"],
        "workflowRunAttempt": os.environ["GITHUB_RUN_ATTEMPT"],
        "runnerImage": "ubuntu-24.04", "target": host,
        "rustc": output("rustc", "--version"), "cargo": output("cargo", "--version"),
        "buildCommand": "cargo build --locked --release --workspace --features tls",
        "pathRemapping": {"workspace": "/spry-turn", "cargoHome": "/cargo-home"},
        "cargoLockSha256": sha256(package / "Cargo.lock"),
        "sourceArchive": {"file": "source.tar.gz", "sha256": sha256(source_archive)},
        "binaries": binaries,
        "scope": "Uploaded after this Linux verify job's checks pass. Other workflow jobs remain separate gates. No service is started by packaging; no deployment, release or physical-network qualification.",
        "runtime": "GLIBC requirements are direct ELF symbol requirements; the listed system libraries and their dependencies must also be available. They are not bundled.",
    }
    (package / "provenance.json").write_text(json.dumps(manifest, indent=2) + "\n")
    files = sorted(path for path in package.rglob("*") if path.is_file())
    (package / "SHA256SUMS").write_text("".join(
        f"{sha256(path)}  {path.relative_to(package).as_posix()}\n" for path in files))
    archive = destination / f"{name}.tar.gz"
    with tarfile.open(archive, "w:gz") as bundle:
        bundle.add(package, arcname=name)
    (destination / f"{name}.tar.gz.sha256").write_text(f"{sha256(archive)}  {archive.name}\n")
    print(f"Packaged {name}; verify the archive checksum and internal SHA256SUMS before use.")


if __name__ == "__main__":
    main()
