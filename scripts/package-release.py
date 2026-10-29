#!/usr/bin/env python3
"""Package release artefacts in CI from already built files; never compile.

Commands (run from the repository root, in the release workflow):

  rustflags                    print RUSTFLAGS=... for $GITHUB_ENV, remapping
                               the checkout and Cargo home out of binaries
  name                         print the artefact name prefix: the tag on a
                               v* tag (which must match Cargo.toml), else
                               ci-<short commit>
  executables TARGET NAME      archive bin/spry-turn and bin/spry-node for
                               TARGET with licences, docs, provenance and an
                               internal SHA256SUMS, into .local/release/
  android NAME                 archive libspry_relay.so for arm64-v8a and
                               x86_64, the C header and keep rules, likewise
  sums DIRECTORY NAME          write SHA256SUMS, release-manifest.json and
                               release-notes.md for every file in DIRECTORY

Each archive holds the same layout as the Linux CI artefact made by
scripts/package-linux.py: provenance.json and SHA256SUMS over its files.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tarfile
import zipfile

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / ".local/release"
REPOSITORY = "https://github.com/forgesworn/spry-turn"
EXECUTABLE_TARGETS = {
    "aarch64-apple-darwin": "macOS on Apple silicon (arm64)",
    "x86_64-pc-windows-msvc": "Windows x64",
    "x86_64-unknown-linux-gnu": "Linux x64 (glibc)",
    "aarch64-unknown-linux-gnu": "Linux arm64 (glibc)",
}
ANDROID_ABIS = {"arm64-v8a": "aarch64-linux-android", "x86_64": "x86_64-linux-android"}
EXECUTABLE_BUILD = "cargo build --locked --release --target {target} --workspace --features tls --bins"
ANDROID_BUILD = "python3 scripts/build-android.py (cargo build --locked -p spry-ffi --features jni --profile release-ffi --target <abi target>)"
SIGNING = {
    "aarch64-apple-darwin": "Ad hoc signed by the Rust linker, as every arm64 macOS executable must be; not Developer ID signed or notarised. A host app that bundles it signs its own copy.",
    "x86_64-pc-windows-msvc": "Unsigned. There is no Authenticode signature, so SmartScreen and Defender may warn about or block it.",
    "x86_64-unknown-linux-gnu": "Unsigned; verify the checksums.",
    "aarch64-unknown-linux-gnu": "Unsigned; verify the checksums.",
}


def output(*args, cwd=ROOT):
    return subprocess.check_output(args, cwd=cwd, text=True).strip()


def sha256(path):
    digest = hashlib.sha256()
    with open(path, "rb") as source:
        for block in iter(lambda: source.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def cargo_version():
    text = (ROOT / "Cargo.toml").read_text()
    return re.search(r'^version = "([^"]+)"$', text, re.M)[1]


def cargo_home():
    return Path(os.environ.get("CARGO_HOME") or Path.home() / ".cargo")


def private_paths():
    """Builder paths that must not appear in a shipped binary."""
    paths = set()
    for path in (str(ROOT), str(cargo_home())):
        paths.add(path)
        paths.add(path.replace("\\", "/"))
    return [path.encode() for path in paths if len(path) > 3]


def ci_identity():
    subprocess.run(["git", "diff", "--quiet", "HEAD", "--"], cwd=ROOT, check=True)
    commit = output("git", "rev-parse", "HEAD")
    if os.environ.get("GITHUB_ACTIONS") != "true" or os.environ.get("GITHUB_SHA") != commit:
        raise SystemExit("Run only in GitHub Actions at the recorded commit")
    return commit


def rustflags():
    flags = [f"--remap-path-prefix={ROOT}=/spry-turn",
             f"--remap-path-prefix={cargo_home()}=/cargo-home"]
    if any(" " in flag for flag in flags):
        raise SystemExit("Build paths contain spaces; RUSTFLAGS cannot carry them")
    print("RUSTFLAGS=" + " ".join(flags))


def name():
    reference = os.environ.get("GITHUB_REF", "")
    if reference.startswith("refs/tags/v"):
        tag = reference.removeprefix("refs/tags/")
        if tag != f"v{cargo_version()}":
            raise SystemExit(f"Tag {tag} does not match Cargo.toml version {cargo_version()}")
        print(tag)
    else:
        print("ci-" + output("git", "rev-parse", "--short=12", "HEAD"))


def linux_metadata(path, target):
    machine = {"x86_64-unknown-linux-gnu": "Advanced Micro Devices X86-64",
               "aarch64-unknown-linux-gnu": "AArch64"}[target]
    header = output("readelf", "--file-header", str(path))
    found = re.search(r"^\s*Machine:\s*(.+)$", header, re.M)[1].strip()
    if found != machine:
        raise SystemExit(f"Expected a {machine} executable, found {found}")
    versions = sorted(set(re.findall(r"\bGLIBC_(\d+(?:\.\d+)+)\b",
                                     output("readelf", "--version-info", str(path)))),
                      key=lambda version: tuple(map(int, version.split("."))))
    dynamic = output("readelf", "--dynamic", str(path))
    return {"machine": found, "minimumGlibc": versions[-1] if versions else None,
            "neededLibraries": sorted(set(re.findall(r"\(NEEDED\).*\[([^\]]+)\]", dynamic)))}


def copy_common(package, docs):
    for filename in ("LICENSE", "NOTICE", "THIRD_PARTY_LICENSES.txt", "Cargo.lock", "README.md"):
        shutil.copy2(ROOT / filename, package / filename)
    (package / "docs").mkdir()
    for filename in docs:
        shutil.copy2(ROOT / "docs" / filename, package / "docs" / filename)


def seal(package, provenance, archive_format):
    """Write provenance.json and SHA256SUMS, then the archive."""
    provenance["files"] = {
        path.relative_to(package).as_posix(): sha256(path)
        for path in sorted(package.rglob("*")) if path.is_file()
    }
    (package / "provenance.json").write_text(json.dumps(provenance, indent=2) + "\n")
    files = sorted(path for path in package.rglob("*") if path.is_file())
    (package / "SHA256SUMS").write_text("".join(
        f"{sha256(path)}  {path.relative_to(package).as_posix()}\n" for path in files))
    if archive_format == "zip":
        archive = OUT / f"{package.name}.zip"
        with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as bundle:
            for path in sorted(package.rglob("*")):
                if path.is_file():
                    bundle.write(path, f"{package.name}/{path.relative_to(package).as_posix()}")
    else:
        archive = OUT / f"{package.name}.tar.gz"
        with tarfile.open(archive, "w:gz") as bundle:
            bundle.add(package, arcname=package.name)
    shutil.rmtree(package)
    print(f"{archive.name} {sha256(archive)}")


def base_provenance(commit, label, target, build):
    return {
        "schemaVersion": 1,
        "kind": "spry-turn-release-artefact",
        "repository": REPOSITORY,
        "name": label,
        "gitCommit": commit,
        "workflowRunId": os.environ.get("GITHUB_RUN_ID"),
        "workflowRunAttempt": os.environ.get("GITHUB_RUN_ATTEMPT"),
        "runnerOs": os.environ.get("RUNNER_OS"),
        "runnerArch": os.environ.get("RUNNER_ARCH"),
        "target": target,
        "rustc": output("rustc", "--version"),
        "cargo": output("cargo", "--version"),
        "buildCommand": build,
        "pathRemapping": {"workspace": "/spry-turn", "cargoHome": "/cargo-home"},
        "cargoLockSha256": sha256(ROOT / "Cargo.lock"),
    }


def executables(target, label):
    if target not in EXECUTABLE_TARGETS:
        raise SystemExit(f"Unknown target {target}")
    commit = ci_identity()
    host = re.search(r"^host: (.+)$", output("rustc", "-vV"), re.M)[1]
    if host != target:
        raise SystemExit(f"Build {target} natively; the toolchain host is {host}")
    suffix = ".exe" if "windows" in target else ""
    package = OUT / f"spry-turn-{label}-{target}"
    (package / "bin").mkdir(parents=True)
    binaries = {}
    for binary in ("spry-turn", "spry-node"):
        source = ROOT / "target" / target / "release" / f"{binary}{suffix}"
        if not source.is_file():
            raise SystemExit(f"Missing release executable: {source.name}")
        data = source.read_bytes()
        for private in private_paths():
            if private in data:
                raise SystemExit(f"Unmapped build path in {source.name}")
        entry = {"sha256": sha256(source), "bytes": len(data)}
        if "linux" in target:
            entry.update(linux_metadata(source, target))
        binaries[f"bin/{binary}{suffix}"] = entry
        shutil.copy2(source, package / "bin" / source.name)
    copy_common(package, ["standalone.md", "supervised-mode.md", "mapped-ports.md", "public-mode.md"])
    provenance = base_provenance(commit, label, target, EXECUTABLE_BUILD.format(target=target))
    provenance.update({
        "platform": EXECUTABLE_TARGETS[target],
        "binaries": binaries,
        "signing": SIGNING[target],
        "scope": "Built natively on the named runner after the workflow's checks on that platform. No service is started by packaging; no deployment, router, NAT or physical-network qualification.",
    })
    seal(package, provenance, "zip" if "windows" in target else "tar.gz")


def android(label):
    commit = ci_identity()
    package = OUT / f"spry-relay-{label}-android"
    libraries = {}
    for abi, target in ANDROID_ABIS.items():
        source = ROOT / "target" / target / "release-ffi" / "libspry_relay.so"
        if not source.is_file():
            raise SystemExit(f"Missing Android library for {abi}; run scripts/build-android.py")
        data = source.read_bytes()
        for private in private_paths():
            if private in data:
                raise SystemExit(f"Unmapped build path in the {abi} library")
        destination = package / "jniLibs" / abi
        destination.mkdir(parents=True)
        shutil.copy2(source, destination / source.name)
        libraries[f"jniLibs/{abi}/libspry_relay.so"] = {
            "sha256": sha256(source), "bytes": len(data), "target": target}
    (package / "include").mkdir()
    shutil.copy2(ROOT / "crates/spry-ffi/include/spry_relay.h", package / "include/spry_relay.h")
    shutil.copy2(ROOT / "crates/spry-ffi/android/consumer-rules.pro", package / "consumer-rules.pro")
    copy_common(package, ["embedding.md", "supervised-mode.md"])
    provenance = base_provenance(commit, label, "android", ANDROID_BUILD)
    provenance.update({
        "platform": "Android arm64-v8a and x86_64, API 33 and later",
        "libraries": libraries,
        "abiVersion": 1,
        "jniClass": "dev.forgesworn.spry.SpryRelayNative",
        "linking": "NDK clang for API 33, 16 KB page alignment, panic = unwind behind catch_unwind at every export",
        "signing": "Unsigned shared libraries; the app that bundles them signs its APK.",
        "scope": "Built and checked for machine, alignment, exports and needed libraries. Not loaded on an Android device or emulator by this workflow.",
    })
    seal(package, provenance, "tar.gz")


NOTES = """\
Draft written by the release workflow from {commit}. Review, edit and publish by hand.

Downloads (verify `SHA256SUMS` first; each archive also holds its own `SHA256SUMS` and `provenance.json`):

{assets}

- **Windows**: the executables are unsigned. There is no Authenticode signature, so SmartScreen and Defender may warn about or block them.
- **macOS**: Apple silicon only; no Intel build. Ad hoc signed by the linker, not Developer ID signed or notarised.
- **Linux**: glibc builds; `provenance.json` lists the minimum glibc.
- **Android**: `libspry_relay.so` for arm64-v8a and x86_64 (API 33+) with `spry_relay.h`, the `dev.forgesworn.spry.SpryRelayNative` JNI entry points and `consumer-rules.pro`. See [embedding]({repository}/blob/{tag}/docs/embedding.md).

```sh
sha256sum -c SHA256SUMS     # or: shasum -a 256 -c SHA256SUMS
```

These are build artefacts with loopback evidence only. No router, NAT, firewall, physical device or remote network is qualified by this workflow.
"""


def sums(directory, label):
    commit = ci_identity()
    directory = Path(directory)
    files = sorted(path for path in directory.iterdir()
                   if path.is_file() and path.name not in ("SHA256SUMS", "release-manifest.json"))
    if not files:
        raise SystemExit("No artefacts to sum")
    manifest = {
        "schemaVersion": 1, "kind": "spry-turn-release", "repository": REPOSITORY,
        "name": label, "gitCommit": commit, "workflowRunId": os.environ.get("GITHUB_RUN_ID"),
        "assets": {path.name: {"sha256": sha256(path), "bytes": path.stat().st_size}
                   for path in files},
    }
    (directory / "release-manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    files.append(directory / "release-manifest.json")
    (directory / "SHA256SUMS").write_text("".join(
        f"{sha256(path)}  {path.name}\n" for path in files))
    assets = "\n".join(f"- `{path.name}`" for path in files)
    (ROOT / ".local/release-notes.md").write_text(
        NOTES.format(commit=commit, assets=assets, repository=REPOSITORY, tag=label))
    print((directory / "SHA256SUMS").read_text(), end="")


def main():
    command, *rest = sys.argv[1:] or [""]
    commands = {"rustflags": (rustflags, 0), "name": (name, 0), "executables": (executables, 2),
                "android": (android, 1), "sums": (sums, 2)}
    if command not in commands or len(rest) != commands[command][1]:
        raise SystemExit(__doc__)
    if command in ("executables", "android"):
        OUT.mkdir(parents=True, exist_ok=True)
    commands[command][0](*rest)


if __name__ == "__main__":
    main()
