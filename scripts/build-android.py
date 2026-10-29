#!/usr/bin/env python3
"""Build and check libspry_relay.so for Android with the NDK's own clang.

Usage: python3 scripts/build-android.py [--ndk PATH] [--check-only]

No cargo-ndk or other wrapper: cargo is pointed at the NDK's clang, linker and
llvm-ar through the standard CC_<target>, AR_<target> and
CARGO_TARGET_<TARGET>_LINKER variables (ring, used by rustls, compiles C and
assembly, so the C compiler matters as much as the linker). The NDK is found
from --ndk, ANDROID_NDK_HOME, ANDROID_NDK_ROOT or ANDROID_HOME/ndk/<NDK>.

Each library is built with the `jni` feature and the `release-ffi` profile
(panics unwind to the C ABI's guards), for API 33 (the app's minSdk), linked
with 16 KB page alignment, then checked: ELF machine, LOAD alignment, the
exported C ABI and JNI symbols, and the shared libraries it needs.
"""
import argparse
import os
from pathlib import Path
import platform
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
NDK = "28.2.13676358"
API = 33
TARGETS = {
    # Rust target: (Android ABI, clang prefix, readelf machine)
    "aarch64-linux-android": ("arm64-v8a", "aarch64-linux-android", "AArch64"),
    "x86_64-linux-android": ("x86_64", "x86_64-linux-android", "Advanced Micro Devices X86-64"),
}
EXPORTS = [
    "spry_relay_abi_version", "spry_relay_start", "spry_relay_next_line",
    "spry_relay_stop", "spry_relay_exit_code", "spry_relay_free",
    *(f"Java_dev_forgesworn_spry_SpryRelayNative_{name}"
      for name in ("abiVersion", "start", "nextLine", "stop", "exitCode", "free")),
]
# Android's own system libraries; nothing else may be needed at load time.
SYSTEM_LIBRARIES = {"libc.so", "libm.so", "libdl.so", "liblog.so"}


def find_ndk(explicit):
    candidates = [explicit, os.environ.get("ANDROID_NDK_HOME"), os.environ.get("ANDROID_NDK_ROOT")]
    home = os.environ.get("ANDROID_HOME") or os.environ.get("ANDROID_SDK_ROOT")
    if home:
        candidates.append(str(Path(home) / "ndk" / NDK))
    for candidate in candidates:
        if candidate and (Path(candidate) / "toolchains/llvm/prebuilt").is_dir():
            return Path(candidate)
    raise SystemExit(f"Android NDK not found; install NDK {NDK} or pass --ndk")


def toolchain(ndk):
    system = platform.system()
    host = {"Darwin": "darwin-x86_64", "Linux": "linux-x86_64", "Windows": "windows-x86_64"}[system]
    bin_dir = ndk / "toolchains/llvm/prebuilt" / host / "bin"
    if not bin_dir.is_dir():
        raise SystemExit(f"No NDK toolchain for {host}")
    return bin_dir


def tool(bin_dir, name):
    suffix = ".cmd" if platform.system() == "Windows" and "clang" in name else ""
    path = bin_dir / f"{name}{suffix}"
    if not path.exists():
        path = bin_dir / f"{name}.exe"
    return str(path)


def build(target, bin_dir):
    _, prefix, _ = TARGETS[target]
    clang = tool(bin_dir, f"{prefix}{API}-clang")
    key = target.replace("-", "_")
    env = dict(os.environ)
    env[f"CC_{key}"] = clang
    env[f"AR_{key}"] = tool(bin_dir, "llvm-ar")
    env[f"CARGO_TARGET_{key.upper()}_LINKER"] = clang
    # RUSTFLAGS (for example a CI path remapping) applies to the target only
    # when --target is given; keep it and add the page alignment.
    flags = env.get("RUSTFLAGS", "").split()
    flags += ["-C", "link-arg=-Wl,-z,max-page-size=16384"]
    env["RUSTFLAGS"] = " ".join(flags)
    subprocess.run(["cargo", "build", "--locked", "-p", "spry-ffi", "--features", "jni",
                    "--profile", "release-ffi", "--target", target], cwd=ROOT, env=env, check=True)


def output(*args):
    return subprocess.check_output(args, text=True)


def check(target, bin_dir):
    abi, _, machine = TARGETS[target]
    library = ROOT / "target" / target / "release-ffi" / "libspry_relay.so"
    if not library.is_file():
        raise SystemExit(f"Missing {library.relative_to(ROOT)}")
    readelf, nm = tool(bin_dir, "llvm-readelf"), tool(bin_dir, "llvm-nm")
    header = output(readelf, "--file-header", str(library))
    found = re.search(r"^\s*Machine:\s*(.+)$", header, re.M)[1].strip()
    if found != machine or "DYN (Shared object file)" not in header:
        raise SystemExit(f"{abi}: expected a {machine} shared object, found {found}")
    loads = re.findall(r"^\s*LOAD\s.*\s(0x[0-9a-f]+)$", output(readelf, "-lW", str(library)), re.M)
    if not loads or any(int(align, 16) < 16384 for align in loads):
        raise SystemExit(f"{abi}: every LOAD segment must be 16 KB aligned, found {loads}")
    symbols = set(output(nm, "-D", "--defined-only", "--format=just-symbols", str(library)).split())
    missing = [name for name in EXPORTS if name not in symbols]
    if missing:
        raise SystemExit(f"{abi}: missing exports {missing}")
    needed = set(re.findall(r"\(NEEDED\)\s+Shared library: \[([^\]]+)\]",
                            output(readelf, "--dynamic", str(library))))
    if not needed <= SYSTEM_LIBRARIES:
        raise SystemExit(f"{abi}: needs libraries outside Android's own: {sorted(needed - SYSTEM_LIBRARIES)}")
    print(f"{abi}: {library.relative_to(ROOT)} {library.stat().st_size} bytes, "
          f"{machine}, LOAD align {min(int(a, 16) for a in loads)}, needs {sorted(needed)}")
    return library


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--ndk")
    parser.add_argument("--check-only", action="store_true")
    options = parser.parse_args()
    bin_dir = toolchain(find_ndk(options.ndk))
    for target in TARGETS:
        if not options.check_only:
            build(target, bin_dir)
        check(target, bin_dir)


if __name__ == "__main__":
    sys.exit(main())
