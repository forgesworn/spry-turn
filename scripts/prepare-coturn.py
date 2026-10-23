#!/usr/bin/env python3
"""Build an unmodified, lean coturn reference in an explicit scratch directory."""
import argparse
import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import urllib.request

VERSION = "4.18.0"
SHA256 = "28d55294ac596fbd129b293a85e7bb1c5dc4bd15b7fb55c500f355149e5f4e28"


def extract_checked(archive, root):
    with tarfile.open(archive) as tar:
        for member in tar.getmembers():
            if member.name.startswith("/") or ".." in Path(member.name).parts or not (member.isfile() or member.isdir() or member.issym() or member.islnk()):
                raise RuntimeError("unexpected archive member")
            if member.issym() or member.islnk():
                target = ((root / member.name).parent / member.linkname).resolve() if member.issym() else (root / member.linkname).resolve()
                if root not in target.parents: raise RuntimeError("archive link escapes destination")
        tar.extractall(root)


def ensure_pkg_config(root, env):
    if shutil.which("pkg-config", path=env["PATH"]): return
    version = "3.0.10"
    url = f"https://distfiles.ariadne.space/pkgconf/pkgconf-{version}.tar.xz"
    digest = "9371b2f6372da574d4c6dc96fe9b1463037bcf6afcb6671c1555afde7b17e2de"
    data = urllib.request.urlopen(url, timeout=60).read()
    if hashlib.sha256(data).hexdigest() != digest: raise RuntimeError("pkgconf source checksum mismatch")
    archive = root / "pkgconf.tar.xz"; archive.write_bytes(data)
    extract_checked(archive, root)
    source = root / f"pkgconf-{version}"; prefix = root / "tools"
    subprocess.run(["./configure", f"--prefix={prefix}", "--disable-shared"], cwd=source, env=env, check=True)
    subprocess.run(["make", "-j2"], cwd=source, env=env, check=True)
    subprocess.run(["make", "install"], cwd=source, env=env, check=True)
    link = prefix / "bin/pkg-config"
    if not link.exists(): link.symlink_to("pkgconf")
    env["PATH"] = str(prefix / "bin") + os.pathsep + env["PATH"]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("destination", type=Path)
    parser.add_argument("--prefix", type=Path, default=Path("/opt/homebrew"))
    args = parser.parse_args()
    root = args.destination.resolve(); root.mkdir(parents=True, exist_ok=True)
    archive = root / f"coturn-{VERSION}.tar.gz"
    with urllib.request.urlopen(f"https://github.com/coturn/coturn/archive/refs/tags/{VERSION}.tar.gz", timeout=60) as response:
        data = response.read()
    if hashlib.sha256(data).hexdigest() != SHA256: raise RuntimeError("coturn source checksum mismatch")
    archive.write_bytes(data)
    source = root / f"coturn-{VERSION}"
    if source.exists(): raise RuntimeError("source directory exists; refusing to overwrite it")
    extract_checked(archive, root)
    env = dict(os.environ)
    paths = [str(args.prefix / "bin"), str(args.prefix / "opt/pkgconf/bin"), env.get("PATH", "")]
    env["PATH"] = os.pathsep.join(paths)
    env["CPPFLAGS"] = f"-I{args.prefix}/opt/libevent/include -I{args.prefix}/opt/openssl@3/include"
    env["LDFLAGS"] = f"-L{args.prefix}/opt/libevent/lib -L{args.prefix}/opt/openssl@3/lib"
    env["PKG_CONFIG_PATH"] = f"{args.prefix}/opt/libevent/lib/pkgconfig:{args.prefix}/opt/openssl@3/lib/pkgconfig"
    env["CFLAGS"] = "-O3 -DNDEBUG"
    ensure_pkg_config(root, env)
    subprocess.run(["./configure", "--prefix=" + str(root / "install"), "--disable-sqlite", "--disable-mysql", "--disable-postgresql", "--disable-redis", "--disable-prometheus"], cwd=source, env=env, check=True)
    subprocess.run(["make", "-j2"], cwd=source, env=env, check=True)
    binary = source / "bin/turnserver"
    subprocess.run(["strip", "-x", str(binary)], check=True)
    print(binary)


if __name__ == "__main__": main()
