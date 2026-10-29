#!/usr/bin/env python3
"""Load a built libspry_relay into a JVM and drive every JNI entry point.

Usage: python3 scripts/jni-smoke.py <path to libspry_relay.so|.dylib>

Needs javac and java on PATH (any JDK 11 or later). The library must be built
with the `jni` feature. Proves the JNI symbol names, the hand-written function
table indices and the lifetime rules on a desktop JVM; Android's runtime uses
the same table, but only a device or emulator proves the packaged app.
"""
import shutil
import socket
import subprocess
import sys
import tempfile
from pathlib import Path

SMOKE = Path(__file__).resolve().parents[1] / "crates/spry-ffi/smoke"


def free_ports():
    """A loopback listener port, with port + 2 also free, on UDP and TCP."""
    for _ in range(200):
        with socket.socket() as probe:
            probe.bind(("127.0.0.1", 0))
            port = probe.getsockname()[1]
        if port > 65000:
            continue
        held = []
        try:
            for candidate in (port, port + 2):
                for kind in (socket.SOCK_STREAM, socket.SOCK_DGRAM):
                    sock = socket.socket(socket.AF_INET, kind)
                    held.append(sock)
                    sock.bind(("127.0.0.1", candidate))
            return port
        except OSError:
            continue
        finally:
            for sock in held:
                sock.close()
    raise RuntimeError("no free loopback ports")


def main():
    if len(sys.argv) != 2:
        raise SystemExit(__doc__)
    library = Path(sys.argv[1]).resolve()
    if not library.is_file():
        raise SystemExit(f"Missing library: {library.name}")
    for tool in ("javac", "java"):
        if not shutil.which(tool):
            raise SystemExit(f"{tool} is not on PATH")
    with tempfile.TemporaryDirectory(prefix="spry-jni-smoke-") as scratch:
        classes = Path(scratch) / "classes"
        state = Path(scratch) / "state"
        state.mkdir()
        sources = [str(path) for path in SMOKE.rglob("*.java")]
        subprocess.run(["javac", "-d", str(classes), *sources], check=True)
        subprocess.run(["java", "-Xcheck:jni", "-cp", str(classes), "SpryRelaySmoke",
                        str(library), str(state), str(free_ports())], check=True, timeout=120)


if __name__ == "__main__":
    main()
