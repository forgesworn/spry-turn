#!/usr/bin/env python3
"""Same-host, real-socket comparison. No installation or external network load."""
import argparse
import json
import os
from pathlib import Path
import secrets
import resource
import socket
import subprocess
import sys
import tempfile
import threading
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tests"))
from interop import Fixture, packet, parse


def rss(pid):
    result = subprocess.run(["ps", "-o", "rss=", "-p", str(pid)], capture_output=True, text=True)
    return int(result.stdout.strip() or "0") * 1024


def udp_sockets(pid):
    result = subprocess.run(["lsof", "-nP", "-a", "-p", str(pid), "-iUDP", "-Ff"], capture_output=True, text=True)
    return sum(line.startswith("f") and line[1:].isdigit() for line in result.stdout.splitlines())


class Coturn:
    def __init__(self, binary):
        self.secret = secrets.token_hex(32)
        self.temp = tempfile.TemporaryDirectory(prefix="spry-coturn-")
        root = Path(self.temp.name)
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0)); self.port = sock.getsockname()[1]
        config = root / "turnserver.conf"
        config.write_text("\n".join([
            f"listening-port={self.port}", "listening-ip=127.0.0.1", "relay-ip=127.0.0.1", "realm=spry-turn",
            "fingerprint", "use-auth-secret", f"static-auth-secret={self.secret}",
            "no-tls", "no-dtls", "no-cli", "no-tcp-relay", "no-rfc5780", "no-multicast-peers",
            "allow-loopback-peers", "relay-threads=0", "total-quota=1024", "user-quota=8",
            "max-bps=1073741824", "no-stdout-log", "simple-log", f"log-file={root / 'server.log'}",
            f"pidfile={root / 'server.pid'}", "stale-nonce=600", ""
        ]))
        config.chmod(0o600)
        self.process = subprocess.Popen([str(binary), "-c", str(config)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        ready = False
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
            probe.settimeout(0.1)
            for _ in range(50):
                if self.process.poll() is not None: break
                probe.sendto(packet(1), ("127.0.0.1", self.port))
                try:
                    if parse(probe.recv(4096))[0] == 0x101: ready = True; break
                except (socket.timeout, ConnectionRefusedError): pass
        if not ready:
            self.close()
            raise RuntimeError("coturn did not become ready")

    def close(self):
        if self.process.poll() is None:
            self.process.terminate()
            try: self.process.wait(timeout=3)
            except subprocess.TimeoutExpired: self.process.kill(); self.process.wait()
        self.temp.cleanup()


def finish(fixture):
    process = fixture.process
    process.terminate()
    _, status, usage = os.wait4(process.pid, 0)
    process.returncode = os.waitstatus_to_exitcode(status)
    fixture.close()
    return usage.ru_utime + usage.ru_stime


def run_one(name, binary, loader, clients, packets, size, window):
    fixture = Fixture(binary, limits=("--bytes-per-second", "1073741824")) if name != "coturn" else Coturn(binary)
    stop = threading.Event(); samples = []
    def monitor():
        while not stop.is_set():
            samples.append(rss(fixture.process.pid)); stop.wait(0.05)
    try:
        time.sleep(0.15)
        idle = rss(fixture.process.pid)
        thread = threading.Thread(target=monitor, daemon=True); thread.start()
        start = time.perf_counter()
        result = subprocess.run([str(loader), f"127.0.0.1:{fixture.port}", str(clients), str(packets), str(size), str(window)],
            env={**os.environ, "SPRY_TURN_SECRET": fixture.secret}, capture_output=True, text=True, timeout=90)
        wall = time.perf_counter() - start
        stop.set(); thread.join(timeout=3)
        loaded = rss(fixture.process.pid)
        sockets = udp_sockets(fixture.process.pid)
        if result.returncode:
            raise RuntimeError(f"{name} load failed: {result.stderr.strip()}")
        cpu = finish(fixture)
        data = json.loads(result.stdout)
        data.update(server=name, idle_rss_bytes=idle, loaded_rss_bytes=loaded,
            peak_sampled_rss_bytes=max(samples + [idle, loaded]), server_cpu_seconds=round(cpu, 6),
            total_workload_wall_seconds=round(wall, 6), server_cpu_percent=round(cpu / wall * 100, 2),
            binary_bytes=binary.stat().st_size)
        data["loaded_udp_sockets"] = sockets
        return data
    finally:
        stop.set(); fixture.close()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--spry", type=Path, default=Path("target/release/spry-turn"))
    parser.add_argument("--coturn", type=Path, required=True)
    parser.add_argument("--baseline", type=Path)
    parser.add_argument("--required-arch", choices=["arm64", "x86_64"])
    parser.add_argument("--loader", type=Path, default=Path("target/release/examples/load"))
    parser.add_argument("--runs", type=int, default=3)
    parser.add_argument("--clients", type=int, nargs="+", default=[1, 16, 128])
    parser.add_argument("--sizes", type=int, nargs="+", default=[160, 1200])
    parser.add_argument("--packets", type=int, default=100000)
    parser.add_argument("--window", type=int, default=32)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    desired = 4096 if hard == resource.RLIM_INFINITY else min(hard, 4096)
    resource.setrlimit(resource.RLIMIT_NOFILE, (max(soft, desired), hard))
    args.spry, args.coturn, args.loader = (p.resolve() for p in [args.spry, args.coturn, args.loader])
    if args.baseline: args.baseline = args.baseline.resolve()
    binaries = {"spry-turn": args.spry, "coturn": args.coturn, "loader": args.loader}
    if args.baseline: binaries["spry-baseline"] = args.baseline
    architectures = {name: subprocess.check_output(["lipo", "-archs", str(path)], text=True).split() for name, path in binaries.items()}
    if args.required_arch and any(value != [args.required_arch] for value in architectures.values()):
        raise RuntimeError("benchmark requires matching thin native binaries: " + json.dumps(architectures))
    chip = subprocess.check_output(["sysctl", "-n", "machdep.cpu.brand_string"], text=True).strip()
    output = {"machine": {"cpu": chip, "system": os.uname().sysname, "release": os.uname().release,
        "logical_cpus": os.cpu_count(), "load_before": os.getloadavg(), "process_descriptor_limit": resource.getrlimit(resource.RLIMIT_NOFILE)[0], "binary_architectures": architectures}, "method": {
        "transport": "TURN/UDP ChannelData in both directions over loopback", "coturn_relay_threads": 0,
        "notes": "Closed-loop delivered-packet workload; not a maximum-capacity or WAN benchmark. No TLS in measured data path. CPU includes server startup, setup and latency samples. RSS excludes kernel socket memory; peak is sampled every 50 ms. No external traffic. Existing host workloads left running."}, "runs": []}
    for size in args.sizes:
        for clients in args.clients:
            for repeat in range(args.runs):
                order = [("spry-turn", args.spry), ("coturn", args.coturn)]
                if args.baseline: order.insert(0, ("spry-baseline", args.baseline))
                if repeat % 2: order.reverse()
                for name, binary in order:
                    try:
                        data = run_one(name, binary, args.loader, clients, args.packets, size, args.window)
                    except Exception as error:
                        output.setdefault("failures", []).append({"server": name, "clients": clients, "payload_bytes": size, "repeat": repeat + 1, "error": str(error)})
                        args.output.write_text(json.dumps(output, indent=2) + "\n")
                        raise
                    data["repeat"] = repeat + 1
                    output["runs"].append(data)
                    args.output.parent.mkdir(parents=True, exist_ok=True)
                    args.output.write_text(json.dumps(output, indent=2) + "\n")
                    print(json.dumps(data), flush=True)
    output["machine"]["load_after"] = os.getloadavg()
    args.output.write_text(json.dumps(output, indent=2) + "\n")


if __name__ == "__main__": main()
