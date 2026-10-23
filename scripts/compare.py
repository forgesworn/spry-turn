#!/usr/bin/env python3
"""Native, same-host socket comparison; creates only temporary local fixtures."""
import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import queue
import re
import resource
import secrets
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tests"))
from interop import packet, parse


def capture(command, timeout=5):
    return subprocess.run(command, capture_output=True, text=True, timeout=timeout)


def rss(pid):
    result = capture(["ps", "-o", "rss=", "-p", str(pid)])
    return int(result.stdout.strip() or "0") * 1024


def linux_sockets(pid):
    descriptors, inodes = 0, set()
    for fd in Path(f"/proc/{pid}/fd").iterdir():
        try:
            target = fd.readlink().as_posix()
        except (FileNotFoundError, PermissionError):
            continue
        descriptors += 1
        found = re.fullmatch(r"socket:\[(\d+)\]", target)
        if found:
            inodes.add(int(found[1]))
    udp_inodes = set()
    for table in ("udp", "udp6"):
        for line in Path(f"/proc/{pid}/net/{table}").read_text().splitlines()[1:]:
            fields = line.split()
            if len(fields) > 9:
                udp_inodes.add(int(fields[9]))
    result = {"process_descriptors": descriptors, "loaded_udp_sockets": len(inodes & udp_inodes),
              "loaded_socket_count": len(inodes), "kernel_socket_memory": None,
              "kernel_socket_memory_unavailable": "ss utility is unavailable"}
    if not shutil.which("ss"):
        return result
    sample = capture(["ss", "-H", "-a", "-n", "-m", "-e", "-u", "-t"])
    if sample.returncode:
        result["kernel_socket_memory_unavailable"] = "ss could not inspect socket memory"
        return result
    matched, counters, per_socket = set(), {}, []
    inode = None
    for line in sample.stdout.splitlines():
        found = re.search(r"\bino:(\d+)\b", line)
        if found:
            inode = int(found[1])
        memory = re.search(r"skmem:\(([^)]+)\)", line)
        if inode in inodes and memory:
            matched.add(inode)
            observed = {key: int(value) for key, value in re.findall(r"([a-z]+)(\d+)", memory.group(1))}
            per_socket.append(observed)
            for key, value in observed.items():
                counters[key] = counters.get(key, 0) + value
            inode = None
    result["kernel_socket_memory"] = {"method": "ss -m -e attributed by process-owned /proc fd socket inodes",
        "observed_sockets": len(matched), "owned_sockets": len(inodes), "counters": counters,
        "per_socket_counters": per_socket,
        "units": "bytes except d (packet drops)",
        "limits": "Point-in-time counters are not additive total kernel memory; rb/tb are configured buffer ceilings, not allocated bytes. Socket structs/slabs, unreported sockets and missed peaks are excluded."}
    if matched:
        result.pop("kernel_socket_memory_unavailable")
    else:
        result["kernel_socket_memory_unavailable"] = "ss returned no process-attributable skmem records"
    return result


def socket_resources(pid):
    if platform.system() == "Linux":
        return linux_sockets(pid)
    if not shutil.which("lsof"):
        return {"loaded_udp_sockets": None, "kernel_socket_memory": None,
                "kernel_socket_memory_unavailable": "No supported process-attributed kernel-memory measurement on this host"}
    result = capture(["lsof", "-nP", "-a", "-p", str(pid), "-iUDP", "-Ff"])
    sockets = sum(line.startswith("f") and line[1:].isdigit() for line in result.stdout.splitlines())
    fds = capture(["lsof", "-nP", "-p", str(pid), "-Ff"])
    count = sum(line.startswith("f") and line[1:].isdigit() for line in fds.stdout.splitlines())
    return {"loaded_udp_sockets": sockets if result.returncode in (0, 1) else None,
            "process_descriptors": count if fds.returncode in (0, 1) else None,
            "kernel_socket_memory": None,
            "kernel_socket_memory_unavailable": "No supported process-attributed kernel-memory measurement on this host; RSS is process memory only"}


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def certificate(root):
    cert, key = root / "cert.pem", root / "key.pem"
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
        "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1",
        "-addext", "basicConstraints=critical,CA:FALSE", "-addext", "extendedKeyUsage=serverAuth",
        "-keyout", str(key), "-out", str(cert)], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        timeout=30)
    key.chmod(0o600)
    return cert, key


class Server:
    def __init__(self, binary, coturn=False, tls=False, relay_ports="49160:49999", relay_threads=0):
        self.secret = secrets.token_hex(32)
        self.temp = tempfile.TemporaryDirectory(prefix="spry-compare-")
        self.process = None
        root = Path(self.temp.name)
        self.port, self.tls_port = free_port(), None
        self.cert = None
        self.log = (root / "startup.log").open("w+")
        try:
            if tls:
                self.cert, key = certificate(root)
                self.tls_port = free_port()
                while self.tls_port == self.port:
                    self.tls_port = free_port()
            if coturn:
                first, last = relay_ports.split(":")
                lines = [f"listening-port={self.port}", "listening-ip=127.0.0.1", "relay-ip=127.0.0.1",
                    "realm=spry-turn", "fingerprint", "use-auth-secret", f"static-auth-secret={self.secret}",
                    "no-dtls", "no-cli", "no-tcp-relay", "no-rfc5780", "no-multicast-peers",
                    "allow-loopback-peers", f"relay-threads={relay_threads}", "total-quota=1024", "user-quota=8",
                    "max-bps=1073741824", "no-stdout-log", "simple-log", f"log-file={root / 'server.log'}",
                    f"pidfile={root / 'server.pid'}", "stale-nonce=600", f"min-port={first}", f"max-port={last}"]
                lines += [f"tls-listening-port={self.tls_port}", f"cert={self.cert}", f"pkey={key}"] if tls else ["no-tls"]
                config = root / "turnserver.conf"
                config.write_text("\n".join(lines) + "\n"); config.chmod(0o600)
                command = [str(binary), "-c", str(config)]
            else:
                command = [str(binary), "serve", "--listen", f"127.0.0.1:{self.port}", "--allow-loopback-peers",
                    "--bytes-per-second", "1073741824", "--max-connections", "1024", "--relay-ports", relay_ports]
                if tls:
                    command += ["--tls-listen", f"127.0.0.1:{self.tls_port}", "--tls-cert", str(self.cert), "--tls-key", str(key)]
            self.process = subprocess.Popen(command, env={**os.environ, "SPRY_TURN_SECRET": self.secret},
                                            stdout=self.log, stderr=self.log)
            ready = False
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
                probe.settimeout(0.1)
                for _ in range(100):
                    if self.process.poll() is not None:
                        break
                    probe.sendto(packet(1), ("127.0.0.1", self.port))
                    try:
                        if parse(probe.recv(4096))[0] == 0x101:
                            ready = True; break
                    except (socket.timeout, ConnectionRefusedError):
                        pass
            if not ready:
                # Do not copy server logs into evidence: they can contain paths or configuration.
                raise RuntimeError("server did not become ready; inspect local temporary logs while debugging")
        except BaseException:
            self.close()
            raise

    def close(self):
        if self.process is not None and self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                self.process.kill(); self.process.wait()
        self.log.close()
        self.temp.cleanup()


def finish(fixture):
    process = fixture.process
    process.terminate()
    deadline = time.monotonic() + 3
    while True:
        pid, status, usage = os.wait4(process.pid, os.WNOHANG)
        if pid:
            process.returncode = os.waitstatus_to_exitcode(status)
            return usage.ru_utime + usage.ru_stime
        if time.monotonic() > deadline:
            process.kill()
            _, status, usage = os.wait4(process.pid, 0)
            process.returncode = os.waitstatus_to_exitcode(status)
            return usage.ru_utime + usage.ru_stime
        time.sleep(0.01)


def run_one(name, binary, loader, clients, packets, size, window, transport="udp", min_seconds=0.0,
            workers=None, relay_ports="49160:49999", relay_threads=0):
    fixture = Server(binary, coturn=name == "coturn", tls=transport == "tls",
                     relay_ports=relay_ports, relay_threads=relay_threads)
    stop = threading.Event(); samples = []; monitor_error = []
    def monitor():
        try:
            while not stop.is_set():
                samples.append(rss(fixture.process.pid)); stop.wait(0.05)
        except Exception:
            monitor_error.append("RSS sampling failed")
    thread = None
    loader_process = None
    output_thread = None
    try:
        time.sleep(0.15)
        idle = rss(fixture.process.pid)
        thread = threading.Thread(target=monitor, daemon=True); thread.start()
        start = time.perf_counter()
        command = [str(loader), f"127.0.0.1:{fixture.tls_port if transport == 'tls' else fixture.port}",
            str(clients), str(packets), str(size), str(window), "--transport", transport, "--min-seconds", str(min_seconds),
            "--resource-hold-ms", "30000"]
        if workers is not None:
            command += ["--workers", str(min(workers, clients))]
        if fixture.cert:
            command += ["--ca", str(fixture.cert)]
        loader_process = subprocess.Popen(command, env={**os.environ, "SPRY_TURN_SECRET": fixture.secret},
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        output = queue.Queue()
        output_thread = threading.Thread(target=lambda: output.put(loader_process.stdout.readline()), daemon=True)
        output_thread.start()
        try:
            line = output.get(timeout=max(90, min_seconds * 3))
        except queue.Empty:
            raise RuntimeError(f"{name} load exceeded its finite timeout") from None
        wall = time.perf_counter() - start
        stop.set(); thread.join(timeout=6)
        if not line:
            _, error = loader_process.communicate(timeout=3)
            raise RuntimeError(f"{name} load failed: {error.strip()}")
        data = json.loads(line)
        loaded = rss(fixture.process.pid)
        sockets = socket_resources(fixture.process.pid)
        if loader_process.poll() is not None:
            raise RuntimeError("loader resource hold expired before inspection completed")
        # Sampling occurs before release: TCP/TLS allocations disappear when
        # their client connections close. Holding avoids a false zero count.
        loader_process.stdin.write("\n"); loader_process.stdin.flush()
        _, error = loader_process.communicate(timeout=3)
        if loader_process.returncode:
            raise RuntimeError(f"{name} load failed: {error.strip()}")
        if monitor_error:
            raise RuntimeError(monitor_error[0])
        cpu = finish(fixture)
        data.update(server=name, idle_rss_bytes=idle, loaded_rss_bytes=loaded,
            peak_sampled_rss_bytes=max(samples + [idle, loaded]), server_cpu_seconds=round(cpu, 6),
            total_workload_wall_seconds=round(wall, 6),
            binary_bytes=binary.stat().st_size, **sockets)
        return data
    finally:
        stop.set()
        if thread:
            thread.join(timeout=6)
        if loader_process is not None:
            if loader_process.poll() is None:
                loader_process.terminate()
                try:
                    loader_process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    loader_process.kill(); loader_process.wait()
            if output_thread:
                output_thread.join(timeout=1)
            for stream in (loader_process.stdin, loader_process.stdout, loader_process.stderr):
                stream.close()
        fixture.close()


def architecture(path):
    if platform.system() == "Darwin":
        return subprocess.check_output(["lipo", "-archs", str(path)], text=True).split()
    result = subprocess.check_output(["file", "-b", str(path)], text=True)
    if "aarch64" in result or "ARM aarch64" in result:
        return ["arm64"]
    if "x86-64" in result:
        return ["x86_64"]
    return ["unknown"]


def binary_identity(path):
    return {"sha256": hashlib.sha256(path.read_bytes()).hexdigest(), "bytes": path.stat().st_size,
            "architectures": architecture(path)}


def cpu_brand():
    if platform.system() == "Darwin":
        return subprocess.check_output(["sysctl", "-n", "machdep.cpu.brand_string"], text=True).strip()
    for line in Path("/proc/cpuinfo").read_text().splitlines():
        if line.startswith(("model name", "Hardware")):
            return line.partition(":")[2].strip()
    return platform.machine()


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
    parser.add_argument("--transports", choices=["udp", "tcp", "tls"], nargs="+", default=["udp"])
    parser.add_argument("--packets", type=int, default=100000)
    parser.add_argument("--window", type=int, default=32)
    parser.add_argument("--workers", type=int)
    parser.add_argument("--min-seconds", type=float, default=0)
    parser.add_argument("--relay-ports", default="49160:49999")
    parser.add_argument("--coturn-relay-threads", type=int, default=0)
    parser.add_argument("--source-id", help="Reviewed git commit or source manifest digest; never a private path")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    ports = re.fullmatch(r"([0-9]{1,5}):([0-9]{1,5})", args.relay_ports)
    if not (1 <= args.runs <= 20 and 1 <= args.window <= 64 and all(1 <= c <= 512 for c in args.clients)
            and all(8 <= size <= 1400 for size in args.sizes) and max(args.clients) <= args.packets <= 100_000_000
            and math.isfinite(args.min_seconds) and 0 <= args.min_seconds <= 60
            and (args.workers is None or 1 <= args.workers <= 64) and 0 <= args.coturn_relay_threads <= 64
            and ports and 0 < int(ports[1]) <= int(ports[2]) <= 65535
            and int(ports[2]) - int(ports[1]) + 1 >= max(args.clients)):
        parser.error("benchmark limits, packet count or relay-port range are invalid")
    if args.source_id and not re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", args.source_id):
        parser.error("--source-id must be a 40-character git hash or 64-character source-manifest SHA-256")
    soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    desired = 4096 if hard == resource.RLIM_INFINITY else min(hard, 4096)
    resource.setrlimit(resource.RLIMIT_NOFILE, (max(soft, desired), hard))
    args.spry, args.coturn, args.loader = (p.resolve() for p in [args.spry, args.coturn, args.loader])
    if args.baseline:
        args.baseline = args.baseline.resolve()
    binaries = {"spry-turn": args.spry, "coturn": args.coturn, "loader": args.loader}
    if args.baseline:
        binaries["spry-baseline"] = args.baseline
    identities = {name: binary_identity(path) for name, path in binaries.items()}
    architectures = {name: identity["architectures"] for name, identity in identities.items()}
    if args.required_arch and any(value != [args.required_arch] for value in architectures.values()):
        raise RuntimeError("benchmark requires matching thin native binaries: " + json.dumps(architectures))
    host_arch = "arm64" if platform.machine() in ("arm64", "aarch64") else platform.machine()
    if args.required_arch and host_arch != args.required_arch:
        raise RuntimeError("benchmark binary architecture differs from host architecture")
    output = {"schema": 2, "source_id": args.source_id, "binaries": identities,
        "machine": {"cpu": cpu_brand(), "system": os.uname().sysname, "release": os.uname().release,
        "logical_cpus": os.cpu_count(), "load_before": os.getloadavg(),
        "process_descriptor_limit": resource.getrlimit(resource.RLIMIT_NOFILE)[0], "binary_architectures": architectures},
        "method": {"transports": args.transports, "coturn_relay_threads": args.coturn_relay_threads,
        "relay_ports": args.relay_ports, "minimum_seconds_per_throughput_phase": args.min_seconds,
        "maximum_load_workers": args.workers or 4, "socket_memory_sample": "After throughput, quiescent with every client connection and allocation held live; not peak kernel memory",
        "notes": "Closed-loop delivered-packet workload, not maximum sustainable capacity or WAN results. Client leg uses selected transport; peer leg remains UDP. CPU includes server startup, setup, warm-up, latency samples and post-phase resource inspection; excludes load generator. RSS excludes kernel memory; peak sampled every 50 ms. RTT includes client and echo scheduling and both forwarding directions. Sequential RTT precedes throughput; loaded RTT samples every 64th packet per allocation using a bounded reservoir per worker. TLS validates a generated localhost certificate via an explicit test trust store. No external traffic; existing host workloads left running."}, "runs": []}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    try:
        for transport in args.transports:
            for size in args.sizes:
                for clients in args.clients:
                    for repeat in range(args.runs):
                        order = [("spry-turn", args.spry), ("coturn", args.coturn)]
                        if args.baseline:
                            order.insert(0, ("spry-baseline", args.baseline))
                        if repeat % 2:
                            order.reverse()
                        for name, binary in order:
                            try:
                                data = run_one(name, binary, args.loader, clients, args.packets, size, args.window,
                                    transport, args.min_seconds, args.workers, args.relay_ports, args.coturn_relay_threads)
                            except BaseException as error:
                                # Subprocess diagnostics may contain absolute
                                # paths or generated credentials. Keep detailed
                                # tracebacks local, outside shareable receipts.
                                output.setdefault("failures", []).append({"server": name, "transport": transport,
                                    "clients": clients, "payload_bytes": size, "repeat": repeat + 1,
                                    "error_code": "benchmark_run_failed", "exception_type": type(error).__name__})
                                raise
                            data["repeat"] = repeat + 1
                            output["runs"].append(data)
                            args.output.write_text(json.dumps(output, indent=2) + "\n")
                            print(json.dumps(data), flush=True)
    finally:
        output["machine"]["load_after"] = os.getloadavg()
        args.output.write_text(json.dumps(output, indent=2) + "\n")


if __name__ == "__main__":
    main()
