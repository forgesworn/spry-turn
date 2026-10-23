#!/usr/bin/env python3
"""Sustained local socket qualification, separate from throughput benchmarks.

The generated lossy proxy deliberately drops and delays UDP datagrams. It is
an application-level fixture, not a claim about WAN or kernel-netem acceptance.
All listeners bind loopback; no production credentials, media or service.
"""
import argparse
from contextlib import ExitStack
import hashlib
import heapq
import json
from pathlib import Path
import random
import re
import selectors
import socket
import struct
import subprocess
import threading
import time

from interop import (Client, Fixture, packet, parse, error_code, NONCE, TRANSPORT,
                     LIFETIME, USERNAME, REALM_ATTR, REALM)


def bounded_int(low, high):
    def parse_int(value):
        number = int(value)
        if not low <= number <= high:
            raise argparse.ArgumentTypeError(f"must be between {low} and {high}")
        return number
    return parse_int


def peer(stack):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    stack.callback(sock.close)
    sock.bind(("127.0.0.1", 0))
    sock.settimeout(1)
    return sock


def client(stack, fixture, **kwargs):
    value = Client(fixture, **kwargs)
    stack.callback(value.close)
    return value


def fixture(stack, binary, **kwargs):
    value = Fixture(binary, **kwargs)
    stack.callback(value.close)
    return value


def release(value):
    try:
        assert value.request(4, [(LIFETIME, bytes(4))])[0] == 0x104
    except (OSError, EOFError, AssertionError) as failure:
        raise AssertionError(f"deallocation failed over {value.mode}") from failure


def channel_roundtrip(value, remote, payload):
    value.send(struct.pack("!HH", 0x4000, len(payload)) + payload)
    received, source = remote.recvfrom(65_536)
    assert received == payload and source == value.relay, "outbound payload/source mismatch"
    remote.sendto(received, source)
    response = value.receive()
    number, length = struct.unpack_from("!HH", response)
    assert number == 0x4000 and response[4:4 + length] == payload, "inbound payload mismatch"


def reserve_range(stack, size):
    chooser = random.SystemRandom()
    for _ in range(100):
        sockets = []
        try:
            first = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sockets.append(first)
            # Keep relay slots outside the usual automatic client-port range.
            # Otherwise a later UDP fixture client can itself occupy a relay
            # slot and legitimately trigger 508 before the intended capacity.
            first.bind(("127.0.0.1", chooser.randrange(10_000, 20_000 - size)))
            port = first.getsockname()[1]
            if port + size > 65_536:
                raise OSError("range overflows")
            for offset in range(1, size):
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sockets.append(sock)
                sock.bind(("127.0.0.1", port + offset))
            for sock in sockets:
                stack.callback(sock.close)
            return port, sockets
        except OSError:
            for sock in sockets:
                sock.close()
    raise RuntimeError("could not reserve generated contiguous relay range")


def process_resources(pid):
    # Only the server is sampled. Process RSS excludes kernel socket memory;
    # these coarse samples are a bounded regression check, not a leak proof.
    result = subprocess.run(["ps", "-o", "rss=", "-p", str(pid)], capture_output=True,
                            text=True, timeout=3, check=True)
    rss = int(result.stdout.strip()) * 1024
    proc_fd = Path(f"/proc/{pid}/fd")
    if proc_fd.is_dir():
        descriptors = len(list(proc_fd.iterdir()))
    else:
        result = subprocess.run(["lsof", "-nP", "-p", str(pid), "-F", "f"],
                                capture_output=True, text=True, timeout=5)
        if result.returncode:
            raise RuntimeError("cannot observe server descriptors")
        descriptors = sum(bool(re.fullmatch(r"f[0-9]+", line)) for line in result.stdout.splitlines())
    return {"rss_bytes": rss, "open_descriptors": descriptors}


class LossyProxy:
    def __init__(self, stack, destination, seed):
        self.local = peer(stack)
        self.upstream = peer(stack)
        self.upstream.connect(destination)
        self.selector = selectors.DefaultSelector()
        stack.callback(self.selector.close)
        self.selector.register(self.local, selectors.EVENT_READ, "up")
        self.selector.register(self.upstream, selectors.EVENT_READ, "down")
        self.random = random.Random(seed)
        self.enabled = False
        self.stop = threading.Event()
        self.client = None
        self.dropped = self.delayed = self.counter = 0
        self.failure = None
        self.thread = threading.Thread(target=self.run, name="spry-lossy-udp")
        self.thread.start()
        # ExitStack unwinds this before it closes the fixture sockets.
        stack.callback(self.close)

    def close(self):
        self.stop.set()
        self.thread.join(timeout=2)
        if self.thread.is_alive():
            raise RuntimeError("lossy proxy thread did not stop")
        if self.failure:
            raise RuntimeError("lossy proxy failed") from self.failure

    def run(self):
        waiting = []
        try:
            while not self.stop.is_set():
                now = time.monotonic()
                while waiting and waiting[0][0] <= now:
                    _, _, direction, payload = heapq.heappop(waiting)
                    if direction == "up":
                        self.upstream.send(payload)
                    elif self.client is not None:
                        self.local.sendto(payload, self.client)
                for key, _ in self.selector.select(0.002):
                    if key.data == "up":
                        payload, self.client = key.fileobj.recvfrom(65_536)
                    else:
                        payload = key.fileobj.recv(65_536)
                    self.counter += 1
                    delay = 0
                    if self.enabled:
                        if self.random.randrange(5) == 0:
                            self.dropped += 1
                            continue
                        delay = self.random.random() * 0.008
                        self.delayed += 1
                    heapq.heappush(waiting, (time.monotonic() + delay, self.counter, key.data, payload))
        except Exception as failure:
            self.failure = failure
            self.stop.set()


def lossy_forwarding(binary, seed):
    with ExitStack() as stack:
        server = fixture(stack, binary)
        proxy = LossyProxy(stack, ("127.0.0.1", server.port), seed)
        value = client(stack, server)
        value.socket.connect(proxy.local.getsockname())
        value.allocate()
        remote = peer(stack)
        assert value.peer_request(9, remote.getsockname(), 0x4000)[0] == 0x109
        proxy.enabled = True
        remote.setblocking(False)
        value.socket.setblocking(False)
        sent = 256
        received = set()
        reordered = 0
        previous = -1
        deadline = time.monotonic() + 3
        for sequence in range(sent):
            payload = struct.pack("!I", sequence) + bytes([sequence % 251]) * 157
            value.send(struct.pack("!HH", 0x4000, len(payload)) + payload)
            time.sleep(0.0005)
            while True:
                try:
                    data, source = remote.recvfrom(65_536)
                    assert source == value.relay
                    remote.sendto(data, source)
                except BlockingIOError:
                    break
        while time.monotonic() < deadline:
            while True:
                try:
                    data, source = remote.recvfrom(65_536)
                    assert source == value.relay
                    remote.sendto(data, source)
                except BlockingIOError:
                    break
            while True:
                try:
                    data = value.receive()
                except BlockingIOError:
                    break
                number, length = struct.unpack_from("!HH", data)
                assert number == 0x4000 and length == 161
                sequence = struct.unpack_from("!I", data, 4)[0]
                assert sequence < sent and sequence not in received
                assert data[8:4 + length] == bytes([sequence % 251]) * 157
                reordered += sequence < previous
                previous = sequence
                received.add(sequence)
            time.sleep(0.001)
        assert proxy.dropped > 0 and proxy.delayed > 0
        assert 0 < len(received) < sent, "loss fixture must exercise both progress and loss"
        proxy.enabled = False
        value.socket.settimeout(1)
        release(value)
        return {"sent_roundtrips": sent, "received_roundtrips": len(received),
                "incomplete_roundtrips": sent - len(received),
                "proxy_dropped_datagrams": proxy.dropped,
                "proxy_delayed_datagrams": proxy.delayed,
                "reordered_roundtrips": reordered,
                "max_injected_delay_ms": 8,
                "scope": "Seeded userspace UDP proxy; corruption/duplicates forbidden, loss/reordering permitted."}


def slow_streams(binary):
    with ExitStack() as stack:
        server = fixture(stack, binary, limits=("--max-connections", "2"))
        slow = []
        for _ in range(2):
            sock = socket.create_connection(("127.0.0.1", server.port), timeout=1)
            stack.callback(sock.close)
            sock.sendall(b"\0")
            slow.append(sock)
        # Wait for accept, then prove the stream cap refuses a new binding.
        time.sleep(0.05)
        refused = client(stack, server, mode="tcp")
        try:
            refused.request(1, signed=False)
        except (EOFError, ConnectionResetError, BrokenPipeError):
            pass
        else:
            raise AssertionError("connection cap did not reject the extra stream")
        stable = client(stack, server)
        stable.allocate()
        remote = peer(stack)
        assert stable.peer_request(9, remote.getsockname(), 0x4000)[0] == 0x109
        started = time.monotonic()
        progress = 0
        while time.monotonic() - started < 17:
            # Occasional bytes must not reset the 15-second unauthenticated
            # absolute lifetime. An unrelated allocation must keep forwarding.
            for sock in slow:
                try:
                    sock.sendall(b"\0")
                except (BrokenPipeError, ConnectionResetError):
                    pass
            channel_roundtrip(stable, remote, b"progress during slow input")
            progress += 1
            time.sleep(0.2)
        recovered = client(stack, server, mode="tcp")
        assert recovered.request(1, signed=False)[0] == 0x101
        recovered.allocate()
        release(recovered)
        release(stable)
        return {"connection_limit": 2, "saturated_partial_streams": 2,
                "extra_stream_rejected": True, "absolute_unauthenticated_timeout_recovered": True,
                "unrelated_udp_roundtrips": progress,
                "observed_seconds": round(time.monotonic() - started, 3)}


def credential_expiry(binary):
    with ExitStack() as stack:
        server = fixture(stack, binary)
        value = client(stack, server, expiry=int(time.time()) + 2)
        value.allocate()
        time.sleep(2.05)
        assert error_code(value.request(4)[1]) == 401
        expired = client(stack, server, expiry=int(time.time()) - 1)
        _, fields, _ = expired.request(3, signed=False)
        expired.nonce = fields[NONCE]
        assert error_code(expired.request(3, [(TRANSPORT, b"\x11\0\0\0")])[1]) == 401
        healthy = client(stack, server)
        healthy.allocate()
        release(healthy)
        return {"live_credential_expiry_rejected": True, "expired_allocate_rejected": True,
                "new_credential_recovery": True}


def slow_readers(binary, tls):
    observations = []
    with ExitStack() as stack:
        server = fixture(stack, binary, tls=tls)
        stable = client(stack, server)
        stable.allocate()
        stable_peer = peer(stack)
        assert stable.peer_request(9, stable_peer.getsockname(), 0x4000)[0] == 0x109
        for mode in ["tcp"] + (["tls"] if tls else []):
            value = client(stack, server, mode=mode)
            # A small advertised receive window makes a pause useful pressure,
            # although the internal queue state still depends on OS buffers.
            value.socket.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1024)
            value.allocate()
            remote = peer(stack)
            assert value.peer_request(9, remote.getsockname(), 0x4000)[0] == 0x109
            count = 48
            for sequence in range(count):
                payload = struct.pack("!I", sequence) + bytes([sequence % 251]) * 1196
                remote.sendto(payload, value.relay)
                time.sleep(0.001)
            time.sleep(0.1)
            channel_roundtrip(stable, stable_peer, b"progress while reader is paused")
            for sequence in range(count):
                response = value.receive()
                number, length = struct.unpack_from("!HH", response)
                assert number == 0x4000 and length == 1200
                assert struct.unpack_from("!I", response, 4)[0] == sequence
                assert response[8:4 + length] == bytes([sequence % 251]) * 1196
            channel_roundtrip(value, remote, b"forwarding after drain")
            assert value.request(4)[0] == 0x104
            release(value)
            observations.append({"client_transport": mode, "paused_inbound_bytes": count * 1200,
                                 "ordered_frames_drained": count,
                                 "post_drain_roundtrip_and_refresh": True,
                                 "unrelated_udp_progress": True})
        release(stable)
    return {"transports": observations,
            "scope": "Paused readers and drain/resume over real sockets. OS buffers vary; the public test does not prove an internal WouldBlock event."}


def control_burst_recovery(binary):
    with ExitStack() as stack:
        server = fixture(stack, binary)
        stable = client(stack, server)
        stable.allocate()
        remote = peer(stack)
        assert stable.peer_request(9, remote.getsockname(), 0x4000)[0] == 0x109
        flood = client(stack, server)
        flood.socket.setblocking(False)
        request = packet(1, tid=bytes(12))
        sent = received = 0

        def drain():
            count = 0
            while True:
                try:
                    response = flood.receive()
                except BlockingIOError:
                    return count
                assert parse(response)[0] == 0x101
                count += 1

        started = time.monotonic()
        while sent < 10_000:
            try:
                flood.send(request)
                sent += 1
            except BlockingIOError:
                pass
            if sent % 128 == 0:
                received += drain()
        offered_seconds = time.monotonic() - started
        drain_deadline = time.monotonic() + 0.25
        while time.monotonic() < drain_deadline:
            received += drain()
            time.sleep(0.001)
        channel_roundtrip(stable, remote, b"progress after control burst")
        time.sleep(0.1)
        assert stable.request(4)[0] == 0x104
        release(stable)
        assert 0 < received <= sent
        assert server.process.poll() is None
        return {"offered_binding_requests": sent, "received_binding_responses": received,
                "offered_requests_per_second": round(sent / offered_seconds),
                "post_burst_channel_roundtrip_and_refresh": True,
                "scope": "A finite UDP control burst; absent replies can reflect socket buffers as well as control admission. Tests recovery, not drop attribution."}


def churn(binary, seconds, tls, seed):
    counts = {"rounds": 0, "allocations": 0, "signed_exhaustions": 0,
              "tampered_nonce_rejections": 0, "wrong_key_rejections": 0,
              "private_peer_rejections": 0, "stable_roundtrips": 0,
              "refreshed_roundtrips": 0, "churn_roundtrips": 0}
    random_source = random.Random(seed)
    modes = ["udp", "tcp"] + (["tls"] if tls else [])
    with ExitStack() as stack:
        first, reserved = reserve_range(stack, 8)
        server = fixture(stack, binary, tls=tls,
                         limits=("--relay-ports", f"{first}:{first + 7}", "--max-allocations", "16"))
        for sock in reserved:
            sock.close()
        stable = client(stack, server)
        stable.allocate()
        counts["allocations"] += 1
        remote = peer(stack)
        assert stable.peer_request(9, remote.getsockname(), 0x4000)[0] == 0x109
        assert stable.request(4, [(LIFETIME, struct.pack("!I", 4))])[0] == 0x104
        channel_roundtrip(stable, remote, b"initial")
        baseline = process_resources(server.process.pid)
        maximum_rss = baseline["rss_bytes"]
        maximum_fd = baseline["open_descriptors"]
        samples = 1
        started = time.monotonic()
        refreshed = sampled = started
        while time.monotonic() - started < seconds:
            round_started = time.monotonic()
            with ExitStack() as round_stack:
                current = []
                for index in range(7):
                    mode = modes[(counts["rounds"] + index) % len(modes)]
                    value = client(round_stack, server, mode=mode)
                    value.allocate()
                    assert first <= value.relay[1] < first + 8
                    current.append(value)
                    counts["allocations"] += 1
                extra = client(round_stack, server)
                _, fields, _ = extra.request(3, signed=False)
                extra.nonce = fields[NONCE]
                extra.send(packet(3, [(TRANSPORT, b"\x11\0\0\0"), (USERNAME, extra.username),
                                      (REALM_ATTR, REALM), (NONCE, extra.nonce)], extra.key))
                assert error_code(parse(extra.receive(), extra.key)[1]) == 508
                counts["signed_exhaustions"] += 1
                value = current[0]
                original_nonce, original_key = value.nonce, value.key
                value.nonce = b"!" * len(original_nonce)
                assert error_code(value.request(4)[1]) == 438
                value.nonce = original_nonce
                counts["tampered_nonce_rejections"] += 1
                value.key = bytes(16)
                assert error_code(value.request(4)[1]) == 401
                value.key = original_key
                counts["wrong_key_rejections"] += 1
                assert error_code(value.peer_request(8, ("10.0.0.1", 1234))[1]) == 403
                counts["private_peer_rejections"] += 1
                remote_current = peer(round_stack)
                for value in current:
                    assert value.peer_request(9, remote_current.getsockname(), 0x4000)[0] == 0x109
                    payload = random_source.randbytes(random_source.choice((1, 159, 1201)))
                    channel_roundtrip(value, remote_current, payload)
                    counts["churn_roundtrips"] += 1
                for index, value in enumerate(current):
                    try:
                        release(value)
                    except AssertionError as failure:
                        raise AssertionError(f"churn round {counts['rounds']} client {index} {value.mode}") from failure
                # The previously exhausted request now succeeds in a released
                # port, exercising event-token reuse while stable stays live.
                extra.allocate()
                assert first <= extra.relay[1] < first + 8
                counts["allocations"] += 1
                release(extra)
            now = time.monotonic()
            if now - refreshed >= 0.5:
                assert stable.request(4, [(LIFETIME, struct.pack("!I", 4))])[0] == 0x104
                refreshed = now
                counts["refreshed_roundtrips"] += 1
            channel_roundtrip(stable, remote, struct.pack("!Q", counts["rounds"]))
            counts["stable_roundtrips"] += 1
            counts["rounds"] += 1
            if now - sampled >= 2:
                sample = process_resources(server.process.pid)
                maximum_rss = max(maximum_rss, sample["rss_bytes"])
                maximum_fd = max(maximum_fd, sample["open_descriptors"])
                samples += 1
                sampled = time.monotonic()
            assert server.process.poll() is None
            # Each round issues 35 controls plus occasional stable refreshes.
            # Stay below the server's 2000/s global admission bucket; this phase
            # tests longevity and reuse. A separate phase exercises bursts.
            time.sleep(max(0, 0.04 - (time.monotonic() - round_started)))
        # Let close events settle before comparing with the same live baseline.
        time.sleep(0.15)
        final = process_resources(server.process.pid)
        assert final["open_descriptors"] <= baseline["open_descriptors"], "descriptors did not return to baseline"
        assert final["rss_bytes"] <= baseline["rss_bytes"] + 16 * 1024 * 1024, "sustained RSS regression budget exceeded"
        assert counts["rounds"] > 0 and counts["refreshed_roundtrips"] > 0
        release(stable)
        return {**counts, "client_transports": modes, "configured_relay_ports": 8,
                "max_churn_rounds_per_second": 25,
                "issued_control_requests": 5 + 35 * counts["rounds"] + counts["refreshed_roundtrips"],
                "observed_seconds": round(time.monotonic() - started, 3),
                "resources": {"baseline": baseline, "final": final,
                              "max_sampled_rss_bytes": maximum_rss,
                              "max_sampled_open_descriptors": maximum_fd,
                              "samples": samples, "rss_regression_budget_bytes": 16 * 1024 * 1024,
                              "scope": "Server-only coarse process RSS/FD sampling; excludes kernel socket memory and does not prove absence of leaks."}}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, default=Path("target/release/spry-turn"))
    parser.add_argument("--seconds", type=bounded_int(3, 86_400), default=60,
                        help="sustained churn phase; other qualification phases add about 25 seconds")
    parser.add_argument("--seed", type=bounded_int(1, 2**32 - 1), default=7411)
    parser.add_argument("--tls", action="store_true")
    parser.add_argument("--output", type=Path, default=Path(".local/stress.json"))
    args = parser.parse_args()
    binary = args.binary.resolve()
    root = Path(__file__).resolve().parents[1]
    started = time.monotonic()
    receipt = {"schema": 1, "kind": "standalone-local-sustained-qualification",
               "seed": args.seed, "requested_churn_seconds": args.seconds,
               "binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
               "binary_version": subprocess.run([str(binary), "--version"], check=True,
                                                capture_output=True, text=True, timeout=3).stdout.strip(),
               "harness_source_sha256": {path: hashlib.sha256((root / path).read_bytes()).hexdigest()
                                         for path in ("tests/stress.py", "tests/interop.py")},
               "passed": False, "phases": {}}
    try:
        receipt["phases"]["churn"] = churn(binary, args.seconds, args.tls, args.seed)
        receipt["phases"]["loss_and_jitter"] = lossy_forwarding(binary, args.seed)
        receipt["phases"]["credential_expiry"] = credential_expiry(binary)
        receipt["phases"]["slow_streams"] = slow_streams(binary)
        receipt["phases"]["slow_readers"] = slow_readers(binary, args.tls)
        receipt["phases"]["control_burst_recovery"] = control_burst_recovery(binary)
        receipt["passed"] = True
    finally:
        receipt["elapsed_seconds"] = round(time.monotonic() - started, 3)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(receipt, indent=2) + "\n")
        print(json.dumps(receipt, indent=2))


if __name__ == "__main__":
    main()
