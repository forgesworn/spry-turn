#!/usr/bin/env python3
"""Independent Python stdlib wire client against the real standalone server."""
import argparse
import base64
import errno
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import secrets
import selectors
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock
import zlib

TLS = "--tls" in sys.argv

COOKIE = 0x2112A442
REALM = b"spry-turn"
USERNAME, MI, ERROR, UNKNOWN = 6, 8, 9, 10
CHANNEL, LIFETIME, PEER, DATA, REALM_ATTR, NONCE = 12, 13, 18, 19, 20, 21
RELAYED, FAMILY, TRANSPORT, MAPPED, FP = 22, 23, 25, 32, 0x8028


def attr(kind, value):
    return struct.pack("!HH", kind, len(value)) + value + bytes(-len(value) % 4)


def packet(method, attrs=(), key=None, tid=None, indication=False):
    tid = tid or secrets.token_bytes(12)
    typ = method | (0x10 if indication else 0)
    body = b"".join(attr(k, v) for k, v in attrs)
    if key is not None:
        header = struct.pack("!HHI12s", typ, len(body) + 24, COOKIE, tid)
        body += attr(MI, hmac.digest(key, header + body, "sha1"))
    header = struct.pack("!HHI12s", typ, len(body) + 8, COOKIE, tid)
    body += attr(FP, struct.pack("!I", zlib.crc32(header + body) ^ 0x5354554E))
    return header + body


def parse(data, key=None):
    typ, length, cookie, tid = struct.unpack_from("!HHI12s", data)
    assert cookie == COOKIE and len(data) == length + 20
    attrs = {}
    offset = 20
    signed = False
    while offset < len(data):
        kind, size = struct.unpack_from("!HH", data, offset)
        value = data[offset + 4:offset + 4 + size]
        if kind == MI and key is not None:
            header = data[:2] + struct.pack("!H", offset + 4) + data[4:20]
            assert hmac.compare_digest(value, hmac.digest(key, header + data[20:offset], "sha1"))
            signed = True
        if kind == FP:
            assert struct.unpack("!I", value)[0] == zlib.crc32(data[:offset]) ^ 0x5354554E
        attrs.setdefault(kind, value)
        offset += 4 + (size + 3 & ~3)
    if key is not None:
        assert signed, "missing response integrity"
    return typ, attrs, tid


def address(value, tid):
    family = socket.AF_INET if value[1] == 1 else socket.AF_INET6
    mask = struct.pack("!I", COOKIE) + tid
    ip = bytes(a ^ b for a, b in zip(value[4:], mask))
    return socket.inet_ntop(family, ip), struct.unpack_from("!H", value, 2)[0] ^ (COOKIE >> 16)


def peer_attr(peer, tid):
    family = 1 if ":" not in peer[0] else 2
    packed = socket.inet_pton(socket.AF_INET if family == 1 else socket.AF_INET6, peer[0])
    mask = struct.pack("!I", COOKIE) + tid
    return struct.pack("!BBH", 0, family, peer[1] ^ (COOKIE >> 16)) + bytes(a ^ b for a, b in zip(packed, mask))


def reserve_listener_ports(tls):
    """Hold a common TCP/UDP port and a distinct TLS TCP port until hand-off.

    UDP port zero can select a number unavailable to TCP, including a recently
    closed client's TIME_WAIT port. Probe both protocols, without SO_REUSEADDR,
    and keep the reservations together. The generated range also avoids the
    usual automatic client-port ranges on our Linux and macOS test machines.
    """
    for _ in range(64):
        held = []
        try:
            tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            held.append(tcp)
            tcp.bind(("127.0.0.1", 20_000 + secrets.randbelow(10_000)))
            port = tcp.getsockname()[1]
            udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            held.append(udp)
            udp.bind(("127.0.0.1", port))
            tls_port = None
            if tls:
                secure = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                held.append(secure)
                secure.bind(("127.0.0.1", 20_000 + secrets.randbelow(10_000)))
                tls_port = secure.getsockname()[1]
            return port, tls_port, held
        except OSError as failure:
            for sock in held:
                sock.close()
            if failure.errno != errno.EADDRINUSE:
                raise
    raise RuntimeError("could not reserve distinct fixture listener ports")


class Fixture:
    STARTUP_TIMEOUT = 10
    STARTUP_ATTEMPTS = 8

    def __init__(self, binary, loopback=True, limits=(), tls=False):
        self.secret = secrets.token_hex(32)
        self.temp = tempfile.TemporaryDirectory(prefix="spry-turn-test-")
        self.cert = Path(self.temp.name) / "cert.pem"
        self.process = None
        self.tls_port = None
        self.startup_attempts = 0
        try:
            if tls:
                key = Path(self.temp.name) / "key.pem"
                subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1", "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1", "-keyout", str(key), "-out", str(self.cert)], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30)
            deadline = time.monotonic() + self.STARTUP_TIMEOUT
            for _ in range(self.STARTUP_ATTEMPTS):
                self.port, self.tls_port, held = reserve_listener_ports(tls)
                try:
                    args = [str(binary), "serve", "--listen", f"127.0.0.1:{self.port}", *limits]
                    if loopback:
                        args += ["--allow-loopback-peers"]
                    if tls:
                        args += ["--tls-listen", f"127.0.0.1:{self.tls_port}", "--tls-cert", str(self.cert), "--tls-key", str(key)]
                finally:
                    for sock in held:
                        sock.close()
                self.startup_attempts += 1
                self.process = subprocess.Popen(args, env={**os.environ, "SPRY_TURN_SECRET": self.secret}, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
                line = self._startup_line(deadline)
                found = re.search(rb"UDP/TCP 127\.0\.0\.1:(\d+)\)", line)
                if found and int(found[1]) == self.port:
                    return
                self._stop_process()
                # Only the unavoidable reservation-to-child hand-off race is
                # retryable. Invalid configuration and other failures surface.
                collision = line.startswith(b"spry-turn: ") and line.rstrip().endswith(
                    f"(os error {errno.EADDRINUSE})".encode())
                if not collision:
                    raise RuntimeError("server startup failed before readiness")
                if time.monotonic() >= deadline:
                    raise TimeoutError("fixture listener collision deadline exceeded")
            raise RuntimeError("fixture listener ports collided repeatedly")
        except BaseException:
            self.close()
            raise

    def _startup_line(self, deadline):
        output = bytearray()
        with selectors.DefaultSelector() as events:
            descriptor = self.process.stderr.fileno()
            os.set_blocking(descriptor, False)
            events.register(descriptor, selectors.EVENT_READ)
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0 or not events.select(remaining):
                    raise TimeoutError("fixture startup readiness deadline exceeded")
                data = os.read(descriptor, 4096)
                if not data:
                    return bytes(output)
                output.extend(data)
                if len(output) > 8192:
                    raise RuntimeError("fixture startup output limit exceeded")
                if b"\n" in output:
                    return bytes(output).split(b"\n", 1)[0]

    def _stop_process(self):
        if self.process is None:
            return
        if self.process.poll() is None:
            self.process.terminate()
            try: self.process.wait(timeout=3)
            except subprocess.TimeoutExpired: self.process.kill(); self.process.wait(timeout=3)
        self.process.stderr.close()

    def close(self):
        try:
            self._stop_process()
        finally:
            self.temp.cleanup()


class Client:
    def __init__(self, fixture, mode="udp", label=None, expiry=None):
        self.fixture, self.mode = fixture, mode
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM if mode == "udp" else socket.SOCK_STREAM)
        self.socket.settimeout(2)
        if mode == "tls":
            context = ssl.create_default_context(cafile=str(fixture.cert))
            self.socket = context.wrap_socket(self.socket, server_hostname="localhost")
        self.socket.connect((getattr(fixture, "host", "127.0.0.1"), fixture.tls_port if mode == "tls" else fixture.port))
        label = label or "test" + secrets.token_hex(4)
        self.username = f"{expiry or int(time.time()) + 3600}:{label}".encode()
        password = base64.b64encode(hmac.digest(fixture.secret.encode(), self.username, "sha1"))
        self.key = hashlib.md5(self.username + b":" + REALM + b":" + password).digest()
        self.nonce = None
        self.pending = b""

    def close(self): self.socket.close()

    def send(self, data):
        if self.mode == "udp": self.socket.send(data)
        else:
            if data[0] >> 6 == 1: data += bytes(-len(data) % 4)
            self.socket.sendall(data)

    def receive(self):
        if self.mode == "udp": return self.socket.recv(65536)
        while True:
            if len(self.pending) >= 4:
                size = struct.unpack_from("!H", self.pending, 2)[0]
                length = 4 + (size + 3 & ~3) if self.pending[0] >> 6 == 1 else 20 + size
                if len(self.pending) >= length:
                    result, self.pending = self.pending[:length], self.pending[length:]
                    return result
            data = self.socket.recv(65536)
            if not data: raise EOFError("server closed stream")
            self.pending += data

    def request(self, method, attrs=(), tid=None, signed=True):
        tid = tid or secrets.token_bytes(12)
        fields = list(attrs)
        if signed:
            fields += [(USERNAME, self.username), (REALM_ATTR, REALM), (NONCE, self.nonce)]
        self.send(packet(method, fields, self.key if signed else None, tid))
        data = self.receive()
        result = parse(data, self.key if signed and b"\x00\x08\x00\x14" in data else None)
        assert result[2] == tid
        return result

    def allocate(self, tid=None):
        if self.nonce is None:
            _, fields, _ = self.request(3, [(TRANSPORT, b"\x11\x00\x00\x00")], signed=False)
            assert error_code(fields) == 401
            self.nonce = fields[NONCE]
        typ, fields, response_tid = self.request(3, [(TRANSPORT, b"\x11\x00\x00\x00")], tid)
        assert typ == 0x103, fields
        self.relay = address(fields[RELAYED], response_tid)
        return self.relay

    def peer_request(self, method, peer, channel=None):
        tid = secrets.token_bytes(12)
        fields = [(PEER, peer_attr(peer, tid))]
        if channel is not None: fields.append((CHANNEL, struct.pack("!HH", channel, 0)))
        return self.request(method, fields, tid)


def error_code(fields):
    value = fields[ERROR]
    return value[2] * 100 + value[3]


class FixtureLifecycle(unittest.TestCase):
    def test_reservations_hold_both_protocols_and_distinct_tls_port(self):
        port, tls_port, held = reserve_listener_ports(True)
        for sock in held: self.addCleanup(sock.close)
        self.assertNotEqual(port, tls_port)
        for kind, number in ((socket.SOCK_STREAM, port), (socket.SOCK_DGRAM, port),
                             (socket.SOCK_STREAM, tls_port)):
            with socket.socket(socket.AF_INET, kind) as probe:
                with self.assertRaises(OSError) as failure:
                    probe.bind(("127.0.0.1", number))
                self.assertEqual(failure.exception.errno, errno.EADDRINUSE)

    def test_occupied_tcp_or_udp_candidate_is_skipped(self):
        original = secrets.randbelow
        for kind in (socket.SOCK_STREAM, socket.SOCK_DGRAM):
            with self.subTest(kind=kind):
                _, _, held = reserve_listener_ports(False)
                port = held[0].getsockname()[1]
                for sock in held: sock.close()
                with socket.socket(socket.AF_INET, kind) as occupied:
                    occupied.bind(("127.0.0.1", port))
                    calls = []
                    def choose(bound):
                        calls.append(bound)
                        return port - 20_000 if len(calls) == 1 else original(bound)
                    with mock.patch.object(secrets, "randbelow", side_effect=choose):
                        selected, _, reserved = reserve_listener_ports(False)
                    for sock in reserved: self.addCleanup(sock.close)
                    self.assertNotEqual(selected, port)
                    self.assertGreaterEqual(len(calls), 2)

    def test_listener_handoff_collision_retries_and_reaps_failed_child(self):
        original = subprocess.Popen
        children, blockers = [], []
        def start(args, **kwargs):
            if not children:
                port = int(args[args.index("--listen") + 1].rsplit(":", 1)[1])
                blocker = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.addCleanup(blocker.close)
                blocker.bind(("127.0.0.1", port))
                blockers.append(blocker)
            else:
                blockers[0].close()
            process = original(args, **kwargs)
            children.append(process)
            return process
        with mock.patch.object(subprocess, "Popen", side_effect=start):
            fixture = Fixture(BINARY)
        self.addCleanup(fixture.close)
        self.assertEqual(fixture.startup_attempts, 2)
        self.assertIsNotNone(children[0].poll())
        value = Client(fixture); self.addCleanup(value.close)
        self.assertEqual(value.request(1, signed=False)[0], 0x101)

    def test_non_bind_startup_error_is_not_retried(self):
        original = subprocess.Popen
        children = []
        def start(*args, **kwargs):
            process = original(*args, **kwargs)
            children.append(process)
            return process
        with mock.patch.object(subprocess, "Popen", side_effect=start):
            with self.assertRaisesRegex(RuntimeError, "startup failed"):
                Fixture(BINARY, limits=("--bytes-per-second", "0"))
        self.assertEqual(len(children), 1)
        self.assertIsNotNone(children[0].poll())

    def test_partial_startup_line_obeys_deadline_and_reaps_child(self):
        scratch = tempfile.TemporaryDirectory(prefix="spry-startup-deadline-")
        self.addCleanup(scratch.cleanup)
        binary = Path(scratch.name) / "silent-fixture"
        binary.write_text("#!/usr/bin/env python3\nimport sys, time\nsys.stderr.write('partial'); sys.stderr.flush()\ntime.sleep(60)\n")
        binary.chmod(0o700)
        original = subprocess.Popen
        children = []
        def start(*args, **kwargs):
            process = original(*args, **kwargs)
            children.append(process)
            return process
        began = time.monotonic()
        with mock.patch.object(Fixture, "STARTUP_TIMEOUT", 0.2), mock.patch.object(subprocess, "Popen", side_effect=start):
            with self.assertRaises(TimeoutError): Fixture(binary)
        self.assertLess(time.monotonic() - began, 4)
        self.assertEqual(len(children), 1)
        self.assertIsNotNone(children[0].poll())


class Interop(unittest.TestCase):
    @classmethod
    def setUpClass(cls): cls.fixture = Fixture(BINARY, tls=TLS)
    @classmethod
    def tearDownClass(cls): cls.fixture.close()

    def client(self, **kwargs):
        c = Client(self.fixture, **kwargs); self.addCleanup(c.close); return c

    def peer(self):
        p = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); p.bind(("127.0.0.1", 0)); p.settimeout(0.2)
        self.addCleanup(p.close); return p

    def test_binding(self):
        c = self.client(); typ, fields, tid = c.request(1, signed=False)
        self.assertEqual(typ, 0x101); self.assertEqual(address(fields[MAPPED], tid), c.socket.getsockname())

    def test_duplicate_allocate_is_idempotent(self):
        c = self.client(); tid = secrets.token_bytes(12); first = c.allocate(tid)
        self.assertEqual(c.allocate(tid), first)
        self.assertEqual(error_code(c.request(3, [(TRANSPORT, b"\x11\x00\x00\x00")])[1]), 437)

    def test_signed_refresh_and_deallocation(self):
        c = self.client(); c.allocate()
        self.assertEqual(c.request(4, [(LIFETIME, struct.pack("!I", 0))])[0], 0x104)
        self.assertEqual(error_code(c.request(4)[1]), 437)
        c.allocate()

    def test_expired_credentials(self):
        c = self.client(expiry=int(time.time()) - 1)
        _, fields, _ = c.request(3, [(TRANSPORT, b"\x11\0\0\0")], signed=False); c.nonce = fields[NONCE]
        self.assertEqual(error_code(c.request(3, [(TRANSPORT, b"\x11\0\0\0")])[1]), 401)

    def test_nonce_tamper(self):
        c = self.client(); c.allocate(); c.nonce = b"A" * len(c.nonce)
        self.assertEqual(error_code(c.request(4)[1]), 438)

    def test_wrong_key(self):
        c = self.client(); c.allocate(); c.key = bytes(16)
        self.assertEqual(error_code(c.request(4)[1]), 401)

    def test_unknown_attribute_and_unsupported_transport(self):
        c = self.client(); c.allocate(); c.request(4, [(LIFETIME, bytes(4))])
        self.assertEqual(error_code(c.request(3, [(TRANSPORT, b"\x06\0\0\0")])[1]), 442)
        self.assertEqual(error_code(c.request(3, [(TRANSPORT, b"\x11\0\0\0"), (FAMILY, b"\x02\0\0\0")])[1]), 440)
        fields = c.request(3, [(TRANSPORT, b"\x11\0\0\0"), (0x7777, b"")])[1]
        self.assertEqual(error_code(fields), 420); self.assertEqual(fields[UNKNOWN], b"\x77\x77")

    def test_private_peers_forbidden(self):
        c = self.client(); c.allocate()
        self.assertEqual(error_code(c.peer_request(8, ("10.0.0.1", 1234))[1]), 403)

    def test_unsolicited_peer_packets_are_dropped(self):
        c = self.client(); relay = c.allocate(); p = self.peer(); p.sendto(b"uninvited", relay)
        c.socket.settimeout(0.15)
        with self.assertRaises(socket.timeout): c.receive()

    def test_send_and_data_indications(self):
        c = self.client(); relay = c.allocate(); p = self.peer(); peer = p.getsockname()
        self.assertEqual(c.peer_request(8, peer)[0], 0x108)
        tid = secrets.token_bytes(12)
        c.send(packet(6, [(PEER, peer_attr(peer, tid)), (DATA, b"outbound")], tid=tid, indication=True))
        data, source = p.recvfrom(1024); self.assertEqual(data, b"outbound"); self.assertEqual(source, relay)
        p.sendto(b"inbound", relay); typ, fields, tid = parse(c.receive())
        self.assertEqual(typ, 0x17); self.assertEqual(fields[DATA], b"inbound"); self.assertEqual(address(fields[PEER], tid), peer)

    def check_channel(self, mode):
        c = self.client(mode=mode); relay = c.allocate(); p = self.peer(); peer = p.getsockname()
        self.assertEqual(c.peer_request(9, peer, 0x4000)[0], 0x109)
        payload = secrets.token_bytes(1201)
        c.send(struct.pack("!HH", 0x4000, len(payload)) + payload)
        data, source = p.recvfrom(2048); self.assertEqual(data, payload); self.assertEqual(source, relay)
        p.sendto(payload, relay); response = c.receive()
        number, size = struct.unpack_from("!HH", response)
        self.assertEqual(number, 0x4000); self.assertEqual(response[4:4 + size], payload)
        self.assertEqual(error_code(c.peer_request(9, (peer[0], peer[1] + 1), 0x4000)[1]), 400)

    def test_udp_channel_both_directions(self): self.check_channel("udp")
    def test_tcp_channel_both_directions(self): self.check_channel("tcp")
    @unittest.skipUnless(TLS, "TLS build required")
    def test_tls_channel_both_directions(self): self.check_channel("tls")

    def test_tcp_fragmentation_and_coalescing(self):
        c = self.client(mode="tcp")
        data = packet(1)
        for byte in data: c.socket.sendall(bytes([byte]))
        self.assertEqual(parse(c.receive())[0], 0x101)
        c.socket.sendall(data + data)
        self.assertEqual(parse(c.receive())[0], 0x101); self.assertEqual(parse(c.receive())[0], 0x101)

    def test_invalid_stream_lengths_close_only_the_offending_client(self):
        modes = ["tcp"] + (["tls"] if TLS else [])
        for mode in modes:
            for header in (b"\x80\0\0\0", b"\0\x01\xff\xff"):
                with self.subTest(mode=mode, header=header.hex()):
                    value = self.client(mode=mode)
                    value.socket.sendall(header)
                    try:
                        self.assertEqual(value.socket.recv(1), b"")
                    except ConnectionResetError:
                        pass
                    healthy = self.client(mode=mode)
                    self.assertEqual(healthy.request(1, signed=False)[0], 0x101)

    def test_bad_fingerprint_is_dropped_and_listener_recovers(self):
        value = self.client()
        damaged = bytearray(packet(1)); damaged[-1] ^= 1
        value.send(damaged)
        value.socket.settimeout(0.1)
        with self.assertRaises(socket.timeout): value.receive()
        value.socket.settimeout(2)
        self.assertEqual(value.request(1, signed=False)[0], 0x101)

    def test_malformed_channel_frames_cannot_forward(self):
        value = self.client(); value.allocate(); remote = self.peer()
        self.assertEqual(value.peer_request(9, remote.getsockname(), 0x4000)[0], 0x109)
        malformed = (b"\x40\0\0\x05a", b"\x40\0\0\x01a" + bytes(8), b"\x50\0\0\x01a")
        remote.settimeout(0.1)
        for frame in malformed:
            value.send(frame)
            with self.assertRaises(socket.timeout): remote.recvfrom(1024)
        value.send(b"\x40\0\0\x01a")
        self.assertEqual(remote.recvfrom(1024), (b"a", value.relay))

    def test_unsigned_lifetime_after_integrity_cannot_delete_allocation(self):
        value = self.client(); value.allocate()
        tid = secrets.token_bytes(12)
        data = packet(4, [(USERNAME, value.username), (REALM_ATTR, REALM),
                          (NONCE, value.nonce)], value.key, tid)[:-8]
        # MESSAGE-INTEGRITY protects only the preceding attributes. The
        # fingerprint covers the appended attribute but does not authenticate it.
        data += attr(LIFETIME, bytes(4))
        data = data[:2] + struct.pack("!H", len(data) - 20 + 8) + data[4:]
        data += attr(FP, struct.pack("!I", zlib.crc32(data) ^ 0x5354554E))
        value.send(data)
        typ, fields, response_tid = parse(value.receive(), value.key)
        self.assertEqual((typ, response_tid), (0x104, tid))
        self.assertGreater(struct.unpack("!I", fields[LIFETIME])[0], 0)
        self.assertEqual(value.request(4)[0], 0x104)

    def test_expired_allocation_cannot_forward_data(self):
        value = self.client(); value.allocate(); remote = self.peer()
        self.assertEqual(value.peer_request(9, remote.getsockname(), 0x4000)[0], 0x109)
        value.request(4, [(LIFETIME, struct.pack("!I", 1))])
        time.sleep(1.05)
        value.send(b"\x40\0\0\x07expired")
        remote.settimeout(0.1)
        with self.assertRaises(socket.timeout): remote.recvfrom(1024)
        remote.sendto(b"expired", value.relay)
        value.socket.settimeout(0.1)
        with self.assertRaises(socket.timeout): value.receive()

    def test_credential_deadline_caps_refresh_and_live_channel_data(self):
        for mode in (("udp", "tcp", "tls") if TLS else ("udp", "tcp")):
            with self.subTest(mode=mode):
                expiry = int(time.time()) + 2
                value = self.client(mode=mode, expiry=expiry)
                value.allocate()
                remote = self.peer()
                self.assertEqual(value.peer_request(9, remote.getsockname(), 0x4000)[0], 0x109)
                typ, fields, _ = value.request(4, [(LIFETIME, struct.pack("!I", 3600))])
                self.assertEqual(typ, 0x104)
                self.assertLessEqual(struct.unpack("!I", fields[LIFETIME])[0], 2)
                value.send(b"\x40\0\0\x04live")
                self.assertEqual(remote.recvfrom(1024)[0], b"live")
                time.sleep(max(0, expiry - time.time()) + 0.05)
                value.send(b"\x40\0\0\x04late")
                remote.settimeout(0.1)
                with self.assertRaises(socket.timeout): remote.recvfrom(1024)
                remote.sendto(b"late", value.relay)
                value.socket.settimeout(0.1)
                with self.assertRaises(socket.timeout): value.receive()

    def test_expiry_enforced_before_sweep(self):
        c = self.client(); c.allocate(); c.request(4, [(LIFETIME, struct.pack("!I", 1))])
        time.sleep(1.05)
        self.assertEqual(error_code(c.request(4)[1]), 437)

    def test_capacity_is_bounded(self):
        f = Fixture(BINARY, limits=("--max-allocations", "1")); self.addCleanup(f.close)
        a = Client(f); b = Client(f); self.addCleanup(a.close); self.addCleanup(b.close)
        a.allocate(); _, fields, _ = b.request(3, signed=False); b.nonce = fields[NONCE]
        self.assertEqual(error_code(b.request(3, [(TRANSPORT, b"\x11\0\0\0")])[1]), 486)

    def reserve_relay_range(self):
        # Hold a generated contiguous range through server startup so the control
        # listener cannot accidentally take one of the test relay ports.
        for _ in range(64):
            sockets = []
            try:
                first = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sockets.append(first); first.bind(("127.0.0.1", 0))
                port = first.getsockname()[1]
                if port > 65533:
                    raise OSError("range would overflow")
                for offset in (1, 2):
                    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    sockets.append(sock); sock.bind(("127.0.0.1", port + offset))
                for sock in sockets: self.addCleanup(sock.close)
                return port, sockets
            except OSError:
                for sock in sockets: sock.close()
        self.fail("could not reserve generated contiguous relay ports")

    def test_relay_range_exhaustion_reuse_and_bidirectional_data(self):
        first, reserved = self.reserve_relay_range()
        f = Fixture(BINARY, tls=TLS, limits=("--relay-ports", f"{first}:{first + 2}"))
        self.addCleanup(f.close)
        # Leave the first port occupied by another host process.
        reserved[1].close(); reserved[2].close()
        modes = ["udp", "tcp"] + (["tls"] if TLS else [])
        for mode in modes:
            with self.subTest(mode=mode):
                a, b, c = [Client(f, mode=mode) for _ in range(3)]
                for client in (a, b, c): self.addCleanup(client.close)
                relay_a, relay_b = a.allocate(), b.allocate()
                self.assertEqual({relay_a[1], relay_b[1]}, {first + 1, first + 2})
                # The failure must be integrity-protected, not an unsignalled
                # timeout or a successful allocation outside the configured range.
                _, fields, _ = c.request(3, signed=False); c.nonce = fields[NONCE]
                c.send(packet(3, [(TRANSPORT, b"\x11\0\0\0"), (USERNAME, c.username),
                                  (REALM_ATTR, REALM), (NONCE, c.nonce)], c.key))
                self.assertEqual(error_code(parse(c.receive(), c.key)[1]), 508)
                peer = self.peer(); endpoint = peer.getsockname()
                self.assertEqual(b.peer_request(9, endpoint, 0x4000)[0], 0x109)
                b.send(struct.pack("!HH", 0x4000, 5) + b"range")
                data, source = peer.recvfrom(1024)
                self.assertEqual((data, source), (b"range", relay_b))
                peer.sendto(b"reply", relay_b)
                self.assertEqual(b.receive()[4:9], b"reply")
                self.assertEqual(a.request(4, [(LIFETIME, bytes(4))])[0], 0x104)
                self.assertEqual(c.allocate(), relay_a)
                # Releasing a different allocation must not disturb b's channel.
                peer.sendto(b"still-live", relay_b)
                self.assertEqual(b.receive()[4:14], b"still-live")
                for client in (b, c):
                    self.assertEqual(client.request(4, [(LIFETIME, bytes(4))])[0], 0x104)
                for client in (a, b, c): client.close()

    def test_single_relay_port_and_nat_advertisement_preserve_port(self):
        first, reserved = self.reserve_relay_range()
        f = Fixture(BINARY, limits=("--relay-ports", f"{first}:{first}",
                                   "--public-ip", "203.0.113.7"))
        self.addCleanup(f.close); reserved[0].close()
        c = Client(f); self.addCleanup(c.close)
        self.assertEqual(c.allocate(), ("203.0.113.7", first))

    def test_invalid_relay_port_cli_refuses_startup(self):
        for value in ("0:0", "0:65535", "40001:40000", "65536:65536", "-1:9", "1", "1:2:3"):
            with self.subTest(value=value):
                result = subprocess.run([str(BINARY), "serve", "--listen", "127.0.0.1:0", "--relay-ports", value],
                                        env={**os.environ, "SPRY_TURN_SECRET": secrets.token_hex(32)},
                                        capture_output=True, timeout=3)
                self.assertNotEqual(result.returncode, 0)
                self.assertNotIn(b"ready", result.stderr)

    def test_per_credential_quota(self):
        f = Fixture(BINARY, limits=("--max-per-user", "1")); self.addCleanup(f.close)
        expiry = int(time.time()) + 3600
        a = Client(f, label="quota", expiry=expiry); b = Client(f, label="quota", expiry=expiry)
        self.addCleanup(a.close); self.addCleanup(b.close)
        a.allocate(); _, fields, _ = b.request(3, signed=False); b.nonce = fields[NONCE]
        self.assertEqual(error_code(b.request(3, [(TRANSPORT, b"\x11\0\0\0")])[1]), 486)

    def test_udp_clients_stay_isolated_across_reallocation(self):
        a = self.client(); b = self.client(); a.allocate(); relay_b = b.allocate()
        peer_a = self.peer(); peer_b = self.peer()
        self.assertEqual(a.peer_request(9, peer_a.getsockname(), 0x4000)[0], 0x109)
        self.assertEqual(b.peer_request(9, peer_b.getsockname(), 0x4000)[0], 0x109)
        self.assertEqual(a.request(4, [(LIFETIME, bytes(4))])[0], 0x104)
        a.allocate()
        peer_b.sendto(b"only-b", relay_b)
        response = b.receive(); self.assertEqual(response[4:10], b"only-b")
        a.socket.settimeout(.15)
        with self.assertRaises(socket.timeout): a.receive()

    def test_loopback_peers_off_by_default(self):
        f = Fixture(BINARY, loopback=False); self.addCleanup(f.close)
        c = Client(f); self.addCleanup(c.close); c.allocate()
        self.assertEqual(error_code(c.peer_request(8, ("127.0.0.1", 9999))[1]), 403)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", type=Path, default=Path("target/release/spry-turn"))
    parser.add_argument("--tls", action="store_true")
    args, rest = parser.parse_known_args()
    BINARY, TLS = args.binary.resolve(), args.tls
    unittest.main(argv=[__file__, *rest])
