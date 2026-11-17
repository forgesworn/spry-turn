#!/usr/bin/env python3
"""Exercise an existing Spry listener with generated credentials and packets."""
import argparse
import json
import secrets
import socket
import struct
from pathlib import Path
from types import SimpleNamespace

from interop import CHANNEL, Client


def check(fixture, mode):
    client = Client(fixture, mode=mode)
    peer = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        relay = client.allocate()
        peer.bind(("127.0.0.1", 0))
        peer.settimeout(3)
        endpoint = peer.getsockname()
        assert client.peer_request(9, endpoint, 0x4000)[0] == 0x109
        payload = secrets.token_bytes(1201)
        client.send(struct.pack("!HH", 0x4000, len(payload)) + payload)
        data, source = peer.recvfrom(2048)
        assert data == payload and source == relay
        peer.sendto(payload, relay)
        response = client.receive()
        number, size = struct.unpack_from("!HH", response)
        assert number == 0x4000 and response[4:4 + size] == payload
        assert client.request(4, [(13, bytes(4))])[0] == 0x104
        return {"transport": mode, "bidirectional_bytes": len(payload), "deallocated": True}
    finally:
        client.close()
        peer.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=3478)
    parser.add_argument("--tls-port", type=int, default=443)
    parser.add_argument("--server-name", default="localhost")
    parser.add_argument("--secret-file", type=Path, required=True)
    parser.add_argument("--ca-file", type=Path, required=True)
    parser.add_argument("--transports", nargs="+", choices=("udp", "tcp", "tls"), default=["udp", "tcp", "tls"])
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    fixture = SimpleNamespace(host=args.host, port=args.port, tls_port=args.tls_port,
                              server_hostname=args.server_name, cert=args.ca_file,
                              secret=args.secret_file.read_text().strip(), client_ports=set())
    results = [check(fixture, mode) for mode in dict.fromkeys(args.transports)]
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps({"passed": True, "results": results}, indent=2) + "\n")
    print(json.dumps({"passed": True, "transports": [result["transport"] for result in results]}))


if __name__ == "__main__":
    main()
