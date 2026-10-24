"""Task-local generated fixture inside one isolated Linux network namespace."""
import json
import os
import secrets
import socket
import struct
import subprocess
import sys
from types import SimpleNamespace

from interop import Client


def answer(value):
    print(json.dumps(value), flush=True)


def main():
    host = socket.gethostbyname(socket.gethostname())
    secret = secrets.token_hex(32)
    process = subprocess.Popen(["/fixture/mesh-node"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
    clients = []
    try:
        process.stdin.write(json.dumps({"client": f"{host}:3480", "peer": f"[{os.environ['FIXTURE_IP6']}]:3745", "secret": secret}) + "\n")
        process.stdin.flush()
        answer(json.loads(process.stdout.readline()))
        fixture = SimpleNamespace(host=host, port=3480, secret=secret)
        for line in sys.stdin:
            command = json.loads(line)
            action = command["action"]
            if action in ("peers", "status"):
                process.stdin.write(json.dumps({"peers": command["peers"]} if action == "peers" else {}) + "\n")
                process.stdin.flush()
                answer(json.loads(process.stdout.readline()))
            elif action == "allocate":
                clients = [Client(fixture, mode) for mode in ("udp", "tcp")]
                answer({"relays": [client.allocate() for client in clients]})
            elif action == "prepare":
                for index, (client, peer) in enumerate(zip(clients, command["relays"])):
                    typ, _, _ = client.peer_request(9, tuple(peer), 0x4000 + index)
                    assert typ == 0x109
                answer({"prepared": True})
            elif action == "send":
                for index, client in enumerate(clients):
                    body = bytes.fromhex(command["payload"]) + bytes([index])
                    client.send(struct.pack("!HH", 0x4000 + index, len(body)) + body)
                answer({"sent": len(clients)})
            elif action == "receive":
                for index, client in enumerate(clients):
                    wire = client.receive()
                    channel, length = struct.unpack_from("!HH", wire)
                    assert channel == 0x4000 + index
                    assert wire[4:4 + length] == bytes.fromhex(command["payload"]) + bytes([index])
                answer({"received": len(clients)})
            elif action == "silent":
                for client in clients:
                    client.socket.settimeout(0.5)
                    try:
                        client.receive()
                        raise AssertionError("Revoked peer delivered a datagram")
                    except socket.timeout:
                        pass
                    finally:
                        client.socket.settimeout(2)
                answer({"silent": True})
            else:
                raise ValueError("Unknown fixture command")
    finally:
        for client in clients:
            client.close()
        process.stdin.close()
        try:
            process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=3)
        process.stdout.close()


if __name__ == "__main__":
    main()
