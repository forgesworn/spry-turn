#!/usr/bin/env python3
"""Two real Spry bridges in isolated Linux containers, with no external network."""
import argparse
import hashlib
import ipaddress
import json
from pathlib import Path
import secrets
import selectors
import subprocess
import time

ROOT = Path(__file__).resolve().parents[1]
IMAGE = "python@sha256:a0f57064cbdcd6285fa45f51237ab0b35ea8ebaed06a1f5973e89e19dfb86704"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    binary = args.binary.resolve()
    context = subprocess.check_output(["docker", "context", "show"], text=True).strip()
    docker = ["docker", "--context", context]
    label = "spry-mesh-" + secrets.token_hex(5)
    network = label + "-net"
    prefix = ipaddress.IPv6Network(((0xFD << 120) | (secrets.randbits(40) << 80) | (1 << 64), 64))
    names = [label + "-one", label + "-two"]
    children, logs = [], []
    created = False

    def read(child):
        with selectors.DefaultSelector() as poll:
            poll.register(child.stdout, selectors.EVENT_READ)
            if not poll.select(15):
                raise TimeoutError("Mesh fixture reply timed out; inspect private fixture logs")
        line = child.stdout.readline(16_385)
        if not line or len(line) > 16_384:
            raise RuntimeError("Mesh fixture exited or exceeded reply bounds")
        return json.loads(line)

    def write(child, command):
        child.stdin.write(json.dumps(command) + "\n")
        child.stdin.flush()

    def exchange(commands):
        for child, command in zip(children, commands):
            write(child, command)
        return [read(child) for child in children]

    try:
        subprocess.run(docker + ["network", "create", "--internal", "--ipv6", "--subnet", str(prefix), network], check=True, stdout=subprocess.DEVNULL)
        created = True
        inspected = json.loads(subprocess.check_output(docker + ["network", "inspect", network], text=True))[0]
        assert inspected["Internal"] is True
        scratch = ROOT / ".local"
        scratch.mkdir(exist_ok=True)
        for index, name in enumerate(names):
            log = (scratch / f"{label}-{index}.log").open("w")
            logs.append(log)
            child = subprocess.Popen(docker + [
                "run", "--rm", "-i", "--name", name, "--network", network,
                "--ip6", str(prefix.network_address + index + 2),
                "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
                "--memory", "128m", "--cpus", "1", "--pids-limit", "32", "--tmpfs", "/tmp:size=4m",
                "--env", f"FIXTURE_IP6={prefix.network_address + index + 2}",
                "--env", "PYTHONDONTWRITEBYTECODE=1",
                "--mount", f"type=bind,source={binary},target=/fixture/mesh-node,readonly",
                "--mount", f"type=bind,source={ROOT / 'tests'},target=/fixture/tests,readonly",
                IMAGE, "python3", "-u", "/fixture/tests/mesh-node.py",
            ], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=log, text=True)
            children.append(child)
        cards = [read(child)["card"] for child in children]
        exchange([{"action": "peers", "peers": [cards[1]]}, {"action": "peers", "peers": [cards[0]]}])
        deadline = time.monotonic() + 12
        while True:
            states = exchange([{"action": "status"}] * 2)
            if all(state["healthy"] and state["connected"] == 1 for state in states):
                break
            if time.monotonic() >= deadline:
                raise TimeoutError("Authenticated peer link did not connect")
            time.sleep(0.1)
        print("Mesh fixture: two authenticated peer links connected", flush=True)
        allocated = exchange([{"action": "allocate"}] * 2)
        exchange([{"action": "prepare", "relays": allocated[1]["relays"]}, {"action": "prepare", "relays": allocated[0]["relays"]}])
        for _ in range(3):
            payload = secrets.token_bytes(1280).hex()
            exchange([{"action": "send", "payload": payload}] * 2)
            received = exchange([{"action": "receive", "payload": payload}] * 2)
            assert all(reply["received"] == 2 for reply in received)
        print("Mesh fixture: bidirectional UDP/TCP TURN ChannelData passed", flush=True)
        write(children[0], {"action": "peers", "peers": []})
        read(children[0])
        time.sleep(0.2)
        payload = secrets.token_bytes(128).hex()
        write(children[1], {"action": "send", "payload": payload})
        read(children[1])
        write(children[0], {"action": "silent"})
        assert read(children[0])["silent"] is True
        print("Mesh fixture: withdrawal stopped live ChannelData", flush=True)
        receipt = {
            "schema": 1, "scope": "isolated-linux-peer-bridge-udp-tcp", "passed": True,
            "twoNetworkNamespaces": True, "externalNetworkingDisabled": True,
            "publishedHostPorts": False, "extraContainerCapabilities": False,
            "containerMemoryLimitBytes": 134217728, "authenticatedPeerLinks": True,
            "udpTurnBidirectional": True, "tcpTurnBidirectional": True,
            "withdrawalStopsForwarding": True, "payloadBytes": 1280, "rounds": 3,
            "binarySha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
            "fixtureImage": IMAGE,
            "limits": ["Generated traffic on a local IPv6 Docker network", "No FIPS daemon, Internet NAT, browser pairing or physical-phone proof"],
        }
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(receipt, indent=2) + "\n")
    finally:
        for child in children:
            if child.stdin:
                child.stdin.close()
        for child in children:
            try:
                child.wait(timeout=5)
            except subprocess.TimeoutExpired:
                child.terminate()
                try:
                    child.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    child.kill()
                    child.wait(timeout=2)
            child.stdout.close()
        if created:
            for name in names:
                subprocess.run(docker + ["rm", "-f", name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            subprocess.run(docker + ["network", "rm", network], check=True, stdout=subprocess.DEVNULL)
        for log in logs:
            log.close()


if __name__ == "__main__":
    main()
