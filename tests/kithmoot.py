#!/usr/bin/env python3
"""Run the actual KithMoot web app against a local, disposable TURN operator.

Requires an authorised KithMoot checkout and its existing Node dependencies.
No KithMoot source, credentials, endpoints or room links enter the receipt.
"""
import argparse
import base64
from functools import partial
import hashlib
import hmac
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import tempfile
import threading
import time

from interop import Fixture


class App(SimpleHTTPRequestHandler):
    def __init__(self, *args, directory, **kwargs):
        super().__init__(*args, directory=str(directory), **kwargs)

    def do_GET(self):
        if self.path.split("?", 1)[0] == "/turn":
            self.server.credential_requests += 1
            self.send_error(410, "This operator fixture has no credential issuer")
            return
        if self.path == "/j" or self.path.startswith("/j/"):
            self.path = self.path[2:]
            return super().do_GET()
        self.send_error(404)

    def log_message(self, *args):
        pass


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def tree_digest(root):
    values = [(str(path.relative_to(root)), digest(path))
              for path in root.rglob("*") if path.is_file() and not path.is_symlink()]
    return {"file_count": len(values), "sha256": hashlib.sha256(
        json.dumps(sorted(values), separators=(",", ":")).encode()).hexdigest()}


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def stop(process):
    if process and process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=3)


def browser_run(env):
    # Kill the browser's entire task-owned process group on an outer timeout.
    process = subprocess.Popen(["node", str(Path(__file__).with_suffix(".mjs"))], env=env,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                               start_new_session=True)
    try:
        out, error = process.communicate(timeout=180)
        if process.returncode:
            raise RuntimeError("Browser acceptance failed: " + error[-1200:])
        return json.loads(out)
    finally:
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        try:
            process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=3)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kithmoot", type=Path, required=True, help="Authorised source checkout with Node dependencies")
    parser.add_argument("--binary", type=Path, default=Path("target/release/spry-turn"))
    parser.add_argument("--app-dist", type=Path, help="Existing production build; otherwise build into temporary scratch")
    parser.add_argument("--transports", nargs="+", choices=("udp", "tcp", "tls"), default=["udp", "tcp", "tls"])
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    checkout, binary = args.kithmoot.resolve(), args.binary.resolve()
    if not (checkout / "test/ws-relay.mjs").is_file() or not (checkout / "app/src/call-relay.ts").is_file() or not binary.is_file():
        parser.error("KithMoot must have device call-relay Settings and its local test relay; the server executable must exist")
    source_commit = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=checkout, text=True).strip()
    relevant = ["package.json", "package-lock.json", "app/index.html", "app/vite.config.ts",
                "app/src/main.ts", "app/src/call-relay.ts", "app/src/ice-resolve.ts", "app/src/relay-only.ts", "src/ice-defaults.ts"]
    source_checksums = [{"path": path, "sha256": digest(checkout / path)} for path in relevant]
    server_version = subprocess.check_output([str(binary), "--version"], text=True, timeout=3).strip()
    receipt = {"schema": 1, "scope": "actual-kithmoot-web-local-operator", "passed": False,
               "kithmoot_commit": source_commit, "source_checksums": source_checksums,
               "server_version": server_version, "server_binary_sha256": digest(binary), "results": [],
               "limits": ["Same-host loopback with generated media and a disposable Nostr fixture",
                          "TLS test certificate bypass; no public trust, NAT or blocked-UDP qualification",
                          "Owner-selected short-lived credentials entered through actual Connections Settings",
                          "No Android build or physical GrapheneOS acceptance"]}
    relay = None
    try:
        with tempfile.TemporaryDirectory(prefix="spry-kithmoot-") as scratch:
            root = Path(scratch)
            app_dist = args.app_dist.resolve() if args.app_dist else root / "app"
            if not args.app_dist:
                with (root / "build.log").open("w") as log:
                    built = subprocess.run(["node", "node_modules/vite/bin/vite.js", "build", "--config",
                                            "app/vite.config.ts", "--outDir", str(app_dist), "--emptyOutDir"],
                                           cwd=checkout, stdout=log, stderr=subprocess.STDOUT, timeout=180)
                if built.returncode:
                    raise RuntimeError("KithMoot production build failed; no acceptance claimed")
            if not (app_dist / "index.html").is_file():
                raise RuntimeError("KithMoot production index is missing")
            receipt["app_build"] = tree_digest(app_dist)
            receipt["app_built_by_runner"] = not bool(args.app_dist)
            port = free_port()
            with (root / "relay.log").open("w") as log:
                relay = subprocess.Popen(["node", "test/ws-relay.mjs"], cwd=checkout,
                                         env={**os.environ, "RELAY_PORT": str(port), "RELAY_HOST": "127.0.0.1"},
                                         stdout=log, stderr=subprocess.STDOUT)
                deadline = time.monotonic() + 10
                while True:
                    try:
                        with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                            break
                    except OSError:
                        if relay.poll() is not None or time.monotonic() > deadline:
                            raise RuntimeError("Isolated KithMoot signalling fixture failed to start")
                        time.sleep(0.05)
                for transport in dict.fromkeys(args.transports):
                    fixture = Fixture(binary, tls=transport == "tls")
                    http, thread = None, None
                    try:
                        username = f"{int(time.time()) + 1800}:generated-app-acceptance"
                        credential = base64.b64encode(hmac.digest(fixture.secret.encode(), username.encode(), "sha1")).decode()
                        url = (f"turns:127.0.0.1:{fixture.tls_port}?transport=tcp" if transport == "tls"
                               else f"turn:127.0.0.1:{fixture.port}?transport={transport}")
                        handler = partial(App, directory=app_dist)
                        http = ThreadingHTTPServer(("127.0.0.1", 0), handler)
                        http.credential_requests = 0
                        thread = threading.Thread(target=http.serve_forever, daemon=True)
                        thread.start()
                        env = {**os.environ, "SPRY_KITHMOOT_ORIGIN": f"http://127.0.0.1:{http.server_port}/j/",
                               "SPRY_KITHMOOT_RELAY": f"ws://127.0.0.1:{port}", "SPRY_KITHMOOT_TRANSPORT": transport,
                               "SPRY_KITHMOOT_ICE": json.dumps({"urls": [url], "username": username, "credential": credential})}
                        # Browser errors may contain room links: keep them out of receipts.
                        result = browser_run(env)
                        if http.credential_requests != 0:
                            raise RuntimeError("The actual app unexpectedly requested a credential service")
                        result["credential_requests"] = http.credential_requests
                        receipt["results"].append(result)
                    finally:
                        fixture.close()
                        if http:
                            http.shutdown()
                            if thread:
                                thread.join(timeout=3)
                            http.server_close()
                stop(relay)
                relay = None
        receipt["passed"] = True
    finally:
        stop(relay)
        receipt["processes_stopped"] = True
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(receipt, indent=2) + "\n")
    print(json.dumps({"passed": True, "transports": [r["transport"] for r in receipt["results"]]}))


if __name__ == "__main__":
    main()
