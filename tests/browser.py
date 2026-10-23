#!/usr/bin/env python3
"""Run Chromium against the standalone server, using only generated media."""
import argparse
import base64
from functools import partial
import hmac
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import subprocess
import threading
import time
from interop import Fixture


class Page(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200); self.send_header("Content-Type", "text/html"); self.end_headers()
        self.wfile.write(b"<!doctype html><title>Generated TURN interop</title>")
    def log_message(self, *args): pass


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", type=Path, default=Path("target/release/spry-turn"))
    parser.add_argument("--tls", action="store_true")
    args = parser.parse_args()
    fixture = Fixture(args.binary.resolve(), tls=args.tls)
    http = ThreadingHTTPServer(("127.0.0.1", 0), Page)
    thread = threading.Thread(target=http.serve_forever, daemon=True); thread.start()
    try:
        username = f"{int(time.time()) + 3600}:browser"
        credential = base64.b64encode(hmac.digest(fixture.secret.encode(), username.encode(), "sha1")).decode()
        urls = [f"turn:127.0.0.1:{fixture.port}?transport=udp", f"turn:127.0.0.1:{fixture.port}?transport=tcp"]
        if args.tls: urls += [f"turns:127.0.0.1:{fixture.tls_port}?transport=tcp"]
        config = [{"urls": url, "username": username, "credential": credential} for url in urls]
        env = {**os.environ, "SPRY_BROWSER_ICE": json.dumps(config), "SPRY_BROWSER_ORIGIN": f"http://127.0.0.1:{http.server_port}"}
        subprocess.run(["node", str(Path(__file__).with_suffix('.mjs'))], env=env, check=True, timeout=90)
    finally:
        fixture.close(); http.shutdown(); thread.join(timeout=3); http.server_close()


if __name__ == "__main__": main()
