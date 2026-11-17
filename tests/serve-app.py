#!/usr/bin/env python3
"""Serve an existing KithMoot production build without a JavaScript toolchain."""
from functools import partial
from http.server import ThreadingHTTPServer
from pathlib import Path
import argparse

from kithmoot import App


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dist", type=Path, required=True)
    parser.add_argument("--port", type=int, default=4173)
    args = parser.parse_args()
    server = ThreadingHTTPServer(("127.0.0.1", args.port), partial(App, directory=args.dist))
    server.credential_requests = 0
    server.serve_forever()


if __name__ == "__main__":
    main()
