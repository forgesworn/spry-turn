#!/usr/bin/env python3
"""Bounded, genuine libFuzzer coverage run; generated corpus stays ignored."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import time

from interop import attr, packet, COOKIE, TRANSPORT, USERNAME, PEER


def positive(value):
    result = int(value)
    if not 1 <= result <= 86_400:
        raise argparse.ArgumentTypeError("must be between 1 and 86400")
    return result


def wire_seeds():
    values = [b"", b"\0", b"\x80\0\0\0", b"\x40\0\0\0",
              b"\x4f\xff\0\x01a\0\0\0", b"\0" * 20]
    for method in (1, 3, 4, 6, 8, 9):
        for fields in ([], [(TRANSPORT, b"\x11\0\0\0")],
                       [(USERNAME, b"1000:generated"), (PEER, b"\0\x01\0\0" + b"\0" * 4)]):
            values.append(packet(method, fields, tid=bytes(12)))
            values.append(packet(method, fields, key=b"generated fuzz key", tid=bytes(12)))
    # A valid envelope without FINGERPRINT permits structural attribute mutation.
    for size in (0, 1, 3, 4, 20, 256, 4096, 65_400):
        body = attr(USERNAME, bytes(size))
        values.append(b"\0\x01" + len(body).to_bytes(2, "big") + COOKIE.to_bytes(4, "big") + bytes(12) + body)
    return values


def portmap_seeds():
    # Synthetic gateway replies on documentation addresses; no real router.
    soap = (b'<?xml version="1.0"?><s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/">'
            b"<s:Body><u:GetExternalIPAddressResponse><NewExternalIPAddress>192.0.2.7"
            b"</NewExternalIPAddress></u:GetExternalIPAddressResponse></s:Body></s:Envelope>")
    fault = (b"<s:Envelope><s:Body><s:Fault><detail><UPnPError><errorCode>718</errorCode>"
             b"</UPnPError></detail></s:Fault></s:Body></s:Envelope>")
    description = (b"<root><URLBase>http://192.0.2.1:5000/</URLBase><device><serviceList><service>"
                   b"<serviceType>urn:schemas-upnp-org:service:WANIPConnection:1</serviceType>"
                   b"<controlURL>/ctl/IPConn</controlURL></service></serviceList></device></root>")
    return [
        b"", b"\0", b"<a/>", b"<a><b>text</b></a>", soap, fault, description,
        b"HTTP/1.1 200 OK\r\nLOCATION: http://192.0.2.1:5000/root.xml\r\n"
        b"ST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n\r\n",
        b"http://192.0.2.1:5000/root.xml", b"/ctl/IPConn", b"../x?y",
        # NAT-PMP external address and mapping replies, then an error.
        bytes([0, 128, 0, 0]) + bytes(4) + bytes([192, 0, 2, 7]),
        bytes([0, 129, 0, 0]) + bytes(4) + (3478).to_bytes(2, "big") * 2 + (3600).to_bytes(4, "big"),
        bytes([0, 129, 0, 3]) + bytes(12),
        # A PCP MAP reply header with a zeroed body.
        bytes([2, 0x81, 0, 0]) + (3600).to_bytes(4, "big") + bytes(16) + bytes(36),
        b"Iface\tDestination\tGateway\tFlags\neth0\t00000000\t010200C0\t0003\n",
        b"   route to: default\n    gateway: 192.0.2.1\n  interface: en0\n",
        b"Active Routes:\n          0.0.0.0          0.0.0.0        192.0.2.1      192.0.2.10     25\n",
    ]


def link_seeds():
    # The target signs these with its own generated key at a fixed time:
    # `kind<TAB>name value<TAB>...<LF>content`. Synthetic names only.
    now = 1_800_000_000
    offer = json.dumps({"credentials": "https://relay.example/v1/public/credentials",
                        "urls": ["turn:relay.example:3478?transport=udp",
                                 "turns:relay.example:5349?transport=tcp"],
                        "note": "Synthetic operator note"})
    advert = f"advert\td spry-turn\tv 1\tauth public\texpiration {now + 3600}\tg GB"
    card = f"card\texpiration {now + 600}\n"
    unsigned = {"id": "0" * 64, "pubkey": "1" * 64, "created_at": now, "kind": 31478,
                "tags": [["d", "spry-turn"]], "content": "{}", "sig": "2" * 128}
    return [value.encode() for value in (
        "{}", "[]", json.dumps(unsigned),
        f"{advert}\tstatus open\n{offer}",
        f"{advert}\tstatus withdrawn\n{{}}",
        card + json.dumps({"v": 1, "profile": "spry-peer-v1", "address": "[fd00::1]:3745"}),
        card + json.dumps({"v": 1, "profile": "spry-standard-v1"}),
        "spry://" + "1" * 64 + "?relay=wss%3A%2F%2Frelay.example",
        "Ag" + "A" * 130,
    )]


# Each target binds the sources whose hashes its receipt records.
TARGETS = {
    "wire": {
        "seeds": wire_seeds, "max_len": 65_536,
        "sources": ("src/lib.rs", "src/limits.rs", "src/wire.rs", "src/auth.rs", "Cargo.toml"),
        "limits": "Parser/auth/codec in process; no network/runtime fuzzing or independent security review.",
    },
    "portmap": {
        "seeds": portmap_seeds, "max_len": 65_536,
        "sources": tuple(f"crates/spry-portmap/src/{name}.rs" for name in
                         ("lib", "xml", "http", "pcp", "natpmp", "upnp", "record", "route"))
        + ("crates/spry-portmap/Cargo.toml",),
        "limits": "Gateway reply, record and route parsers in process; no sockets, real routers or "
                  "independent security review.",
    },
    "link": {
        "seeds": link_seeds, "max_len": 24_576,
        "sources": tuple(f"crates/spry-link/src/{name}.rs" for name in
                         ("lib", "identity", "advert", "control", "nip44", "peer", "standard"))
        + ("crates/spry-link/Cargo.toml",),
        "limits": "Event, advert, card, pairing link and NIP-44 payload parsing in process with a "
                  "generated key; no relays, sessions or independent security review.",
    },
}


def seed_corpus(directory, values):
    directory.mkdir(parents=True, exist_ok=True)
    for value in values:
        if value:
            (directory / hashlib.sha256(value).hexdigest()).write_bytes(value)


def corpus_identity(directory):
    contents = sorted(hashlib.sha256(path.read_bytes()).hexdigest()
                      for path in directory.iterdir() if path.is_file())
    return {"files": len(contents),
            "sha256": hashlib.sha256("\n".join(contents).encode()).hexdigest()}


def stop_group(process):
    # cargo-fuzz starts the instrumented executable as a child. Reap cargo and
    # stop the whole task-owned group even if cargo exits before its child.
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    try:
        process.wait(timeout=3)
    except subprocess.TimeoutExpired:
        pass
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    process.wait(timeout=3)


def run_bounded(command, root, stream, timeout, quiet=False):
    process = subprocess.Popen(command, cwd=root,
                               stdout=subprocess.DEVNULL if quiet else stream,
                               stderr=stream, start_new_session=True)
    try:
        return process.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        stop_group(process)
        return 124
    except BaseException:
        stop_group(process)
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--seconds", type=positive, default=180)
    parser.add_argument("--seed", type=positive, default=7411)
    parser.add_argument("--toolchain", default="nightly")
    parser.add_argument("--target", choices=sorted(TARGETS), default="wire")
    # The fuzzer process grows with its corpus and the sanitiser's quarantine.
    # A long campaign can reach the default without any input being at fault.
    parser.add_argument("--rss-limit-mb", type=int, choices=range(256, 8193), default=768,
                        metavar="256..8192")
    parser.add_argument("--output", type=Path, default=Path(".local/fuzz/receipt.json"))
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    scratch = root / ".local/fuzz"
    target = TARGETS[args.target]
    corpus, artifacts = scratch / "corpus" / args.target, scratch / "artifacts" / args.target
    seed_corpus(corpus, target["seeds"]())
    initial_corpus = corpus_identity(corpus)
    source_paths = tuple(map(Path, target["sources"] + (
        f"fuzz/fuzz_targets/{args.target}.rs", "fuzz/Cargo.lock",
        "fuzz/Cargo.toml", "tests/fuzz.py", "tests/interop.py")))
    source_hashes = {str(path): hashlib.sha256((root / path).read_bytes()).hexdigest()
                     for path in source_paths}
    artifacts.mkdir(parents=True, exist_ok=True)
    before = {p.name for p in artifacts.iterdir()}
    log = scratch / f"{args.target}.log"
    command = ["cargo", f"+{args.toolchain}", "fuzz", "run", "--target-dir", str(root / "target"),
               "--sanitizer", "address", args.target, str(corpus), "--",
               f"-max_total_time={args.seconds}", f"-seed={args.seed}", f"-max_len={target['max_len']}",
               "-timeout=5", f"-rss_limit_mb={args.rss_limit_mb}", "-print_final_stats=1",
               f"-artifact_prefix={artifacts}{os.sep}"]
    started = time.monotonic()
    with log.open("w") as stream:
        try:
            # Reject a stale lock before cargo-fuzz builds the isolated project.
            status = run_bounded(["cargo", f"+{args.toolchain}", "metadata", "--locked",
                                  "--format-version", "1", "--manifest-path", "fuzz/Cargo.toml"],
                                 root, stream, timeout=30, quiet=True)
            if status == 0:
                status = run_bounded(command, root, stream, timeout=args.seconds + 600)
        except KeyboardInterrupt:
            status = 130
    content = log.read_text(errors="replace")
    done = re.findall(r"#(\d+)\s+DONE\s+cov:\s*(\d+)\s+ft:\s*(\d+).*?exec/s:\s*(\d+)", content)
    executions = re.findall(r"stat::number_of_executed_units:\s*(\d+)", content)
    peak_rss = re.findall(r"stat::peak_rss_mb:\s*(\d+)", content)
    new_artifacts = sorted({p.name for p in artifacts.iterdir()} - before)
    source_unchanged = all(hashlib.sha256((root / path).read_bytes()).hexdigest() == source_hashes[str(path)]
                           for path in source_paths)
    receipt = {
        "schema": 1, "engine": "libFuzzer", "coverage_guided": True,
        "target": f"fuzz/fuzz_targets/{args.target}.rs", "sanitizer": "address",
        "toolchain": args.toolchain, "seed": args.seed, "requested_seconds": args.seconds,
        "rss_limit_mb": args.rss_limit_mb,
        "elapsed_seconds_including_build": round(time.monotonic() - started, 3),
        "returncode": status, "completed": status == 0 and bool(done) and not new_artifacts and source_unchanged,
        "executions": int(executions[-1]) if executions else None,
        "coverage_edges": int(done[-1][1]) if done else None,
        "coverage_features": int(done[-1][2]) if done else None,
        "final_executions_per_second": int(done[-1][3]) if done else None,
        "corpus_files": sum(p.is_file() for p in corpus.iterdir()),
        "initial_corpus": initial_corpus, "final_corpus": corpus_identity(corpus),
        "new_crash_artifact_count": len(new_artifacts),
        "fuzzer_peak_rss_mb": int(peak_rss[-1]) if peak_rss else None,
        "source_sha256": [{"path": path, "sha256": digest} for path, digest in source_hashes.items()],
        "source_unchanged_during_run": source_unchanged,
        "limits": target["limits"],
    }
    output = args.output if args.output.is_absolute() else root / args.output
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(receipt, indent=2) + "\n")
    print(json.dumps(receipt, indent=2))
    if not receipt["completed"]:
        print(f"Fuzzing did not complete; inspect the ignored .local/fuzz/{args.target}.log and artifacts.")
        raise SystemExit(1)


if __name__ == "__main__":
    main()
