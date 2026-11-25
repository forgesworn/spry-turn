"""Temporary probe: how often does a loopback port chosen for one protocol
refuse the other on this runner? Not for merge."""
import collections
import socket


def attempt(first, second):
    a = socket.socket(socket.AF_INET, first)
    try:
        a.bind(("127.0.0.1", 0))
        port = a.getsockname()[1]
        b = socket.socket(socket.AF_INET, second)
        try:
            b.bind(("127.0.0.1", port))
            return port, None
        except OSError as error:
            return port, getattr(error, "winerror", None) or error.errno
        finally:
            b.close()
    except OSError as error:
        return 0, ("first", getattr(error, "winerror", None) or error.errno)
    finally:
        a.close()


for name, first, second in (
    ("udp-then-tcp", socket.SOCK_DGRAM, socket.SOCK_STREAM),
    ("tcp-then-udp", socket.SOCK_STREAM, socket.SOCK_DGRAM),
):
    ports, failures = [], []
    for _ in range(400):
        port, error = attempt(first, second)
        ports.append(port)
        if error is not None:
            failures.append((port, error))
    steps = collections.Counter(b - a for a, b in zip(ports, ports[1:]))
    print(name, "attempts", len(ports), "refused", len(failures))
    print("  port range", min(ports), max(ports), "distinct", len(set(ports)))
    print("  commonest steps", steps.most_common(4))
    print("  errors", collections.Counter(e for _, e in failures).most_common())
    print("  refused ports", sorted({p for p, _ in failures})[:40])
    run = longest = 0
    refused = {port for port, _ in failures}
    for port in ports:
        run = run + 1 if port in refused else 0
        longest = max(longest, run)
    print("  longest run of refusals", longest)
