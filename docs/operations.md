# Independent operator guide

The supported first step is a local standalone server. Public deployment,
sustained hostile-network use and production replacement of coturn remain
unqualified. This guide describes current controls and limits so an owner
can evaluate an instance deliberately.

## Addresses and reachability

The default listener is loopback only. `--listen IP:PORT` chooses the UDP
and TCP listening address. Without `--relay-ip`, the CLI uses the listener
IP for peer sockets. A wildcard listener such as `0.0.0.0:3478` requires an
explicit, concrete `--relay-ip`.

`--public-ip` changes the advertised relay IP for operator-managed NAT;
it does not configure a router, discover a mapping, open firewall ports or
solve carrier-grade NAT. Its address family must match the relay family.
Use one relay family per instance; dual allocations are not implemented.

Client listener reachability alone is insufficient. UDP peer relay sockets
use OS-assigned ephemeral ports. There is currently no `--min-port` or
`--max-port` option and no bounded relay-port range. A deployment requiring
a narrowly specified firewall range must wait for that feature. Do not
copy a coturn firewall recipe and assume matching behaviour.

## Credentials

Supply `SPRY_TURN_SECRET` privately through the operator's process manager
or shell. Use an unpredictable value containing at least 32 bytes. It must
be the same value used by the credential command or trusted generator.
There is no remote credential API or static user database.

Credential usernames begin with epoch expiry seconds and an opaque label;
the password uses the coturn-compatible shared-secret HMAC scheme. The CLI
accepts a TTL of 1–86,400 seconds. Keep clocks accurate. Applications must
obtain replacement credentials before expiry and implement their own
renewal/reconnect policy; extending a username does not extend an already
issued credential. In-flight credential expiry and network recovery need
qualification in the target application.

There is no rolling dual-secret mechanism. A restart loses allocation
state, and changing the secret invalidates previously issued credentials.
Plan operator-driven rotation and client recovery; never distribute the
shared secret to calling clients.

## Resource controls

| CLI option | Default | Scope |
|---|---:|---|
| `--max-allocations` | 1024 | Total logical allocations |
| `--max-per-user` | 8 | Allocations per credential username |
| `--max-connections` | 256 | Accepted TCP/TLS connections |
| `--bytes-per-second` | 67108864 | Aggregate byte rate per allocation across both directions |

The server additionally bounds peer entries, stream queues and control
request rate in code. It has no per-room or application membership policy.
The allocation limit does not reserve memory or raise the process's file
descriptor limit. Authentication and stream setup also consume resources.

On a concrete IPv4 listener the default optimisation uses one client-facing
connected UDP socket plus one peer-facing relay socket per UDP allocation.
Budget at least those descriptors, listeners, stream connections and host
headroom. Wildcard, IPv6 and unavailable optimisation sockets use the
portable path. To select that path explicitly:

```sh
cargo build --locked --release --no-default-features --features runtime,turn
```

Process RSS omits kernel socket buffers. Use host-level measurements before
drawing total-memory or maximum-capacity conclusions. The benchmark
runner's descriptor limit applies only to its own child processes.

## Peer policy and TLS

Private, loopback, link-local and multicast peers are blocked by default.
The CLI's `--allow-loopback-peers` exists for generated local tests and
requires a loopback-only listener. It is not a public deployment option.
Do not relax peer restrictions to work around a reachability problem.

TLS requires `--features tls`, an explicit listener and operator-provided
PEM certificate/key files. Use a certificate trusted by the intended
clients. There is no automatic renewal or file reload; replacement needs
an operator-managed restart, which loses active state. Local browser tests
bypass trust for their generated certificate and do not qualify public PKI.

TLS protects client-to-relay transport. It does not turn arbitrary forwarded
payloads into end-to-end encrypted media; the endpoint protocol owns that.

## Lifecycle and observability

The CLI runs in the foreground and emits startup/errors to stderr. It has
no daemonisation, HTTP health endpoint, admin UI, per-client access log or
recording feature. An embedding host can read aggregate `Server::stats()`
and `allocation_count()`; no remote metrics exporter is included.

Use the operator's process supervision and restrictive environment/file
permissions. Stop a local instance with Ctrl-C. Restart closes existing
allocations; graceful drain and live configuration reload are not present.
See [security](../SECURITY.md), [qualification](../GOALS.md) and the
[transport position](legal/transport-position.md) for the remaining boundaries.
