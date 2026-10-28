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

Client listener reachability alone is insufficient. `--relay-ports FIRST:LAST`
selects an inclusive UDP peer-relay range, for example `49160:49191`. Both
ports must be nonzero and the first must not exceed the last. With this
option, allocations bind only within that range. Occupied host ports are
skipped; exhaustion returns an authenticated TURN 508 response and never
falls back to an ephemeral port. Released ports can be allocated again.
The range is not reserved at startup. Allow headroom for occupied ports,
and keep other services out of the selected range. Narrow ranges limit
available allocations even when `--max-allocations` is higher.

Without the option, peer sockets retain OS-assigned ephemeral ports for
backwards compatibility. A public package must choose a bounded range
explicitly. These bounds apply to UDP peer-relay allocations, separately
from the UDP/TCP client listener, optional TLS listener and optimised
client-facing sockets. A single-port range is supported; it does not
implement EVEN-PORT or reservation tokens.

## Public endpoint deployment plan

Public operation is still unqualified. The deploying operator owns each
step below; installing software must not open or publish a service silently.

| Item | Operator configuration and readback |
|---|---|
| Client listeners | Allow inbound UDP/TCP only on the chosen `--listen` port and TCP on the chosen TLS port; use concrete bind addresses or a deliberate wildcard listener with concrete `--relay-ip` |
| Relay sockets | Choose `--relay-ports FIRST:LAST`; allow inbound peer UDP on that range at the host and provider firewall, with required outbound UDP and return traffic |
| NAT | If used, configure one-to-one address translation and preserve relay ports; `--public-ip` changes the advertised address only |
| Certificate | Supply a currently valid chain trusted by the intended clients, with the DNS name used in their `turns:` URI covered by the certificate; keep its private key on the operator node |
| Renewal | Arrange issuance, renewal and an operator-controlled restart; files are read at startup and active allocations are lost on restart |
| Readiness | Check authenticated Allocate, permitted bidirectional traffic and trusted TLS from an independent network, including a client with UDP blocked; a listening TCP socket is insufficient |
| Retention | Read back process-manager, container, host, crash-dump and hosting-provider logging; lack of a payload/access-log writer in Spry does not disable these |

TURN over TCP/TLS still uses UDP between relay and peer. Opening only a TLS
port is insufficient. Restrict unrelated inbound services and preserve the
default private-peer restrictions. This is a plan, not an applied firewall,
certificate-renewal implementation or public-network acceptance result.
Port bounds are exposure/resource controls; they do not settle who provides
an underlying communications service or establish a legal exemption.

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

The `spry-node` standard profile starts the relay with 32 allocations, 8 per
credential, 32 connections and 1000000 bytes per second. An operator can lower
the first three with `SPRY_MAX_ALLOCATIONS`, `SPRY_MAX_ALLOCATIONS_PER_USER` and
`SPRY_MAX_TCP_CONNECTIONS` (decimal integers from 1 to those values; the
per-credential cap may not exceed the total), and set the rate with
`SPRY_BYTES_PER_SECOND`. Invalid values refuse startup. The private-node
profile does not read these settings. See
[public mode](public-mode.md#separate-standard-profiles-on-one-host).

The server additionally bounds peer entries, stream queues and control
request rate in code. It has no per-room or application membership policy.
The allocation limit does not reserve memory or raise the process's file
descriptor limit. Authentication and stream setup also consume resources.

TCP/TLS input is parsed between reads: a burst of valid frames can exceed
the 128 KiB input limit in total without requiring a larger queue. Each
stream gets at most 64 frames, 16 read attempts and 128 KiB of read work per
poll turn; TLS counts both encrypted input and decoded plaintext. Unfinished
work resumes on the next poll without waiting for a new readiness edge.
The 64 KiB frame limit and 128 KiB output queue limit still apply. These
bounds prevent one busy stream from monopolising stream dispatch; they are
not a bandwidth or end-to-end latency guarantee.

Relayed UDP payloads reserve 1 KiB within the stream output cap for ordinary
control replies. If a complete ChannelData frame or Data indication cannot
fit, the new datagram is dropped and counted without closing the allocation
or altering queued frames. Forwarded counters exclude those dropped bytes.
Control traffic that exceeds the full output cap still closes the stream.

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
