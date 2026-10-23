# Coturn compatibility and migration

spry-turn implements a focused subset of STUN/TURN. It has no coturn
configuration-file parser and is not a universal drop-in replacement.
The goal is a small forwarding core with measured resource costs.

## Feature map

| Coturn deployment need | spry-turn 0.2.0 |
|---|---|
| STUN Binding | Implemented |
| TURN UDP relay allocations | Implemented |
| UDP clients | Implemented and socket/browser tested |
| TCP clients | Implemented and socket/browser tested |
| TLS clients | Optional `tls` feature; socket/browser tested with generated certificates |
| Expiring shared-secret TURN REST credentials | Implemented; operator-run credential command |
| Allocate, Refresh and explicit deallocation | Implemented |
| IP permissions, ChannelBind and ChannelData | Implemented |
| Send and Data indications | Implemented |
| IPv4 or IPv6 relay sockets | One configured family per instance; IPv6 field acceptance remains open |
| Allocation, per-user, connection and bandwidth limits | Implemented; names and semantics differ from coturn |
| NAT-advertised relay IP | `--public-ip`; actual NAT mapping is operator responsibility |
| Static long-term username/password database | Not implemented |
| Fixed UDP relay-port range | `--relay-ports FIRST:LAST`; exhaustion fails with 508, no ephemeral fallback |
| Dual allocations, EVEN-PORT and reservation tokens | Not implemented |
| RFC 8489 SHA-256 authentication | Not implemented |
| TCP relay allocations (RFC 6062) | Not implemented |
| DTLS client transport | Not implemented |
| OAuth, database backends, clustering, HTTP/telnet administration | Not implemented |
| Certificate renewal or reload | Not implemented |

Unknown comprehension-required attributes receive a 420 response. See
[GOALS.md](../GOALS.md) for qualification and remaining extensions.

## Configuration concepts

These are conceptual mappings, not a compatible configuration syntax:

| Coturn concept | spry-turn equivalent |
|---|---|
| `listening-ip` and `listening-port` | `--listen IP:PORT` |
| `relay-ip` | `--relay-ip IP` |
| `min-port` / `max-port` | Inclusive `--relay-ports FIRST:LAST`; no coturn configuration-file parsing |
| `external-ip` | `--public-ip IP`; no automatic mapping discovery |
| `realm` | `--realm NAME` |
| `use-auth-secret` / `static-auth-secret` | Required `SPRY_TURN_SECRET` environment variable |
| `total-quota` | `--max-allocations COUNT` |
| `user-quota` | `--max-per-user COUNT` |
| `max-bps` | `--bytes-per-second COUNT`; assess aggregate accounting and burst behaviour separately |
| TLS listener/certificate/key | `--tls-listen`, `--tls-cert`, `--tls-key` with a TLS-enabled build |

For shared-secret clients, retain the expiry-prefixed username format and
HMAC-generated password. Do not reuse application identity or room IDs as
transport labels. The realm and nonce are server-owned authentication
inputs; coturn's live sessions and nonces are not transferred.

## Assess a deployment before switching

1. List the exact transports, authentication mode, relay address family,
   firewall port range and extensions your current clients require.
2. Compare that list with the feature map. A deployment needing a missing
   feature should continue using its current server.
3. Run an independent instance and configure an explicit test client with
   separate credentials. Do not redirect active calls during evaluation.
4. Test both endpoints, forced relay, actual decoded media/data, credential
   renewal, UDP blocking, long calls, reconnects and trusted TLS certificates.
5. Size file descriptors for the additional connected-UDP socket and test
   exhaustion and peer restrictions on the intended host/network.
6. Retain the existing ICE configuration as a rollback path. Switching a
   server address does not transfer existing allocations or guarantee ICE
   restart behaviour in an application.

## Measured performance

The native ARM64 M4 Max UDP loopback matrix recorded 17–22% higher packet
throughput than the tested coturn 4.18.0 configuration. CPU and process RSS
were lower; the optimisation also used more UDP sockets. These results
apply to the recorded workload and configuration, not all coturn uses.
See [benchmarks](benchmarks.md) for latency, methodology, architecture
checks, descriptor counts, raw evidence and explicitly superseded runs.
