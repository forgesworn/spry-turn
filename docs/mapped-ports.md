# Explicit TURN allocation port mappings

This native development increment lets an independent operator describe exact
local/public UDP port pairs for a **TURN media relay**. It does not obtain NAT
mappings, renew VPN leases, publish a Nostr announcement or prove reachability.
Audio/video packets never become Nostr events in this design.

## Configuration

Repeat `--relay-port-map LOCAL:PUBLIC` instead of `--relay-ports FIRST:LAST`:

```sh
spry-turn serve --listen 127.0.0.1:3478 --relay-ip 127.0.0.1 \
  --public-ip 192.0.2.10 \
  --relay-port-map 41000:51000 --relay-port-map 41002:51033
```

Set the operator-generated `SPRY_TURN_SECRET` as described in
[Getting started](getting-started.md). The address above is a documentation
address, and the bind is loopback: this illustrates parsing and local behaviour,
not a usable Internet deployment. Never publish test endpoints in adverts.

For Rust hosts, set `Config.relay_port_mappings` to
`Some(Vec<RelayPortMapping>)`, with `local_port` and `advertised_port` fields.
The server accepts 1–1024 unique nonzero local/public pairs. Range and explicit
mapping modes are mutually exclusive. Mapped mode rejects the local peer bridge
and a local UDP listener collision. Public and local IP families must match.

Translated port pairs require an explicit advertised IP different from the local
bind IP. Otherwise a claimed public endpoint could accidentally authorise an
unowned local service. Identity pairs such as `41000:41000` can use the same IP
and provide a bounded noncontiguous local port set. The loopback peer opt-in
remains necessary for loopback traffic, with exact live endpoint checks even
when enabled.

The allocator rotates through listed local ports only, skips occupied ports and
returns authenticated TURN error 508 on exhaustion. It never binds a port in a
gap, expands to a surrounding range or falls back to an ephemeral allocation.
Effective capacity is limited by both usable mapped entries and allocation caps.
The existing range and OS-ephemeral modes remain available without a map.

## Endpoint ownership

Each allocation stores separate bound and advertised endpoints. Allocation
responses, including retransmissions, return the advertised IP/public port.
Socket ownership, release/reuse and `allocated_relay_ports()` refer to local
bound ports. Own-address permission/channel/forwarding checks accept only exact
live local or advertised endpoint pairs; crossing an IP with the other endpoint's
port does not authorise an unrelated host service. Released ports lose that
authority, including when an earlier permission/channel still exists.

The mapping is immutable for a server run. A later supervising host must stop
the native process and discard its allocations when mappings change or expire.
This native option does not provide that lease guard. It also does not configure
the TURN client listener's public address/port: a supervising host must advertise
that separately from UDP allocation endpoints.

## Parent-lifetime supervision

An explicitly supervising host can pass `--exit-on-stdin-close` and hold the
child's stdin pipe open. EOF ends the whole native process successfully, even
while forwarding; a stdin read error exits unsuccessfully. The OS closes relay
and listener sockets. This opt-in process exit does not run Rust destructors.
The flag is refused for `credential` and when repeated. Ordinary standalone
serving keeps its existing lifetime when stdin closes.

This guard does not implement VPN lease or desktop lifecycle policy. The host
must stop the process on mapping expiry, route loss and its own lifecycle
transitions. Parent-crash socket-release fixtures are separate from physical
sleep/wake and installed application acceptance.

## Evidence and limits

Native unit and independent Python socket tests cover validation, capacity,
translated/noncontiguous allocation responses, actual local UDP source ports,
occupied entries, gap exclusion, authenticated exhaustion, retransmission,
release/reuse, crossed endpoint denial and stale forwarding denial after a host
service takes a released local port. UDP/TCP/TLS client transports are exercised.
Default connected and portable builds have separate interop checks. Version
0.3.0 includes these native options; its macOS ARM64 executable is separate
from desktop application packaging and installed-app acceptance.

No live Proton mapping or external audio/video call is established by those
fixtures. Current Proton preflight observed a refused NAT-PMP address query,
before any mapping request. The diagnostic classifies connection refusal,
source disappearance and missing routes without exposing raw endpoint errors.
No VPN setting or owner Archipelago node was changed.

Actual forwarding must be proved in both directions through each advertised
endpoint from an independent network. Same-server NAT hairpin behaviour,
physical sleep/wake, lease loss, reconnect, sustained media and performance
remain separate acceptance gates. No destination rewrite shortcut is provided.
The current public Nostr advert format and private ULA access profile also need
explicit compatible adapters before describing a dynamic desktop endpoint.

See [Goals and acceptance](../GOALS.md), [Operations](operations.md) and
[Public mode](public-mode.md) for the surrounding operator/client boundaries.
