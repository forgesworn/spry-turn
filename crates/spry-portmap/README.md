# spry-portmap

An MIT Rust library that asks the home router to forward ports to a
self-hosted Spry relay, written in-house for this repository. It speaks
PCP (RFC 6887, MAP opcode), NAT-PMP (RFC 6886) and UPnP IGD (SSDP, device
description, WANIPConnection v1 and v2, WANPPPConnection v1), in that order,
and keeps to the first protocol that grants a mapping. It depends only on
the standard library, `getrandom` for PCP nonces and `socket2` to pick the
interface for SSDP multicast; both were already in the workspace.

The relay process owns the mappings, so leases lapse when it stops renewing
them. This crate is not wired into `spry-node` yet; that is a later step.

## What it does

- Finds the IPv4 default gateway from the host's route table: Linux
  `/proc/net/route`, macOS and BSD `route -n get default`, Windows
  `route print -4 0.0.0.0`. Android should pass the gateway from
  `LinkProperties` in `Options::gateway`. It never guesses `.1`.
- Requests, renews (at half the granted lifetime) and removes mappings, and
  reports the external address. Translated external ports and shortened
  leases are accepted and reported as granted.
- Detects a gateway restart from the PCP or NAT-PMP epoch (RFC 6887
  section 8.5) and reports it on renewal so every mapping can be requested
  again.
- Classifies the router's reported external address: public, carrier-grade
  NAT (100.64.0.0/10), private (a second router) or unusable. Comparing it
  with a STUN answer is a later step.
- Records the mappings a process created (`record::Ledger`), so the next
  launch can remove what a crashed run left: PCP by its nonce, UPnP after
  `GetSpecificPortMappingEntry` shows this host's address, port and
  description tag. NAT-PMP leftovers are left to expire, as NAT-PMP cannot
  prove ownership after a restart.
- Accepts UPnP routers that grant only permanent leases (error 725) unless
  `Options::allow_permanent` is false. Such a mapping is recorded and must be
  removed on stop and again on the next launch; it can outlive a crash.

## Bounds

Everything a router sends is outside input:

- PCP and NAT-PMP talk only to the default gateway, from a connected socket,
  so replies from any other address are never read. Replies for another
  nonce, protocol or port are ignored, not obeyed. Each request has a total
  budget (2 s by default) with the RFC 6886 retransmission schedule inside
  it, and datagrams over 1100 bytes are discarded.
- UPnP uses an SSDP answer only when it comes from the gateway's address
  and its description URL and control URL name that same address. URLs must
  be `http://` with an IPv4 literal, so no name is resolved; redirects are
  never followed. The HTTP client reads at most 64 KiB for a description and
  16 KiB for a SOAP reply, within the request budget.
- The XML reader keeps only element names and text, refuses any document
  type declaration and every entity beyond the five predefined ones and
  numeric references, and limits depth (24), elements (2048) and text per
  element (4096 bytes).
- The record file is at most 64 KiB and 256 entries, parsed strictly and
  written atomically, private to the user on Unix.

## Use

```rust
use spry_portmap::{Error, Options, PortMapper, Protocol, Request};
use std::time::Duration;

fn open_listener() -> Result<(), Error> {
    let mut mapper = PortMapper::new(Options::default())?;
    let listener = mapper.map(Request::new(Protocol::Udp, 3478, Duration::from_secs(7200)))?;
    println!("{} via {}", listener.external, listener.method);
    // Later: mapper.renew(&listener) at listener.renew_at(); on stop:
    mapper.remove(&listener)
}
```

The API is blocking; an async host runs it on a blocking thread.

## Diagnostic

`spry-node portmap check [--port PORT] [--protocol udp|tcp|both]
[--gateway IPV4]` maps a test port (a random high port by default) for
120 seconds, prints what each protocol answered, the external address and
the granted ports, then removes the mapping. It starts no relay and nothing
listens on the port. It does not test reachability from outside.

## Tests

`cargo test -p spry-portmap` runs codec, parser and lifecycle tests against
in-house fake PCP, NAT-PMP and UPnP IGD gateways on loopback (the `testing`
feature, in `src/fake.rs`). No third-party router software is used, in tests
or in CI. Behaviour against real routers has not been proven by these tests.
