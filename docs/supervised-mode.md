# Supervised standard mode

`spry-node supervised` runs Spry as the child process of a host application,
such as the KithMoot desktop app, so that a person can relay calls for their
own rooms while that app is open. It is the standard TURN profile with every
other surface removed:

- no HTTP listener, owner UI, claim code or pairing link;
- no public mode, anonymous credentials or Nostr advert;
- no private mesh or peer routes;
- room grants only, every grant sealed (`SPRY_ROOM_SEAL=required`);
- every network value supplied by the supervisor; nothing is discovered,
  looked up or guessed;
- the TURN relay runs inside the same process, which exits when the
  supervisor's stdin pipe closes.

The supervising app's signing key is trusted as the node's one pairing at
start-up. Guests reach the node only through the encrypted `spry:` control
channel (Nostr kinds 24181 and 24182) on relays the supervisor names.

Router ports are opened in one of two ways. With `--map-ports` the node asks
the router itself (PCP, NAT-PMP, then UPnP IGD), keeps the mappings alive,
follows changes and removes what it made; see
[Automatic router port opening](#automatic-router-port-opening). Without it
the supervisor supplies the public address and mapped ports. Either way this
mode does not prove reachability from outside or enforce a daily data limit,
and the supervisor decides when the network can host at all. It does cap the
relay's total bandwidth and report counts of its use; both are described
below.

The same node also runs inside a host app's own process, through the
`libspry_relay` C ABI and its JNI shim, for Android; see
[Embedding the relay](embedding.md). Release builds of `spry-node` for macOS
arm64, Windows x64 and Linux x64 and arm64, and of the Android library, are
listed there.

## Command line

```sh
SPRY_TURN_SECRET=<at least 32 bytes> spry-node supervised \
  --exit-on-stdin-close \
  --pairing-key <app public key> \
  --state-file <private state file> \
  --control-relay wss://relay.example/ \
  --bind <LAN IPv4> --public-ip <public IPv4> \
  --listen-port 41000 --public-udp-port 51000 --public-tcp-port 51001 \
  --relay-port-map 41002:51002 --relay-port-map 41003:51003
```

With `--map-ports` the router supplies the public address and every external
port, so those four options are replaced by one switch:

```sh
SPRY_TURN_SECRET=<at least 32 bytes> spry-node supervised \
  --exit-on-stdin-close --map-ports \
  --pairing-key <app public key> \
  --state-file <private state file> \
  --control-relay wss://relay.example/ \
  --bind <LAN IPv4> --listen-port 41000
```

The first argument must be `supervised`. Without it, `spry-node` runs the
existing standard or private-node profile exactly as before.

| Option | Required | Rule |
|---|---|---|
| `--exit-on-stdin-close` | Yes | The node exits when its stdin pipe reaches EOF, and unsuccessfully on a read error. A supervisor holds the pipe open for the node's life. |
| `--pairing-key` | Yes | The supervising app's x-only public key, 64 lowercase hex characters, a valid curve point |
| `--state-file` | Yes | The node's private state file (mode 0600, written atomically). No default. |
| `--control-relay` | Yes, 1 to 4 times | Distinct `wss://` relay URLs on DNS names, the same rule as private-node control relays. The design allowed up to 8; the existing `spry:` endpoint rule allows 4. |
| `--map-ports` | No | Ask the router for the listener and the allocation ports and use what it grants. Forbidden together with `--public-ip`, `--public-udp-port`, `--public-tcp-port` and `--relay-port-map`; required when none of those is given. |
| `--gateway` | No, with `--map-ports` only | The router's IPv4 address on the hosting network, for a host that already knows it (Android reads it from `LinkProperties`). Unspecified, multicast, broadcast, link-local and loopback addresses are refused. Without it the node reads the default route from the operating system. |
| `--bind` | Yes | The concrete local IPv4 address the listener and allocation ports bind to: not unspecified, loopback, link-local, multicast or broadcast |
| `--public-ip` | Yes, unless `--map-ports` | The IPv4 address given to guests: public unicast, refusing private, loopback, link-local, carrier-grade NAT, documentation, benchmarking, multicast and reserved space |
| `--listen-port` | Yes | Local TURN listener port, 1024 to 65535, shared by UDP and TCP |
| `--public-udp-port` | Yes, unless `--map-ports` | External UDP port of the listener, 1024 to 65535 |
| `--public-tcp-port` | Yes, unless `--map-ports` | External TCP port of the listener, 1024 to 65535. It may differ from the UDP port. |
| `--relay-port-map LOCAL:PUBLIC` | Yes, 1 to 64 times, unless `--map-ports` | UDP allocation port pairs, each 1024 to 65535, every local and every public port used once. No local port may be the listener port and no public port the listener's public UDP port. |
| `--max-allocations` | No | 1 to 32, default 8. With `--map-ports` it is also how many allocation ports are asked of the router, and the relay never holds more allocations than ports granted. |
| `--max-per-user` | No | 1 to 8 and at most `--max-allocations`, default 2 (or the total, if lower) |
| `--max-tcp-connections` | No | 1 to 32, default 16 |
| `--bytes-per-second` | No | Per allocation, 1 to 67108864, default 125000 |
| `--aggregate-bytes-per-second` | No | For every allocation together, 1 to 67108864, default 625000. See [the aggregate cap](#the-aggregate-bandwidth-cap). |

When `--bind` equals `--public-ip` (a host holding a public address on its
own interface), every mapping must be `PORT:PORT` and both public listener
ports must equal `--listen-port`.

The allocation map uses the relay's existing
[explicit mapping mode](mapped-ports.md): allocations rotate through the
listed local ports only, answer with the public IP and public port, and
return 508 when every mapped port is in use. Explicit mappings are fixed
for the run; a supervisor restarts the node when they change. Under
`--map-ports` the node restarts its own relay when the router changes them.

Any unknown, valueless or repeated option refuses startup. Each refusal
names the setting and never prints its value.

### Environment

| Variable | Rule |
|---|---|
| `SPRY_TURN_SECRET` | Required, at least 32 bytes. TURN credentials, grant tokens, the pairing id and the node's control identity are derived from it. |
| `SPRY_ROOM_SEAL` | Unset or `required`. `auto` and `off` refuse startup. |
| `SPRY_SOCKS_PROXY`, `SPRY_CONTROL_CA_FILE` | Optional outbound control settings, as for the private-node profile |
| `SPRY_LOCAL_TEST` | Unset or `true`; generated fixtures only. Allows a loopback bind, any non-multicast advertised address and `ws://` loopback control relays. Under `--map-ports` it also skips the route-table, VPN and external-address checks and allows `--gateway-port` and `--ssdp` (the fake gateways' ports). Never set it on a real host. |

Every other `SPRY_` variable refuses startup, so a setting meant for another
profile (`SPRY_PUBLIC`, `SPRY_HTTP_PORT`, `SPRY_PEER_BIND`, `SPRY_RELAY_IP` and
so on) cannot appear to apply. Supervisors should start the node with a
cleared environment.

## The aggregate bandwidth cap

A home uplink is small, and every allocation can ask for its own
`--bytes-per-second`. The aggregate cap limits the relay as a whole, so that
eight allocations at their default 125,000 bytes a second (1,000,000 in all)
cannot take more than the supervisor allows from the connection.

- It is always on in this mode. The default, 625,000 bytes a second (5 Mbit/s),
  is two thirds of what eight default allocations could ask for. It is a
  cautious choice, not a measured one; the supervisor may set any value from
  1 to 67108864.
  A value below `--bytes-per-second` is allowed and then rules over it.
- It counts relayed payload bytes in both directions, from every allocation,
  in one token bucket that refills continuously and holds at most one second
  of allowance. It is the same accounting as the per-allocation limit
  (payload only, no STUN, TURN or UDP/TCP framing overhead), applied after
  it. The per-allocation limit is checked first, and a packet the aggregate
  refuses gives that allocation its tokens back, so a busy neighbour cannot
  also spend someone's own allowance.
- Over the cap a packet is dropped, not queued, so the senders see loss and
  delay is not added. No allocation is reserved a share; whoever's packets
  arrive first in a second spend it.
  Nothing is closed or refused at allocation time, so the allocation caps
  above are unchanged.

There is no environment variable for it: this mode reads no tuning
variables.

## Automatic router port opening

`--map-ports` makes the node ask the router for what a guest needs to reach
it: the listener on UDP and TCP, and one UDP port for each allocation the
relay may hold. It uses the `spry-portmap` crate, so the order is PCP
(RFC 6887), then NAT-PMP (RFC 6886), then UPnP IGD, stopping at the first
that grants the listener. `spry-node portmap check` shows what a router
allows without starting a relay.

### Steps

1. **Clean up after a crash.** The node keeps a record of every mapping it
   makes in `<state file>.mappings` (private to the user, written atomically
   on every grant and renewal). Before asking for anything it removes what
   the record lists for this router: PCP by its nonce, UPnP after the router
   shows the entry is this host's with the node's tag. NAT-PMP cannot prove
   ownership after a restart, so those entries are left to expire.
   Entries for another router are forgotten, unless they never expire. A
   record that cannot be read is renamed `<record>.rejected` and a new one
   started. If a router stops answering, the rest is left for next time.
2. **Check the network.** The default route must not be a tunnel (`vpn`),
   and `--bind` must be the address that reaches the router
   (`wrong-interface`); otherwise a mapping would point at the wrong host.
   The tunnel check uses the operating system's route table, so it is
   skipped under `--gateway` (the host already chose a gateway) and under
   `SPRY_LOCAL_TEST`.
3. **Map the listener.** UDP then TCP, asking for the same external port as
   `--listen-port` and accepting another if the router translates it. If
   either fails the node stops: nothing else is useful. The router's
   reported external address must be public. Carrier-grade NAT
   (`100.64.0.0/10`), a private address (a second router) and a reserved or
   documentation address each stop the node with their own reason, and the
   mappings are given back.
4. **Map the allocation ports.** Random local ports in 49152 to 65535 that
   the node can bind, up to `--max-allocations` of them, same port first.
   The node starts with at least four (or all of them, if it asked for
   fewer) and stops the search after three refusals in a row, a silent
   router, or 40 requests in all, listener included. Fewer than the minimum
   stops the node and gives everything back.
5. **Start.** The router's grant becomes the public address, both public
   listener ports and the `--relay-port-map` pairs. The relay's
   allocation cap is lowered to the number of ports granted, and `ready`
   follows with those values, so `ready.urls` is where the supervisor reads
   the external address (for example to compare it with a STUN answer).
6. **Renew.** Each mapping is renewed at half its granted lease. The node asks
   for 7200 seconds, or 3600 on UPnP. A failed renewal is tried again after
   30 seconds, or at the end of the lease if sooner. Once a lease has ended
   the mapping is asked for afresh. A permanent UPnP lease has no end, so it
   is added again every 30 minutes, which also restores it after a router
   restart. Once the router stops answering, the rest of that round is not
   sent, so a missing router costs one timeout, not one per mapping. If the
   router reports it restarted (a PCP or NAT-PMP epoch that went back) every
   mapping is renewed at once, which puts back the ones it lost.
7. **Follow changes.** If a renewal returns another external address or
   port, the node tells the supervisor (`portmap changed`), stops
   answering credential requests for a moment, restarts its own relay on
   the same local ports with the new public values, updates the TURN URLs
   that credential answers carry, and prints `urls`. Allocations on the old
   relay end and clients renew through ICE. Grants, the pairing and the
   control channel are untouched, and the status counts carry over.
   The external address is classified again on a change, and a change to
   a private, shared or reserved address ends the node as a loss. A lost
   allocation port (its lease ended and a fresh request failed) is dropped
   and the relay restarts with the smaller map. A lost listener mapping, a
   loss of every allocation port, or a router silent until the lease ends
   ends the node with `portmap lost` and exit code 3.
8. **Stop.** On stdin EOF, SIGINT or SIGTERM the relay stops first, then each
   mapping the node made is removed, newest first, within two seconds. A
   router that stops answering ends the attempt; what is left stays in the
   record for the next launch. Only mappings this run made and recorded are
   removed, and a UPnP entry is first checked to be this host's.

### Permanent UPnP leases

A UPnP router that accepts only permanent leases is used, as the owner
decided. Each such mapping is recorded without an end time, reported
(`"permanent":true`), removed on stop, and removed again at the next launch
if the node was killed first. Until that next launch it stays open on the
router. A supervisor should tell the person that a mapping may outlive a
crash. A mapping can also outlive a crash in the moment between the router
granting it and the node saving the record.

### What the node prints

Under `--map-ports` these lines join the ones above. They carry states,
counts and fixed reason words only: never the router's address or a port.
The external address is in `ready.urls` and `urls`, where the supervisor
already receives it.

```json
{"v":1,"event":"portmap","state":"cleaned","removed":10,"remaining":0}
{"v":1,"event":"portmap","state":"mapped","method":"pcp","allocationPorts":8,"requested":8,"permanent":false}
{"v":1,"event":"ready", ...}
{"v":1,"event":"portmap","state":"changed","method":"pcp","allocationPorts":8,"requested":8,"permanent":false,"reason":"address"}
{"v":1,"event":"urls","urls":["turn:<public IP>:51000?transport=udp","turn:<public IP>:51001?transport=tcp"],"relayPortMap":[[49200,51002]]}
{"v":1,"event":"portmap","state":"lost","reason":"expired"}
{"v":1,"event":"portmap","state":"released","removed":10,"remaining":0}
```

| Line | When |
|---|---|
| `cleaned` | Before anything else, only if the record listed something. `removed` is how many mappings were taken off the router, `remaining` how many records are kept for next time. |
| `mapped` | The first grant, before the relay starts and before `ready`. `method` is `pcp`, `natpmp` or `upnp`. `allocationPorts` of `requested` were granted. `permanent` is true if any mapping has no lease end. |
| `changed` | A value the relay hands out has changed; `reason` is `address`, `port` or `ports` (an allocation port was lost). Followed by `urls` once the relay is running again. |
| `urls` | The new `urls` and `relayPortMap`, in the same shape as in `ready`. Replaces what `ready` said. |
| `failed` | Nothing is mapped and the node exits with code 3. No `ready` follows. |
| `lost` | The relay can no longer be reached and the node exits with code 3. |
| `released` | The last line, after the relay stopped: how many mappings were removed and how many records remain. It may be missing if the supervisor has already gone. |

Reasons for `failed` and `lost`: `no-gateway` (no default route), `vpn`,
`wrong-interface`, `no-answer` (the router did not reply, or has no PCP,
NAT-PMP or UPnP), `refused`, `failed` (another error), `carrier-grade-nat`,
`double-nat`, `unusable-address`, `too-few-ports`, `record` (the record could
not be saved, so the node does not keep a mapping it cannot clean up),
`expired` (a lease ended and could not be renewed).

### Exit codes

`1` is a refusal or a failure (a bad setting, a port in use, the relay
stopped, the pipe could not be read). `3` means the router could not host:
`portmap failed` or `portmap lost` came first. A supervisor should not
restart a node that exited with 3 as if it had crashed; the network needs
looking at first (a new network, a router setting, a VPN). The automatic
restart after a crash belongs to the supervisor, and the node never
restarts itself.

### Limits

- A change of external address is noticed at the next renewal, up to half a
  lease later, not when it happens. The node does not listen for the
  multicast address announcement PCP and NAT-PMP routers can send.
- The record file is separate from the state file, so a state file removed
  on its own does not forget mappings.
- The node does not compare the router's address with a STUN answer, and it
  does not prove that the mapping works from outside. The supervisor reads
  the address from `ready.urls` and runs any such comparison or remote test.
- A port the router already maps for someone else may be translated to
  another port, and is used as granted.
- Only IPv4 is mapped.
- No real router has been tried with this wiring; see below.

## Lifetime and output

After the settings are accepted the node watches stdin, binds the UDP and
TCP listener, loads its state, trusts the pairing, then starts control. If
the listener cannot be bound it exits unsuccessfully before printing
anything on stdout or writing state (under `--map-ports` the `portmap` lines
below may already have been printed, and the mappings are removed again). Mapped allocation ports are bound one
per allocation, as in the relay's mapping mode: a mapped port already in use
is skipped, and the relay answers 508 when none is free. SIGINT and SIGTERM stop it cleanly. If the embedded
relay stops, the node exits unsuccessfully. Closing stdin ends the whole
process at once; the operating system closes every socket. Under
`--map-ports` it instead starts an orderly stop: the relay's ports are freed,
the node's router mappings are removed, and the process exits, normally well
inside three seconds; whatever is unfinished after five seconds is left to
the next launch. State writes are atomic, so an abrupt exit loses no saved
grant.

Standard output carries only single-line JSON objects, for the supervisor:

```json
{"v":1,"event":"ready","endpoint":"spry://<node key>?relay=wss%3A%2F%2Frelay.example%2F","pairing":"<43 characters>","urls":["turn:<public IP>:51000?transport=udp","turn:<public IP>:51001?transport=tcp"],"relayPortMap":[[41002,51002],[41003,51003]]}
{"v":1,"event":"status","allocations":0,"bytesRelayed":0,"lastAllocation":null}
{"v":1,"event":"control","relays":1}
{"v":1,"event":"control","relays":0}
{"v":1,"event":"status","allocations":2,"bytesRelayed":412000,"lastAllocation":1800000000}
```

- `ready` is printed once, when the relay is bound and control has started.
  `endpoint` is the exact `spry:` string the host stores as its pairing
  endpoint and offers in rooms; clients compare these strings whole.
  `pairing` is the pairing id for `/v1/grants` and `/v1/grants/devices`.
- `control` is printed when the number of connected control relays changes
  between none and some. Until the first such line, guests cannot reach the
  node.
- `status` carries counts and nothing else; see below.
- `portmap` and `urls` appear only under `--map-ports`; see
  [the next section](#automatic-router-port-opening).

### The status line

Always these five keys and no others, so a line is under 160 bytes:

| Key | Meaning |
|---|---|
| `v` | `1` |
| `event` | `"status"` |
| `allocations` | Allocations open now |
| `bytesRelayed` | Payload bytes forwarded since the node started, both directions, counted once for each allocation they pass through. At most `u64::MAX`. |
| `lastAllocation` | Unix seconds of the newest allocation whose client was a non-local address, or `null` if there has been none |

A client address is local, and so never sets `lastAllocation`, when it is
loopback, unspecified, private (10/8, 172.16/12, 192.168/16), link-local,
IPv6 unique-local, multicast, or the node's own `--bind` or `--public-ip`
address (a host reaching its own relay through its router). The node keeps
only the time, never the address. Allocations from local addresses still
count in `allocations` and `bytesRelayed`.

One status line is printed straight after `ready`. After that the node
checks once every 5 seconds and prints a line only if a count has changed,
so an idle relay is silent and a busy one prints at most one line in 5
seconds. A supervisor shows the numbers as they stand and should treat a
missing line as unchanged.

The line never carries an address, port, login, credential, key, grant, room
or relay URL, and the node holds none of that in the counters it reads: the
forwarding thread publishes three numbers and the status line is built from
those alone.

Standard error carries at most one refusal line. Neither stream carries
secrets, tokens, credentials, guest keys or guest addresses.

## Pairing and state

The pairing id is HMAC-SHA-256 of `spry-supervised-pairing-v1:<key>` under the
node secret, encoded as 43 base64url characters. The same secret and key give
the same id after every restart, so room grants and their registered keys
survive. At start-up the node keeps only that pairing: any other pairing in
the state file, its grants and any pending claim code are removed in one
saved write. A new `--pairing-key` therefore replaces the old pairing and all
of its grants.

## Control paths

The node answers these room-grant paths over `spry:` control, with the
signed-request, body, rate and seal rules of the
[API reference](api.md#room-grant-paths):

| Path | Signer | Notes |
|---|---|---|
| `/v1/grants` | The trusted pairing key | Answer adds `node`, the standard card; `endpoint` is the `spry:` endpoint |
| `/v1/grants/devices` | The trusted pairing key | Registration and sealing, unchanged |
| `/v1/grants/vouch` | A confirmed key on the grant | Unchanged |
| `/v1/credentials` | A registered or vouched key | Answer carries exactly the two `turn:` URLs above and adds `node` |

The other control paths, `/v1/pairings/claim`, `/v1/pairings/remove-self`
and `/v1/peers`, get 404 `{"error":"Not found."}` before the authority sees
them; paths outside the control allowlist are never opened at all. Because every grant is enforced from creation,
nobody redeems a grant until the pairing key registers keys on it, the host
app's own key included. A refused answer carries no card.

To stop sharing a room, the host removes every registered key with
`/v1/grants/devices`; the sealed grant then refuses every redemption, and
issued credentials lapse within five minutes. `/v1/grants/remove` is not a
`spry:` control path, so the grant itself stays until it expires 30 days
after its last renewal.

## The `spry-standard-v1` node card

A Nostr event of kind 24183 signed by the node's control key (the key in
the `spry:` endpoint):

```json
{
  "kind": 24183,
  "pubkey": "<node control key>",
  "created_at": 1700000000,
  "tags": [["expiration", "1700000600"]],
  "content": "{\"profile\":\"spry-standard-v1\",\"v\":1}",
  "id": "...",
  "sig": "..."
}
```

A verifier accepts it only when the signature is valid, the content is
exactly an object with `v` 1 and `profile` `spry-standard-v1` and nothing
else, there is exactly one tag, `expiration`, no more than 600 seconds after
`created_at` and in the future, and `created_at` is at most 60 seconds ahead.
It carries no address, so a client may copy it into a room descriptor
without revealing the host's public IP; the TURN URLs travel only in the
encrypted credential answer, to admitted guests. The node re-signs it every
four minutes, so repeated answers carry the same card.

A `spry-peer-v1` verifier refuses a standard card, and a standard verifier
refuses a peer card, so a private mesh can never treat a standard node as a
peer route. A client accepting a foreign standard offer should still check
that every returned URL is `turn:` on one public IPv4 literal, with a port
from 1024 to 65535 and at most two URLs.

Rust: `spry_link::standard::StandardCard::{sign, verify}`. The shared
vector is `standardNode` in [`tests/vectors/spry-link.json`](../tests/vectors/spry-link.json):
node key from the repeated byte 1, `created_at` 1700000000, signed with zero
auxiliary randomness so it can be reproduced byte for byte with
`cargo run -p spry-link --example vectors`.

## Evidence and limits

`cargo test --workspace` runs the unit tests for settings, refusals, the
control-path filter and sealing, and an integration test that starts the
real `spry-node supervised` with a generated loopback Nostr relay. It
creates and registers a grant over control, checks the card and URLs,
allocates through the embedded relay with the issued credentials (the
relayed address is the advertised public IP and a mapped public port),
checks that an HTTP request to the listener gets no HTTP answer, then
closes stdin and checks that the process exits within three seconds and
frees its ports. A second integration test starts the node with a
5000 bytes-per-second aggregate cap, opens two allocations well inside their
own allowance, sends 20,000 bytes through them and checks that about 5000
were relayed in all. It then reads the status lines: the first is all zeros,
the next shows both allocations and the bytes that crossed, `lastAllocation`
is `null` because both clients are on loopback, every line has exactly the
five keys, and no key, address, port, login, credential, grant, room or relay
URL appears in it.

With `--map-ports` the same integration tests run the node against the
in-house fake PCP, NAT-PMP and UPnP gateways on loopback (never third-party
router software). They check, from the node's stdout, the router's own table
and the record file: the router is asked and reported before `ready`; the
relay hands out the router's address and a granted port; closing stdin
removes exactly the node's mappings; a node killed with `SIGKILL` leaves
them and the next launch removes them before asking for its own (the router
refuses a second owner for the listener port, so the second launch cannot
start otherwise); a permanent-lease UPnP router is used, reported, recorded
and cleaned up the same way; a router that refuses stops the node with exit
code 3 before anything listens or is written; a changed external address
restarts the relay, prints `urls`, and later credentials carry the new
address; and a router that goes silent past the lease ends the node with
exit code 3 and leaves its record. Unit tests with a fixture clock cover
renewal at half the lease, retry, a router restart, a lost allocation port,
classification of shared and private addresses, ownership checks before a
UPnP delete, and the exact shape of every `portmap` line.

These are loopback tests. No router, NAT, firewall prompt, remote guest,
sleep and wake cycle or packaged desktop build is exercised; those remain
separate gates in the KithMoot built-in relay plan.
