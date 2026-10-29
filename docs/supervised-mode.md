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

This mode does not open router ports, prove reachability, cap aggregate
bandwidth, report usage counts or ship release builds. The supervisor (or a
later Spry release) supplies mapped ports and decides when the network can
host at all.

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

The first argument must be `supervised`. Without it, `spry-node` runs the
existing standard or private-node profile exactly as before.

| Option | Required | Rule |
|---|---|---|
| `--exit-on-stdin-close` | Yes | The node exits when its stdin pipe reaches EOF, and unsuccessfully on a read error. A supervisor holds the pipe open for the node's life. |
| `--pairing-key` | Yes | The supervising app's x-only public key, 64 lowercase hex characters, a valid curve point |
| `--state-file` | Yes | The node's private state file (mode 0600, written atomically). No default. |
| `--control-relay` | Yes, 1 to 4 times | Distinct `wss://` relay URLs on DNS names, the same rule as private-node control relays. The design allowed up to 8; the existing `spry:` endpoint rule allows 4. |
| `--bind` | Yes | The concrete local IPv4 address the listener and allocation ports bind to: not unspecified, loopback, link-local, multicast or broadcast |
| `--public-ip` | Yes | The IPv4 address given to guests: public unicast, refusing private, loopback, link-local, carrier-grade NAT, documentation, benchmarking, multicast and reserved space |
| `--listen-port` | Yes | Local TURN listener port, 1024 to 65535, shared by UDP and TCP |
| `--public-udp-port` | Yes | External UDP port of the listener, 1024 to 65535 |
| `--public-tcp-port` | Yes | External TCP port of the listener, 1024 to 65535. It may differ from the UDP port. |
| `--relay-port-map LOCAL:PUBLIC` | Yes, 1 to 64 times | UDP allocation port pairs, each 1024 to 65535, every local and every public port used once. No local port may be the listener port and no public port the listener's public UDP port. |
| `--max-allocations` | No | 1 to 32, default 8 |
| `--max-per-user` | No | 1 to 8 and at most `--max-allocations`, default 2 (or the total, if lower) |
| `--max-tcp-connections` | No | 1 to 32, default 16 |
| `--bytes-per-second` | No | Per allocation, 1 to 67108864, default 125000 |

When `--bind` equals `--public-ip` (a host holding a public address on its
own interface), every mapping must be `PORT:PORT` and both public listener
ports must equal `--listen-port`.

The allocation map uses the relay's existing
[explicit mapping mode](mapped-ports.md): allocations rotate through the
listed local ports only, answer with the public IP and public port, and
return 508 when every mapped port is in use. Mappings are fixed for the
run; a supervisor restarts the node when they change.

Any unknown, valueless or repeated option refuses startup. Each refusal
names the setting and never prints its value.

### Environment

| Variable | Rule |
|---|---|
| `SPRY_TURN_SECRET` | Required, at least 32 bytes. TURN credentials, grant tokens, the pairing id and the node's control identity are derived from it. |
| `SPRY_ROOM_SEAL` | Unset or `required`. `auto` and `off` refuse startup. |
| `SPRY_SOCKS_PROXY`, `SPRY_CONTROL_CA_FILE` | Optional outbound control settings, as for the private-node profile |
| `SPRY_LOCAL_TEST` | Unset or `true`; generated fixtures only. Allows a loopback bind, any non-multicast advertised address and `ws://` loopback control relays. Never set it on a real host. |

Every other `SPRY_` variable refuses startup, so a setting meant for another
profile (`SPRY_PUBLIC`, `SPRY_HTTP_PORT`, `SPRY_PEER_BIND`, `SPRY_RELAY_IP` and
so on) cannot appear to apply. Supervisors should start the node with a
cleared environment.

## Lifetime and output

After the settings are accepted the node watches stdin, binds the UDP and
TCP listener, loads its state, trusts the pairing, then starts control. If
the listener cannot be bound it exits unsuccessfully before printing
anything on stdout or writing state. Mapped allocation ports are bound one
per allocation, as in the relay's mapping mode: a mapped port already in use
is skipped, and the relay answers 508 when none is free. SIGINT and SIGTERM stop it cleanly. If the embedded
relay stops, the node exits unsuccessfully. Closing stdin ends the whole
process at once; the operating system closes every socket. State writes are
atomic, so an abrupt exit loses no saved grant.

Standard output carries only single-line JSON objects, for the supervisor:

```json
{"v":1,"event":"ready","endpoint":"spry://<node key>?relay=wss%3A%2F%2Frelay.example%2F","pairing":"<43 characters>","urls":["turn:<public IP>:51000?transport=udp","turn:<public IP>:51001?transport=tcp"],"relayPortMap":[[41002,51002],[41003,51003]]}
{"v":1,"event":"control","relays":1}
{"v":1,"event":"control","relays":0}
```

- `ready` is printed once, when the relay is bound and control has started.
  `endpoint` is the exact `spry:` string the host stores as its pairing
  endpoint and offers in rooms; clients compare these strings whole.
  `pairing` is the pairing id for `/v1/grants` and `/v1/grants/devices`.
- `control` is printed when the number of connected control relays changes
  between none and some. Until the first such line, guests cannot reach the
  node.

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
frees its ports.

These are loopback tests. No router, NAT, firewall prompt, remote guest,
sleep and wake cycle or packaged desktop build is exercised; those remain
separate gates in the KithMoot built-in relay plan.
