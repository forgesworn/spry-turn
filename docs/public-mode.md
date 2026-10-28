# Public mode

Draft profile, version 1. Not a ratified NIP. Kind 31478 is a draft
allocation chosen for this profile and may change before any NIP proposal.

Public mode lets an independent operator open their own Spry relay to
anyone, and lets clients find it over Nostr. It is off unless the operator
turns it on. The software publisher runs no relay, credential service,
directory, index or default Nostr relay for it, and does not approve, rank
or list operators.

An operator who turns public mode on runs their own public service and is
responsible for it under the law where they and their users are. Spry does
not decide that for them. For the GB position see jurisdiction-kit's
[online-services note](https://github.com/forgesworn/jurisdiction-kit/blob/main/law/gb/online-services.md),
sections 2.11 (transport) and 2.13 (discovery).

## What changes when it is on

| | Off (default) | On |
|---|---|---|
| Who can get TURN credentials | Paired apps with a room grant | Also anyone, through the public endpoint |
| Advert on Nostr | None | Only if the operator names relays to publish to |
| Pairing, grants, private-node routes | Unchanged | Unchanged |

Public credentials grant TURN relaying only. They give no pairing, grant,
room, peer route or owner authority, and they are not linked to any of
those.

## Operator configuration

| Variable | Meaning |
|---|---|
| `SPRY_PUBLIC=true` | Turn public mode on. Any other value, or unset, leaves it off |
| `SPRY_PUBLIC_RELAYS` | JSON array of `wss://` relays to publish the advert to. Unset: public but unlisted (no advert) |
| `SPRY_PUBLIC_REGION` | Optional ISO 3166-1 alpha-2 country code the operator chooses to state, such as `GB` |
| `SPRY_PUBLIC_NOTE` | Optional operator text, at most 140 bytes, shown to people choosing a relay |
| `SPRY_PUBLIC_PRIVACY_URL` | Optional link to the operator's own privacy notice, published on open adverts as `["privacy", url]` |

There is no default relay list, region, note or privacy link. Spry never
fills these in, and never fetches the privacy link.

`SPRY_PUBLIC_PRIVACY_URL` must be an `https://` address on a DNS name of two
or more lowercase labels, with a path, at most 256 bytes: for example
`https://operator.example/privacy`, or `https://operator.example/` for the
site's front page (the trailing `/` is required). It may not carry userinfo,
a port, a query, a fragment, a percent-escape, an uppercase or `xn--` label,
an IP address, a reserved suffix such as `.local`, or an empty, `.` or `..`
path segment. Spry refuses to start, naming the setting, when it is invalid.
It is published only on open adverts, so only when `SPRY_PUBLIC_RELAYS` is
set. Its host need not be the relay's.

If you have no relays of your own in mind, these widely read public relays
accepted connections on 25 October 2026. They are run by other people, are
not checked or endorsed by the Spry project, and are only an example to
choose from; Spry does not use them unless you set them:

```sh
SPRY_PUBLIC_RELAYS='["wss://relay.damus.io","wss://relay.primal.net","wss://nostr-pub.wellorder.net","wss://relay.nostr.info"]'
```

Relays that charge for writing, such as `wss://nostr.wine`, will not take
the advert unless you are a member.

`SPRY_PUBLIC_RELAYS` follows the same rules as `SPRY_CONTROL_RELAYS`: one to
four distinct `wss://` URLs on DNS hostnames. Spry refuses to start, naming
the setting, when a value is invalid. To publish an advert, `SPRY_PUBLIC_URL`
must be an `https://` DNS hostname with no port, because clients refuse
anything else (client rule 4).

Public mode is v1 for the standard profile, where the relay allocates
ordinary addresses on the operator's public IP. The private-node profile
keeps its relay addresses on loopback behind peer links (127.64.0.0/10), so
v1 refuses to start with `SPRY_PUBLIC=true` in that profile, with a clear
error, rather than half-working. The other `SPRY_PUBLIC_*` settings are
ignored in that profile.

### Separate standard profiles on one host

The standard profile resolves these transport settings once at startup,
whether public mode is on or off:

| Variable | Default | Meaning |
|---|---|---|
| `SPRY_HTTP_PORT` | `3744` | Loopback HTTP API port behind the operator's HTTPS proxy |
| `SPRY_TURN_PORT` | `3478` | UDP and TCP TURN listener port |
| `SPRY_TLS_PORT` | `5349` | Direct TLS listener and advertised TLS port |
| `SPRY_RELAY_PORTS` | `49160:49191` | Inclusive UDP allocation port range |
| `SPRY_BYTES_PER_SECOND` | `1000000` | Per-allocation aggregate payload budget, in bytes per second, across both directions |

TURN and TLS ports must be decimal integers from 1 to 65535, must differ,
and must lie outside the ordered, non-zero relay range. The bandwidth must
be a decimal integer from 1 to 67108864; zero, overflow, signs and spaces
are refused with the setting's name. The private-node profile keeps its
existing settings and limits; it does not read the new standard-only
`SPRY_TLS_PORT`, `SPRY_RELAY_PORTS` or `SPRY_BYTES_PER_SECOND` settings.

For example, an operator can keep an existing paired instance and give a
separate public, unlisted standard instance its own ports and state:

```sh
SPRY_PUBLIC=true
SPRY_PUBLIC_URL=https://relay.example:3746
SPRY_HTTP_PORT=3746
SPRY_TURN_PORT=3479
SPRY_TLS_PORT=5350
SPRY_RELAY_PORTS=49200:49231
SPRY_BYTES_PER_SECOND=8388608
SPRY_TLS_GATE=true
```

These settings complement the required owner keys, fresh TURN secret,
reachable relay address and separate persistent state file described in
[standalone setup](standalone.md). Do not set a private peer bind or
interface on the public instance. Keep all API, listener and allocation
ports distinct from the other service, including its private peer port.
The two instances must have separate secrets and state files.

`SPRY_TLS_GATE=true` advertises TLS; the operator must provide a trusted
TLS gate at the selected TLS port forwarding to this instance's TCP TURN
port. With both existing `/data/tls/fullchain.pem` and
`/data/tls/privkey.pem` present, Spry instead starts its own TLS listener
on the selected TLS port. Configure the host's proxy, certificates,
firewall and any catalogue port mapping separately; setting an environment
variable does not open or route a host port.

The child relay's arguments, issued TURN URLs and UDP Binding readiness
probe use the same settings. An unavailable configured TURN port keeps
this instance unready; another instance listening elsewhere cannot make
it ready. Readiness checks the live child and a valid Binding response,
not the external TLS gate or public network route.

The rate is per allocation, with one second of burst capacity, rather than
a global server cap. The existing bounds remain 32 allocations, 8 per
username and 32 client connections; size host resources separately. An
8 MiB/s aggregate allocation budget can carry two directions sharing that
budget, but it is not a measured throughput promise.

Custom ports are for explicitly configured clients. They do not broaden
the signed advert rules: discovery still requires an HTTPS endpoint with
no port, and TURN ports from the existing allowlist in client rule 4.
Keep `SPRY_PUBLIC_RELAYS` unset for the custom-port example above.

## Public credential endpoint

`POST /v1/public/credentials`, body exactly `{"v":1}` (at most 256 bytes),
`Content-Type: application/json`. No `Authorization` header. Any `Origin` is
accepted for this path only; the response, including a refusal and the
`OPTIONS` preflight, carries `Access-Control-Allow-Origin: *` and no
credentials mode. Every other path keeps its existing origin rules. With
public mode off the path does not exist: every method gets 404.

Response 200:

```json
{"urls":["turn:relay.example:3478?transport=udp","turn:relay.example:3478?transport=tcp","turns:relay.example:5349?transport=tcp"],
 "username":"1793000000:pub-0123456789abcdef01234567",
 "credential":"<base64 HMAC-SHA1>",
 "expiresAt":1793000000}
```

- Lifetime 3600 seconds. The relay ends an allocation when its login
  expires and refuses to refresh it after that, so a login bounds how long
  a call can use it. A client whose call may outlast the login fetches a
  fresh one before `expiresAt` and restarts ICE with it; a call that ends
  sooner needs nothing more.
- The username label is fresh random bytes for each issue. It is not derived
  from the caller's address, origin, any key or any earlier issue, so two
  credentials cannot be linked by their usernames.
- Limits, all in memory and swept: at most 32 issues per minute in total,
  6 per source address per minute, 256 tracked source addresses. Over a
  limit: 429 with a generic message. These limits are separate from the
  ones that protect pairing and paired apps.
- The service listens only on loopback behind the operator's HTTPS reverse
  proxy, so the source address is the right-most `X-Forwarded-For` entry,
  the one that proxy appended; without one, the connecting address. IPv6
  sources are grouped by /64. Configure the proxy to append or set that
  header; a proxy that passes a caller's own header through lets callers
  evade the per-source limit, though not the total.
- Responses carry `Cache-Control: no-store`.
- Nothing about the request, the caller or the issued username is logged or
  persisted. Startup and error diagnostics only.
- When the relay is not ready, 503 with the existing readiness message.

The relay's existing allocation, per-user, bandwidth and capacity limits
apply to public users as to anyone else.

## Advert

A Nostr addressable event signed by the node's transport identity (the
`spry-link` identity, separate from the owner's signing key):

```json
{"kind":31478,
 "tags":[["d","spry-turn"],["v","1"],["status","open"],["auth","public"],
         ["expiration","1793007200"],["g","GB"],
         ["privacy","https://operator.example/privacy"]],
 "content":"{\"credentials\":\"https://relay.example/v1/public/credentials\",\"urls\":[\"turn:relay.example:3478?transport=udp\",\"turn:relay.example:3478?transport=tcp\",\"turns:relay.example:5349?transport=tcp\"],\"note\":\"Optional operator text\"}"}
```

- `d` is always `spry-turn`: one advert per transport identity.
- `status` is `open` or `withdrawn`. `auth` is `public` in v1.
- `expiration` (NIP-40) is at most two hours after `created_at`. Spry sets
  it to exactly two hours.
- `g` appears only on an open advert, and only if the operator set
  `SPRY_PUBLIC_REGION`.
- `privacy` appears only on an open advert, and only if the operator set
  `SPRY_PUBLIC_PRIVACY_URL`. Like `g`, a reader refuses the whole advert if
  the tag is repeated, has other than two items or holds a link outside the
  rules above, wherever it appears. Readers that predate it ignore it, so
  the advert stays version 1.
- `content` holds the credential endpoint, the TURN URLs and the optional
  note. A withdrawn advert has `content` `{}`.
- It never contains credentials, the TURN secret, owner keys, pairings,
  rooms, participants, usage counts or call records.

Lifecycle:

- Publish when the relay first reports ready, then every 30 minutes, each
  time with a fresh `created_at` and `expiration`.
- If the relay stops being ready while the service runs, for example
  because its process died, publish a newer `withdrawn` advert within a few
  seconds, waiting at most 5 seconds for relays. When it is ready again,
  publish a fresh `open` advert and resume the 30-minute cycle.
- On graceful shutdown, publish a newer `withdrawn` advert before stopping,
  waiting at most 5 seconds. Every advert's `created_at` is later than the
  one before, even within the same second.
- When public mode is turned off, the next start publishes a `withdrawn`
  advert if `SPRY_PUBLIC_RELAYS` is still set. Spry keeps no record of
  earlier adverts, so with the relays also removed, or if the whole service
  stops abruptly, the last advert expires within two hours.
- Withdrawals are best effort: a relay that misses one keeps the last open
  advert until it expires, while the endpoint answers 503.
- Publish only to `SPRY_PUBLIC_RELAYS`, using the existing control-relay
  connection rules (TLS validation, SOCKS option, public-address checks). A
  relay that refuses or fails is retried on the next cycle; failures are not
  reported anywhere.

## Client rules

These bind any client that reads the adverts, including KithMoot. KithMoot's
own change gate applies before it builds this.

1. Read kind 31478 only from relays the user already uses or has chosen.
   No publisher default discovery relay, directory or index.
2. Verify the event id and signature, kind, `d`, `v` = `1` and `auth`.
   Refuse events over 4 KiB, `created_at` more than 10 minutes in the
   future, a missing `expiration`, an `expiration` that is not 1 to 16
   ASCII digits (no sign, space or other character), or an `expiration` in
   the past or more than two hours after `created_at`.
3. Keep, per transport key, the newest `created_at` seen (a replay
   watermark). Ignore anything not newer, including a repeat of the same
   event. A newer `withdrawn` advert removes the relay; an older `open` one
   cannot restore it. A watermark may be forgotten two hours after its
   `created_at`, since anything older has expired by then.
   A client that keeps watermarks across restarts may store, with each,
   the id of the event that set it, and after restoring accept that one
   identical event once without moving the watermark, so a chosen relay
   works before the operator next republishes. Anything older, and any
   other event with the same `created_at`, is still refused.
4. The credential endpoint must be exactly
   `https://<DNS hostname>/v1/public/credentials` in canonical form: no
   userinfo, port (not even `:443`), query, fragment or other path, and no
   `xn--` label. Refuse IP literals and names that resolve to private, loopback, link-local or
   reserved addresses. Every TURN URL (`turn:` over UDP or TCP, `turns:`
   over TCP, at most four) must use the same hostname, and a port of
   exactly `3478`, `5349` or `443`, or none for the scheme's default. Do
   not follow redirects.
5. Consider at most 64 adverts and contact at most 3 credential endpoints
   for one call. Never probe every advertised endpoint.
6. Choose and rank locally. Send no choice, latency, failure or usage report
   to the publisher or anyone else.
7. A signature shows which key made the statement. It does not show the
   operator's identity, honesty, uptime, logging or jurisdiction; `g` and
   `privacy` are the operator's own claims. Show them as such.
8. A privacy link is the operator's own; never fetch it without the person
   tapping it, and send no referrer. Show its hostname, label it as the
   operator's, and do not prefetch, preconnect, preview or persist it.
9. Reading an advert grants nothing. Credentials come only from the chosen
   operator's endpoint, and room admission stays with the calling app.

`spry_link::advert` implements rules 2 to 4, the privacy-link grammar
(`privacy_valid`) and the watermark (`verify` and the bounded `AdvertBook`),
so clients and fixtures share one implementation. It opens no sockets, so the resolution part of rule 4
remains the client's job when it connects.

## Fixtures

The standalone service tests start the real relay executable from this
source tree. Build it before running workspace tests:

```sh
cargo build --locked --release --features tls --bin spry-turn
SPRY_TEST_RELAY_BINARY=target/release/spry-turn cargo test --locked --workspace --all-features
```

`SPRY_TEST_RELAY_BINARY` is relative to the workspace root unless absolute;
without it, tests use `target/release/spry-turn` (with the platform's
executable suffix). A missing binary fails with the build command. The
tests use generated ports and synthetic secrets, exercise two distinct
profiles and their own readiness, and verify issued credentials against
real authenticated allocations. They do not qualify a public deployment
or an operator's TLS gate. CI builds the same source's TLS relay before
these tests and reuses that build for interop.

`crates/spry-link/examples/public-advert.rs` writes signed fixtures from a
fixed test key to `docs/fixtures/public-advert-v1.json`: a valid open advert,
a valid withdrawal, and invalid cases (bad signature, missing expiration,
expiration too far ahead, future `created_at`, an `expiration` with a sign,
IP-literal endpoint, mismatched TURN host, a TURN port outside the allowed
three, older open after newer withdrawn, the same advert twice, an `xn--`
credential host), a valid open advert with a privacy link, and privacy links
that are refused (over `http:`, with a port, query, fragment, percent-escape,
uppercase host, IP literal, `xn--` label or dot segment, or a repeated
`privacy` tag, each `Destination`; over 256 bytes, `Size`). Each case lists
events to give, in order, to a fresh watermark at the file's `now`, with the
expected verdict for each: `open`, `withdrawn` or the refusal's name, and in
`privacy` the link a verifier must expose for each, or null. Readers that
predate `privacy` accept the privacy-link cases' events as open adverts;
that is harmless, since they never show the link. Signing uses fixed auxiliary bytes, so regenerating
gives the same file. Clients test against that file.
