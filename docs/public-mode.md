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

There is no default relay list, region or note. Spry never fills these in.

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

- Lifetime 600 seconds. A client renews at two thirds of the remaining
  lifetime.
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
         ["expiration","1793007200"],["g","GB"]],
 "content":"{\"credentials\":\"https://relay.example/v1/public/credentials\",\"urls\":[\"turn:relay.example:3478?transport=udp\",\"turn:relay.example:3478?transport=tcp\",\"turns:relay.example:5349?transport=tcp\"],\"note\":\"Optional operator text\"}"}
```

- `d` is always `spry-turn`: one advert per transport identity.
- `status` is `open` or `withdrawn`. `auth` is `public` in v1.
- `expiration` (NIP-40) is at most two hours after `created_at`. Spry sets
  it to exactly two hours.
- `g` appears only on an open advert, and only if the operator set
  `SPRY_PUBLIC_REGION`.
- `content` holds the credential endpoint, the TURN URLs and the optional
  note. A withdrawn advert has `content` `{}`.
- It never contains credentials, the TURN secret, owner keys, pairings,
  rooms, participants, usage counts or call records.

Lifecycle:

- Publish when the relay first reports ready, then every 30 minutes, each
  time with a fresh `created_at` and `expiration`.
- On graceful shutdown, publish a newer `withdrawn` advert before stopping,
  waiting at most 5 seconds. Its `created_at` is always later than the last
  open advert's, even within the same second.
- When public mode is turned off, the next start publishes a `withdrawn`
  advert if `SPRY_PUBLIC_RELAYS` is still set. Spry keeps no record of
  earlier adverts, so with the relays also removed, or after an abrupt
  stop, the last advert expires within two hours.
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
   future, a missing `expiration`, or an `expiration` in the past or more
   than two hours after `created_at`.
3. Keep, per transport key, the newest `created_at` seen (a replay
   watermark). Ignore anything not newer, including a repeat of the same
   event. A newer `withdrawn` advert removes the relay; an older `open` one
   cannot restore it. A watermark may be forgotten two hours after its
   `created_at`, since anything older has expired by then.
4. The credential endpoint must be exactly
   `https://<DNS hostname>/v1/public/credentials` in canonical form: no
   userinfo, port (not even `:443`), query, fragment or other path. Refuse
   IP literals and names that resolve to private, loopback, link-local or
   reserved addresses. Every TURN URL (`turn:` over UDP or TCP, `turns:`
   over TCP, at most four) must use the same hostname. Do not follow
   redirects.
5. Consider at most 64 adverts and contact at most 3 credential endpoints
   for one call. Never probe every advertised endpoint.
6. Choose and rank locally. Send no choice, latency, failure or usage report
   to the publisher or anyone else.
7. A signature shows which key made the statement. It does not show the
   operator's identity, honesty, uptime, logging or jurisdiction; `g` is the
   operator's own claim. Show it as such.
8. Reading an advert grants nothing. Credentials come only from the chosen
   operator's endpoint, and room admission stays with the calling app.

`spry_link::advert` implements rules 2 to 4 and the watermark
(`verify` and the bounded `AdvertBook`), so clients and fixtures share one
implementation. It opens no sockets, so the resolution part of rule 4
remains the client's job when it connects.

## Fixtures

`crates/spry-link/examples/public-advert.rs` writes signed fixtures from a
fixed test key to `docs/fixtures/public-advert-v1.json`: a valid open advert,
a valid withdrawal, and invalid cases (bad signature, missing expiration,
expiration too far ahead, future `created_at`, IP-literal endpoint,
mismatched TURN host, older open after newer withdrawn, the same advert
twice). Each case lists events to give, in order, to a fresh watermark at
the file's `now`, with the expected verdict for each: `open`, `withdrawn`
or the refusal's name. Signing uses fixed auxiliary bytes, so regenerating
gives the same file. Clients test against that file.
