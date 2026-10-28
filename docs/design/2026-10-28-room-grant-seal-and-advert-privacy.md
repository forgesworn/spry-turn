# Room grant sealing and advert privacy links

Design, 28 October 2026. The spry-turn parts (1 and 2 of the
implementation order) are implemented on an unmerged branch; see the
implementation notes. Covers spry-turn (this
repository), KithMoot web and desktop (`forgesworn/kithmoot`) and KithMoot
Android (`forgesworn/kithmoot-android`).

Context: the Spry package gets three positions. **Private mesh** is today's
private-node profile. **Share with my rooms** is the standard profile with an
internet-reachable relay, credentials only through room grants, no anonymous
issuer and no advert. **Open to anyone** is the standard profile with
`SPRY_PUBLIC=true` and an optional kind 31478 advert. Part A makes "only
through room grants" a fact the node enforces. Part B adds an optional
operator privacy-notice link to the advert.

Nothing here adds a ForgeSworn hostname, relay, directory, probe, list or
default. No client fetches the privacy link on its own.

## Decisions in brief

1. Each device announces its room Spry public key as a new optional
   `spryKey` field in its own roster entry, which every device publishes on
   join and old clients already tolerate.
2. Registration is by delta with leases, not by full-set replacement: the
   paired owner's app adds and removes keys on `/v1/grants/devices`.
3. Any device the owner registered may vouch for a newcomer on the same call
   through `/v1/grants/vouch`. A vouched key lasts 24 hours and cannot vouch.
4. `/v1/credentials` refuses an unregistered key on a sealed grant with the
   existing "Call access has expired." refusal.
5. Node setting `SPRY_ROOM_SEAL=auto|required|off`, default `auto`: a grant
   seals when its owner's app asks, and new apps ask once no present device
   in the room lacks a `spryKey`.
6. The advert carries the privacy link as a new `["privacy", url]` tag. All
   three shipped verifiers ignore unknown tags and refuse unknown content
   fields, so the tag needs no v2.
7. The link is `https://` on a DNS name with a restricted path, no port, query
   or fragment, at most 256 bytes, checkable by string operations alone.
8. Clients label it as the operator's link, show its hostname, never fetch
   or prefetch it, and open it only on tap with no referrer.

## Verified facts

Read from `origin/main` of each repository on 28 October 2026. Against the
desktop v0.1.109 and Android v0.6.121 tags, `git diff <tag> origin/main` is
empty for every client file this design names except web `app/src/main.ts`,
whose differences are in attachment and chat rendering, not Spry or the relay
picker. So "shipped clients" means current `main` for these purposes.

| Claim | Finding |
|---|---|
| Both clients redeem another member's `https:` offer; only `spry:` offers need the device's own pairing | Correct. Web `src/spry.ts` `spryCredentials` (lines 94 to 95), `app/src/spry-room.ts` (lines 34 and 118); Android `SpryRoomAccess.kt` (lines 54 and 108) |
| `/v1/credentials` checks the signature but not that the signer is paired or registered | Correct. `crates/spry-access/src/lib.rs` `handle()`, `/v1/credentials` arm |
| Leak bounds: 32 devices per grant, 5-minute credentials, 30-day idle lease | Partly. The 32 counts device leases of 600 seconds, so more than 32 keys can redeem over time. Each redemption renews the grant once fewer than 29 days remain, so a leaked token in regular use never lapses. No shipped client calls `/v1/grants/remove`, so in practice only unpairing revokes |
| Guests sign with `spryDeviceKey(deviceKey)` or a random `newSpryKey()` | The web app always passes the room device key (`app/src/main.ts`, `new SpryRoom(... deviceSk ...)`); the random key appears only in tests. Android always uses `hmacSha256(deviceSecretKey, "spry-device-v1")`. Web device keys are per room (`deviceKey()` comment in `main.ts`), so a Spry key is per room per device |
| `/v1/peers` already registers per-room device lists and could be extended to HTTPS mode | Wrong. `/v1/peers` carries signed kind 24183 node transport cards of other members' Spry nodes (at most 8) for the private mesh. It exists only when the private bridge runs (`crates/spry-service/src/node.rs` returns 404 otherwise). Its `device` field is only an opaque hash that separates one device's scope entry from another's. It holds no list of redeeming signing keys, so this design adds new paths instead |
| An earlier write-up said stock clients refuse offers from nodes the device is not paired to | Wrong for `https:` offers; true only for `spry:` |
| `spry-room.ts` republishes on roster change | Correct, but it republishes the room descriptor (the offer), and only on devices that hold an offer. The roster entry is what every device publishes on join |
| The KithMoot advert verifier rejects unknown content fields and requires exactly one two-element tag per name | Content: correct. Tags: only for the names it reads (`d`, `v`, `auth`, `expiration`, `status`, and `g` when present). Unknown tag names are ignored, within the shape limits (at most 8 tags, 1 to 3 items each, at most 256 bytes per item, 4096 bytes in all). Rust and Android behave the same |
| (Found) the three advert verifiers agree on hostnames | Not quite. Android refuses any `xn--` label in the credential and TURN hosts (`PublicCallRelayAdvert.kt`, `labelsValid` and `turnHost`); Rust and TypeScript accept them. The fixture has no `xn--` case, so the divergence is untested |

## Part A: sealing room-grant redemption

### What changes and what does not

Today anyone holding a grant token can relay through the node, invisibly, for
as long as they keep using it. After sealing, a token is useless without a
signing key that a device admitted to the room has announced and the owner's
app (or a device it registered) has registered.

Sealing does not change who counts as admitted. In KithMoot whoever holds the
link may join, so a leaked link still gives relay access, but only by joining
the room, where the joiner shows on its roster. An admitted member can still
hand out its own 5-minute TURN credentials; no TURN scheme prevents that. The
node still learns no room id, room key, participant or device identity.

### A1. Announcing the Spry key

A new optional field on `RosterEntry`:

```ts
/** This device's Spry signing key for this room: the x-only public key of
 *  spryDeviceKey(deviceSk), 64 lowercase hex. A claim like `callProfile`;
 *  malformed values are dropped, never the entry. */
spryKey?: string
```

Why the roster entry and not the descriptor: every device publishes its roster
entry on join and answers newcomers with it (`session.announce()`), so a
registrar sees a guest's key whenever both are online. The descriptor is
republished only by devices that already hold an offer, after a one-second
debounce. Both are encrypted to the room key and signed by the device key.
Old clients keep the field without acting on it: web `decodeRosterEvent`
sanitises known fields and returns the parsed object with the rest intact,
and `encodeRosterEvent` only ever writes the device's own entry; Android
`RosterEntry.fromJson` reads named fields only.

Every new client announces `spryKey` in every room, derived inside the
session from its room device key, whether or not it uses Spry there. That
makes "admitted, not an agent, and no `spryKey`" a reliable sign of an old
client, which the seal decision (A4) depends on. Members learn nothing new: the
key is a one-way derivation of a per-room key they already see the public
half of.

- Web: `src/types.ts` `RosterEntry.spryKey`; `src/roster.ts`
  `sanitiseSpryKey()` used by `encodeRosterEvent` and `decodeRosterEvent`
  (accept `/^[0-9a-fA-F]{64}$/`, normalise with `normaliseHex`, else drop);
  `src/session.ts` own-entry construction (beside `callProfile`) adds
  `spryKey: spryDevicePublicKey(this.#opts.deviceSk)`; a new helper
  `spryDevicePublicKey(deviceSk)` in a small `src/spry-key.ts` so the session
  does not import the HTTP client.
- Web: a new read accessor `session.spryRoster(): { device, participant,
  spryKey?, agent }[]`, built from the same filtered entries `participants()`
  uses (lapsed devices swept, blocked and removed participants excluded,
  agent policy applied).
- Android: `protocol/.../Roster.kt` `RosterEntry.spryKey` with the same
  sanitising in `toJson`/`fromJson`; `session/RoomSession.kt` own entry (beside
  `callProfile`) derives it from `identity.deviceSecretKey`; an equivalent of
  `spryRoster()` for `SpryRoomAccess`.
- Vectors: a `spry-device-key` group in `vectors/kithmoot-vectors.json`
  (device secret, Spry secret, Spry public key, a roster entry carrying it),
  merged by hand into Android's vendored copy, never copied whole.

### A2. Who registers, and the offline owner

The registrar is any device holding the pairing that owns the grant: the
owner's paired app, including other devices that received the same pairing
through account sync (same pairing id and key, so the same scope and grant).

Registration is a delta with per-key leases:

- On grant creation or renewal, on every roster change (the existing
  debounced `onChange` path) and on app start, the registrar adds every
  `spryKey` in `spryRoster()` it has not already registered this session, and
  always its own Spry key. Its own key is not its pairing key: `SpryRoom`
  redeems with `spryDeviceKey(deviceSk)`.
- When a participant is removed from the room, the registrar removes every
  key it has seen for that participant.
- It never removes a key because its device left or lapsed. Roster presence
  is not membership: a guest who joined while the owner was away, left, and
  returns later with a saved offer must still work.

Why not full-set replacement: the registrar's view is only the devices present
now. Replacing the set on each change would prune absent members, who would
then fail on return whenever no registrar is online.

Offline owner. Options considered:

| Option | Result |
|---|---|
| Persisted list with leases only | Guests who join while no owner device is online get no relay from this room until one comes online |
| Any registered device may add keys | Covers standing rooms whose owner is rarely online; a registered device can add keys the owner never saw |
| Accept the limitation | Breaks "automatic in rooms I created" whenever the owner's devices are offline |

Decision: persisted leases plus bounded vouching. A device whose key the
registrar confirmed may vouch for a newcomer through `/v1/grants/vouch`. A
vouched entry expires 24 hours after the vouch, is never renewed by use, and
becomes a confirmed entry when the registrar next adds that key. Vouched
entries cannot vouch. Clients vouch only for a device that joins the call the
voucher is on, after a random 1 to 5 second delay, once per device per session.

The risk accepted: a confirmed member, or a removed member before the owner's
app sends the removal, can admit up to 8 keys at a time for a day each. That
member could already share 5-minute credentials, and the room link, so the
increase is small and bounded.

### A3. Node wire format

Both new paths are authenticated exactly like the existing ones (NIP-98-style
`Authorization: Nostr` over HTTPS, or the `spry:` control channel), counted
against the existing per-source and per-key limits, and bounded by
`MAX_BODY`.

**`POST /v1/grants/devices`** (registrar)

```json
{"v":1,"pairing":"<pairing id>","grant":"<grant token>",
 "add":["<64 hex>"],"remove":["<64 hex>"],"seal":true,"revision":1793000000123}
```

- Authorised only when the signer is the pairing's key
  (`pairing_authorises`) and the grant belongs to that pairing; else 403
  "Approval required.". An unknown or expired grant: 403 "Call access has
  expired.".
- `add` and `remove`: at most 32 each, no duplicates, no key in both, each a
  valid x-only point. `seal` optional boolean. `revision` a safe integer that
  must exceed the last one seen for this grant in the past 90 seconds (in
  memory, as `PeerRegistry::update_revision`); else 409 "Out of date. Try
  again.". It guards against reordering on the `spry:` control channel.
- Each added key becomes a confirmed entry with a lease of `GRANT_TTL` (30
  days), replacing any vouched entry for it. Each removed key loses its entry
  and its current device lease, which frees its slot at once; TURN
  credentials already issued stay valid until they expire, at most 5 minutes.
- `seal: true` sets the grant's `sealed` flag. The flag is monotonic: `false`
  never unseals.
- Response: `{"v":1,"sealed":true,"enforced":true,"devices":12}`, where
  `enforced` reflects `SPRY_ROOM_SEAL` and `devices` counts entries.

**`POST /v1/grants/vouch`** (member)

```json
{"v":1,"grant":"<grant token>","add":["<64 hex>"]}
```

- Authorised only when the signer holds a confirmed, unexpired entry on that
  grant; else 403 "Call access has expired." (indistinguishable from an
  expired grant to a token holder).
- `add`: at most 4 keys. A key already listed is left unchanged and is not
  counted. Otherwise a vouched entry expiring 24 hours later.
- At most 8 vouched entries per grant at once, and 8 vouches per sponsor per
  grant per 24 hours (in memory, table of at most 256, swept); over either:
  429 "Spry is busy. Try again shortly.".
- Response: `{"v":1,"added":1}`.

**`/v1/credentials`** (changed)

- When the grant is enforced (`sealed` under `auto`, always under `required`,
  never under `off`), the signer must hold an unexpired entry; otherwise 403
  "Call access has expired.", the existing refusal, so a token holder cannot
  tell a sealed grant from an expired one.
- A confirmed entry's lease renews to 30 days when fewer than 29 remain, at
  most one state write per entry per day, as the grant does today. A vouched
  entry is not renewed. Last use is kept in memory only.
- The 32 concurrent device leases, 5-minute credentials and response shape are
  unchanged.

**Capacity.** At most 64 entries per grant and 1024 per node. A registrar add
into a full grant evicts the confirmed entry with the oldest last use that has
no active device lease (never used since start counts as oldest); with none
to evict, 429 "This call has reached its device limit.". A vouch never evicts.
Over the node limit: 429.

**Persistence.** `Grant` gains two serialised fields with `#[serde(default)]`
and skip-if-empty, so `Saved.version` stays 1:

```json
{"pair":"...","scope":"...","salt":"...","expires":1795592000,
 "sealed":true,"members":[["<64 hex>",1795592000,false]]}
```

`members` holds key, lease end and vouched flag. `restore()` additionally
checks at most 64 members and 8 vouched per grant, 1024 in all, and valid
keys. A member entry is about 86 bytes, so a full state stays under the
existing 131072-byte read limit; a test must prove it. An older binary ignores
the unknown fields (neither `Saved` nor `Grant` denies them), loads every grant
unsealed and drops the lists on its next save: rollback loses sealing but
still starts.

**Sweep and revocation.** `sweep()` drops expired members. Removing a grant
(`/v1/grants/remove`) or its pairing drops its members with it, as today. A
sealed grant with no members stays sealed.

**Routing.** `crates/spry-service/src/node.rs` passes both paths to
`Authority::handle` unchanged (no node card in their responses).
`crates/spry-link/src/control.rs` `PATHS` gains both, so they work on `spry:`
nodes too.

### A4. Modes, migration and compatibility

`SPRY_ROOM_SEAL`, read once at startup into `spry_access::Config::seal`; any
other value refuses to start, naming the setting.

| Value | Behaviour |
|---|---|
| `auto` (default, both profiles) | A grant is enforced once its registrar sends `seal: true` |
| `required` | Every grant is enforced from creation, including grants created before the switch |
| `off` | Registration and vouching are accepted and stored but never enforced. For diagnosis and rollback |

New registrars decide `seal` per request: `true` when every device in
`spryRoster()` that is not an agent carries a `spryKey`, otherwise `false`
(keys are still registered, so a later seal is immediate). Agents are exempt
because no agent redeems Spry offers today (`src/agent.ts` never uses
`spry.ts`). Once a response reports `sealed: true`, the client stops deciding.
A room therefore seals the first time its owner's app sees no old client
present, and stays sealed.

Order: the registrar registers (including itself) before its first
redemption of a new grant, so `required` grants work for new clients from the
first call.

| Clients | `auto` | `required` |
|---|---|---|
| New owner, new guests | Sealed; works | Works |
| New owner, an old guest present | Stays unsealed while that guest is present; works as today | Old guest refused |
| Old guest joins after sealing | Refused; its app shows its existing generic "Spry access is unavailable" message and the call uses the room's other connection paths | Same |
| Old owner app (Android 0.6.121, desktop 0.1.109, web before this change) | Never registers, so its grants never seal; works as today. Once a new owner device has sealed a room's grant, an old owner device redeeming that grant is refused like any old guest | Refused on its own node until updated |
| New client, node without these paths | 404; the client stops trying for an hour and behaves as today | n/a |

Package positions: Private mesh and Open to anyone keep the default `auto`.
Share with my rooms starts at `auto`, which already seals every room whose
devices run the new releases. Moving it to `required` drops support for old
owner apps on that node, so it is the owner's call once the client releases
in this design are the oldest in use. It stays an open question below.

### A5. Client behaviour

- Registrar (`app/src/spry-room.ts` new `#registerDevices()`, Android
  `SpryRoomAccess.registerDevices()`): runs inside the existing serialised
  `refresh()`, after `spryGrant` and before redemption; tracks keys
  registered this session; revision from the existing `Date.now()` style
  counter, retried once with a fresh revision on 409.
- Removal: the registrar subscribes to the session's participant removal
  (web `#removed`; a public `onRemoved` listener is needed if none is exposed:
  unverified) and sends `remove` for that participant's keys.
- Member (`#vouch()`, Android `vouch()`): only when its own last redemption
  of this grant succeeded in the past 10 minutes, for a device newly on the
  same call with a `spryKey`, after the jitter in A2.
- Retry: today a guest's `prepare()` waits 2.5 seconds for an offer, then the
  30-second timer is the next chance. After a refused redemption within the
  first minute of holding an offer or joining a call, retry after 3, 10 and 30
  seconds, then fall back to the 30-second timer. No new refusal reason is
  needed on the wire.
- Request helpers: web `src/spry.ts` `spryRegisterDevices()` and
  `spryVouch()`, both paths added to the `spryRequest` allowlist (line 50);
  Android `SpryClient.registerDevices()` and `vouch()`, paths added to
  `SpryClient.request` (line 102) and `protocol/.../SpryLink.kt` (line 37).

### A6. What people see

- Owner: nothing new. Sharing in rooms they created stays automatic.
- Guest joining while an owner device, or a registered member on the call, is
  online: the room's relay within a few seconds of joining the call.
- Guest joining when nobody registered is online: no relay from this room's
  Spry until someone is; the call connects directly where it can, or through
  a relay the guest set up. Proposed status line: "This room's call relay
  starts working once its owner, or someone already using it, is online."
- Returning guest with a saved offer and an unexpired lease: works with nobody
  else online.
- Removed participant: loses the relay within 5 minutes of the owner's app
  next being online.

### A7. Privacy

| | Today | After |
|---|---|---|
| Keys per grant | Keys that redeemed, in memory, 600-second leases | Every registered key per opaque scope, on disk, up to 30 days after last use or registration |
| Linking renewals | One key per device per room across renewals, in memory | The same, plus persisted across restarts |
| Idle members | Invisible | Members who never call are listed, so the node learns the room's device count over time |
| Timing | Redemption times | Also registration times (about when a guest joined while the owner was online) and removal times |
| Relationships | None | Which member vouched for which key |
| Across rooms | Not linkable by key (per-room keys); source address only | Unchanged |

The node is the owner's own, and its registrar is the owner's app, which
already sees the room's roster. The new exposure is persistence: someone who
takes the node's state file learns per-scope key sets, not identities. No
room id, room key, participant, device public key or name reaches the node.

### A8. Tests

spry-turn, `crates/spry-access/tests/authority.rs` (existing `pair`, `grant`
and `signed` helpers):

- `auto`: an unsealed grant redeems for any signer; after `seal: true`, listed
  keys redeem and an unlisted key gets the expired refusal.
- `required`: a new grant refuses everyone until registration; `off`: entries
  stored, never enforced.
- Only the owning pairing's key may register; another pairing cannot touch
  the grant.
- Vouching: a confirmed member vouches; a vouched key redeems; a vouched key
  cannot vouch; a stranger cannot vouch; per-grant and per-sponsor caps; a
  vouched entry expires after 24 hours and is not renewed by use; a registrar
  add confirms it.
- Removal refuses the next redemption and frees the device slot.
- Leases renew on use at most daily; expired members are swept; removing the
  pairing or grant drops members.
- 64-per-grant eviction of idle entries, 429 with none idle, 1024 node limit.
- Persistence: members and `sealed` survive `restore()`; a state file without
  the fields loads unsealed; a full state serialises under 131072 bytes; a
  test-only copy of the v0.3 `Saved`/`Grant` structs still parses the new file.
- Revision replay gives 409; `seal: false` never unseals.
- `crates/spry-service`: HTTP routing and origin rules for both paths; both
  in the control `PATHS`; `SPRY_ROOM_SEAL` parsing and refusal of bad values.

KithMoot web:

- `src/roster` tests: `spryKey` round trip, hostile values dropped without
  losing the entry, byte-identical entries when absent.
- `src/spry.test.ts`: request shapes and allowlist; 404 handling.
- `app/src/spry-room.test.ts`: registrar adds its own key, adds roster keys,
  removes on removal, sends `seal: false` while an old client is present and
  `true` after; member vouching rules; retry schedule.
- e2e `test/spry-room-seal.spec.ts`, beside `test/spry-pairing.spec.ts`: an
  owner context with a seeded pairing and an unpaired guest, against a fake
  Spry served by `context.route('https://relay.example/**')` that implements
  this contract (a shared `test/spry-fake.mjs`). Assert: the guest's first
  redemption is refused, the owner's `/v1/grants/devices` carries the guest's
  roster key, the guest's next redemption succeeds within 15 seconds; a third
  context outside the room replaying the token is refused; with the owner
  closed, a second guest joining the call is vouched for and redeems. Run the
  full e2e suite, as for any change to call setup.
- Cross-repository: extend spry-turn's `tests/kithmoot.py` with a room-seal
  scenario against the real binary, forwarding the routed origin to the
  loopback service (request signatures bind to the configured endpoint, not
  the socket). Unverified that the runner can route this way.

KithMoot Android:

- `protocol` tests: `RosterEntry.spryKey` round trip and sanitising; the
  `spry-device-key` vector group; request body shapes for both paths in
  `SpryTest.kt`; control paths in `SpryLinkTest.kt`.
- App unit tests for `SpryRoomAccess` registration, seal decision, vouching
  and retry. Compile the instrumented tests too
  (`compileDebugAndroidTestKotlin`), since `./gradlew test` skips them.

## Part B: optional privacy-notice link in kind 31478 adverts

### B1. What shipped verifiers do

| | Rust `spry_link::advert::verify` | Web `verifyPublicRelayAdvert` | Android `PublicCallRelayAdvert.verify` |
|---|---|---|---|
| New content field | Refused, `Encoding` (`Offer` has `deny_unknown_fields`) | Refused, `Encoding` (key allowlist in `parseOffer`) | Refused, `Encoding` (key allowlist in `parseOffer`) |
| New tag name | Ignored (`Event::tag` looks up named tags only) | Ignored (`tag()` likewise) | Ignored (`tag()` likewise) |
| Tag shape limits | At most 8 tags, 1 to 3 items, 256 bytes per item (`Event::verify`) | Same | Same |
| Whole event | 4096 bytes | Same | Same |

An open advert uses five tags plus an optional `g`, so a seventh fits with one
to spare.

### B2. Representation

A tag on open adverts, version unchanged:

```json
["privacy","https://operator.example/privacy"]
```

Shipped clients accept such adverts and ignore the tag. A content field would
need a v2 advert and dual publication, for nothing gained. The name is
multi-letter, so relays do not index it. When present the tag must occur
once with two items, like `g`; a malformed one refuses the whole advert
(`Destination`), again like `g`. Spry never puts it on a withdrawal; a reader
validates it wherever present, as it does `g`.

Shipped clients will accept an advert whose privacy tag new clients refuse.
That is harmless (old clients never show the link) and the fixture records it.

### B3. URL rules

A grammar checkable by string operations, because Android's protocol module
deliberately parses advert URLs by hand:

```
privacy = "https://" host path            ; at most 256 bytes
host    = label 1*("." label)             ; two or more labels
label   = 1 to 63 of [a-z0-9-], not starting or ending with "-",
          not starting "xn--"
path    = "/" *[A-Za-z0-9._~/-]
```

Also refused: a last label that does not start with a letter (no IP literal
or numeric look-alike), a last label of `local`, `localhost`, `internal`,
`invalid` or `test`, `//` in the path, and any `.` or `..` path segment. So
no userinfo, port, query, fragment, percent-encoding, uppercase host or
trailing dot. Under this grammar the string is its own canonical form; Rust
also asserts `Url::parse(s).as_str() == s` and TypeScript
`new URL(s).href === s`, and Android relies on the grammar alone. The `xn--`
refusal follows Android's existing rule for advert hosts, so the three agree
from the start.

The host need not match the relay's: an operator may keep their notice on a
site they already run, and checking a shared registrable domain would need a
public suffix list none of the readers has. The picker shows the link's
hostname instead. At display time the client also applies its connect-time
host rules (`publicRelayHostAllowed`, Android `hostAllowed`); a link that
fails them is hidden, the advert still listed.

### B4. Display

- Listing: `PublicRelayListing` gains `privacy?: { url, host }` (web
  `app/src/public-call-relays.ts` line 115, Android `PublicCallRelays.kt`
  `listing()`). Taken from the live advert only; never persisted, never
  copied into `lastGood`, a room, a descriptor, a link or an invitation.
- Words: "The operator's privacy notice" followed by its hostname, for
  example "The operator's privacy notice (operator.example)", with
  "Opens operator.example in your browser. KithMoot has not checked it." as
  its accessible description. It is the operator's own link, like region and
  note under client rule 7.
- Web (`renderPublicRelays` in `app/src/main.ts`): an `<a>` after the
  `<label>`, not inside it, so a tap does not select the relay;
  `target="_blank" rel="noopener noreferrer nofollow"
  referrerpolicy="no-referrer"`. No prefetch, preconnect, favicon or preview.
  Desktop must hand it to the system browser through its existing external
  link path (unverified which handler applies to this element).
- Android (`ui/settings/PublicCallRelaysPanel.kt`): a separate tappable line
  under the operator's claim line; on tap,
  `Intent(ACTION_VIEW, uri).addCategory(CATEGORY_BROWSABLE)` with no
  `EXTRA_REFERRER`. No WebView, no Custom Tabs warm-up or `mayLaunchUrl`.
  Whether the chosen browser adds a referrer of its own is outside the app's
  control (unverified per browser).
- Never fetched automatically, by any client, at any time.

### B5. Operator setting

`SPRY_PUBLIC_PRIVACY_URL`, optional, no default. Validated when
`SPRY_PUBLIC=true`; a bad value refuses to start with "SPRY_PUBLIC_PRIVACY_URL
must be an https:// address on a DNS name, without port, query or fragment,
at most 256 bytes". Published only on open adverts, so only when
`SPRY_PUBLIC_RELAYS` is set. Ignored in the private-node profile, like the
other `SPRY_PUBLIC_*` settings. Spry never fetches it either.

Code: `crates/spry-link/src/advert.rs` gains `privacy_valid()`,
`Advert::privacy: Option<String>`, and a `privacy: Option<&str>` parameter on
`tags()`, `open_parts()` and `open()`; `verify()` reads it.
`crates/spry-service/src/public.rs` `PublicSettings` gains `privacy`, read in
`parse()`/`from_environment()` with a new `SetupError`, and
`Publisher::start` carries it; `crates/spry-service/src/lib.rs` passes it.
`docs/public-mode.md`: the settings table, the advert example and bullets,
a new client rule ("A privacy link is the operator's own; never fetch it
without the person tapping it, and send no referrer"), and the fixture list.

### B6. Fixtures

`crates/spry-link/examples/public-advert.rs` regenerates
`docs/fixtures/public-advert-v1.json` (deterministic, as today). New cases:

- valid open advert with a privacy link (expect `open`);
- privacy link that is `http:`, has a port, a query, a fragment, a
  percent-escape, an uppercase host, an IP literal, an `xn--` label, a dot
  segment, or a repeated `privacy` tag (each `Destination`);
- privacy link over 256 bytes (`Size`, from the shape check).

Each case may carry `"privacy": [<url or null>, ...]`, one per event, the link
a verifier must expose; readers that do not know the key ignore it. KithMoot
copies the file to `test/fixtures/public-advert-v1.json` (and updates
`public-advert-v1.source.md`) and Android to
`protocol/src/test/resources/public-advert-v1.json`, each in the same PR as
its verifier change, since the new invalid cases fail old verifiers.
Recommended in the same spry-turn PR: an `xn--` credential-host case, with
Rust and TypeScript aligned to Android's refusal, to close the divergence
found above.

### B7. Tests

Rust advert tests for `privacy_valid` and an open advert with seven tags under
4096 bytes; `public.rs` settings tests; web `src/public-call-relays.test.ts`
and Android `PublicCallRelayAdvertTest` comparing verdicts and `privacy`
values with the fixture; listing tests that the link is not persisted and is
hidden when its host fails the connect-time rules; a web e2e check that
rendering the picker makes no request to the link's host.

## Implementation order

1. **spry-turn, sealing**: `crates/spry-access/src/lib.rs` (`Seal`,
   `Config::seal`, `Grant::sealed`, `Grant::members`, the two new `handle()`
   arms, `/v1/credentials` check, `sweep()`, `restore()`, `save()`),
   `crates/spry-access/tests/authority.rs`, `crates/spry-service/src/lib.rs`
   (`SPRY_ROOM_SEAL`), `crates/spry-link/src/control.rs` (`PATHS`),
   `crates/spry-access/README.md`, `docs/api.md`, `docs/standalone.md`,
   `CHANGELOG.md`, and `llms-full.txt` if it lists endpoints.
2. **spry-turn, privacy link**: `crates/spry-link/src/advert.rs`, the fixture
   generator and file, `crates/spry-service/src/public.rs` and `lib.rs`,
   `docs/public-mode.md`. Release spry-turn after 1 and 2; in `auto` nothing
   changes for existing clients.
3. **KithMoot web and desktop**: `spryKey` in roster and session,
   `spryRoster()`, `src/spry-key.ts`, `src/spry.ts` helpers and allowlist,
   `app/src/spry-room.ts` registrar, vouching and retry, vectors; then the
   privacy link in `src/public-call-relays.ts`,
   `app/src/public-call-relays.ts`, `renderPublicRelays` and the fixture.
4. **KithMoot Android**: the same in `protocol/.../Roster.kt`,
   `session/RoomSession.kt`, `media/SpryClient.kt`, `protocol/.../SpryLink.kt`,
   `media/SpryRoomAccess.kt`, `protocol/.../PublicCallRelayAdvert.kt`,
   `media/PublicCallRelays.kt`, `ui/settings/PublicCallRelaysPanel.kt`, the
   vendored vectors and fixture.
5. **Spry package positions**: Share with my rooms sets `SPRY_ROOM_SEAL`
   (`auto` first); Open to anyone gains an optional privacy-link field. These
   are Archipelago screens. Maintainer must review and approve UI work on the
   Spry app's sharing and public-mode settings screens before merging or
   approval. ZAT pending.

## Unverified and open

- Whether Android `RoomIdentity` keys are never reused across rooms (the type
  says "Who this device is in one room"; not traced to storage).
- Whether the web session exposes participant removal publicly, or
  `onRemoved` must be added.
- Which handler opens a `target="_blank"` link in the desktop app, and
  whether Android browsers add their own referrer to an `ACTION_VIEW` launch.
- Whether the desktop app redeems Spry offers through anything other than the
  bundled web code (no desktop-specific Spry code found).
- Whether the Spry package surfaces node settings in a form that can carry
  `SPRY_ROOM_SEAL` and `SPRY_PUBLIC_PRIVACY_URL`.
- Whether `tests/kithmoot.py` can route a public-looking origin to the
  loopback service for the cross-repository seal scenario.
- Open: when Share with my rooms moves from `auto` to `required`.

## Implementation notes (spry-turn)

Choices made while implementing parts 1 and 2 of the order above, where
this design was silent or ambiguous. Each takes the safer reading.

- `/v1/grants/devices` checks the signer's pairing before the grant, so a
  signer that does not hold the named pairing gets "Approval required."
  whether or not the token is live; a stranger learns nothing about a token.
  A paired app naming another pairing's live grant still gets "Approval
  required." where an unknown grant gets "Call access has expired.", as
  `/v1/grants/remove` already does.
- Both new paths refuse any field not in their wire format and any `v`
  other than 1 (400). A later field needs `v: 2`. `/v1/grants/vouch` also
  refuses an empty `add`.
- Statuses the design left without a message: a vouch into a grant already
  holding 64 entries gets 429 "This call has reached its device limit.";
  either path over the 1024-entry node limit gets 429 "Spry is already
  helping too many calls.". A vouch over any cap adds nothing.
- The per-sponsor vouch count is a fixed 24-hour window from the sponsor's
  first vouch, like the existing per-minute buckets, so across a window
  boundary a sponsor may add up to 16 keys in a little over a day. The
  8-at-once per-grant cap still holds.
- Open: the sponsor table holds 256 entries, while 64 grants could each have
  many confirmed sponsors. When it is full, a new sponsor gets 429 until
  entries lapse, up to a day. Sponsors are only keys the owner's app
  registered, so the owner bounds it; sizing it to the 1024-entry node limit
  is an option.
- Vouched entries are not removed when their sponsor is removed; they lapse
  within 24 hours, the risk this design already accepts. The node does not
  persist which key vouched for which.
- `enforced` in the `/v1/grants/devices` response is `sealed` under `auto`,
  always `true` under `required` and always `false` under `off`, even for a
  sealed grant.
- `SPRY_ROOM_SEAL` set to the empty string refuses startup, like any value
  other than `auto`, `required` or `off`.
- Added: `save()` refuses a state file over the 131072-byte read limit, so a
  state that grew past it can never stop the next start. Under the bounds it
  is unreachable; a node at every bound (16 pairings, 64 sealed grants, 1024
  members, a 2048-byte transport address) wrote 107274 bytes in the test.
- Added: removing a pairing drops its grants, with their registered keys,
  from the saved state in the same write. Before, they stayed on disk,
  ignored by `restore()`, until the next save.
- `SPRY_PUBLIC_PRIVACY_URL` is validated whenever it is set in the standard
  profile, not only with `SPRY_PUBLIC=true`, as `SPRY_PUBLIC_REGION` and
  `SPRY_PUBLIC_NOTE` already are. The private-node profile ignores it.
- A privacy link must have a path, so an operator linking a front page must
  write the trailing slash (`https://operator.example/`): the grammar needs
  `/`, and the URL parser adds one, so the canonical check would refuse the
  bare host either way. The settings documentation says so.
- The oversize privacy fixture case gives `Size` because the shape check
  runs before the signature check; its signature cannot be valid, since the
  signer refuses an item over 256 bytes. A port that checks signatures first
  would report `Authentication` and must reorder to match the fixture.
- Rust now refuses `xn--` credential hosts, so the new fixture case fails
  the current TypeScript verifier until KithMoot copies the fixture with its
  verifier change, as for the privacy-link cases.
