# KithMoot client acceptance

spry-turn speaks standard TURN. KithMoot can use that transport without
adding KithMoot, WebRTC or media codecs to the server. Each device chooses
its operator and enters the credentials supplied for that relay. The
publisher need not run a relay or credential service.

## Run the actual web application locally

The acceptance runner builds an authorised KithMoot source checkout using
its existing Node dependencies, then serves that unchanged production app
on loopback. It starts a disposable Nostr signalling fixture and a separate
spry-turn process. Each browser enters the operator's short-lived TURN
credentials through the real Settings → Connections form. The shared
secret stays in the fixture; only its expiring username and credential
reach the client. The fixture refuses `/turn`, and the test asserts that
the application never requests it. No credential service is needed.

```sh
cargo build --locked --release --features tls --bin spry-turn
python3 tests/kithmoot.py \
  --kithmoot /path/to/authorised/kithmoot \
  --binary target/release/spry-turn \
  --output .local/kithmoot-web.json
```

Install KithMoot's pinned dependencies in that checkout beforehand. The
runner uses this repository's Playwright installation and Chromium, as
described in [standalone verification](verification.md). `--app-dist`
accepts an existing production build instead; its content digest is
recorded, and the receipt says whether the runner built it. No source from
the other project is committed into this repository. The receipt identifies
the source commit, relevant file checksums, app build digest and exact
spry-turn executable hash.

For each transport, two independent browser contexts create and join a
real KithMoot room, then use its camera and microphone controls. The
application's own “Hide my IP address” preference selects relay-only ICE.
The test observes peer connections and rejects any direct configuration;
it supplies no substitute ICE servers. Both sides must display remote
video, decode video frames and receive audio bytes with positive audio
energy. Selected candidates must be relay candidates at both ends with
the requested relay protocol. HTTP and signalling are restricted to local
fixtures; generated camera frames and an oscillator are the only media.

The default run qualifies UDP, plain TCP and TLS separately in Chromium.
KithMoot's explicit device relay path preserves plain TCP where the browser
supports it. WebKit rejects that URI and needs UDP or TLS alternatives;
this Chromium run does not qualify WebKit. The app's legacy same-origin
credential resolver has different filtering rules and is not the path
tested here. spry-turn's independent
[socket and browser suites](../CONTRIBUTING.md) also cover all three server
transports. The invitation is checked to exclude the device's username and
credential.

The runner stops its servers and browser processes, including on failure,
and removes its temporary build and credentials. The requested JSON
receipt contains counters and digests, without room invitations, TURN
credentials, addresses or machine paths. Keep raw failure logs private:
browser error messages can include a room invitation.

## What this proves

This is real web application and server interoperability on one machine.
It exercises KithMoot's explicit relay Settings, room signalling, media
controls, peer negotiation and decoded media through spry-turn. Browser
TLS uses an explicit test-certificate bypass. It establishes neither
trusted public certificate validation nor cross-network reachability.

spry-turn does not add an HTTP credential issuer, a publisher-operated
service or a hosted default. The operator generates short-lived credentials
locally and distributes those to their clients. This fixture qualifies the
identified web source and executable, rather than every released KithMoot
client or an unrelated public deployment.

## Choose an operator on each device

The KithMoot web source at
[`24038110`](https://github.com/forgesworn/kithmoot/commit/24038110cd4a60037b5e3f6a6c0131af65478102)
provides Relay addresses, Relay username and Relay password under
Settings → Connections. Enter the TURN URLs alongside the credential
minted for that operator, then leave and reopen the room. The device
choice takes precedence over the room's ICE URL hints. Credentials remain
on the device and are omitted from invitations. Never put the shared TURN
secret into a client, room link or descriptor.

The older room ICE field carries URLs alone; it is insufficient to provide
a TURN username and password. Use the explicit call-relay Settings rather
than treating that field as a credential mechanism.

Android source at
[`c0ad53b2`](https://github.com/forgesworn/kithmoot-android/commit/c0ad53b20fa3ed50900bf672916d3aa458634c05)
also has explicit per-device `CallRelayConfig`, with credentials associated
only with the saved URLs. Its relay-only resolver returns no relay when
none is configured. That source inspection is separate from executing a
native call against spry-turn; no Android binary was changed or tested by
this runner.

Existing coturn accounts using persistent usernames and passwords cannot
be reused unchanged: spry-turn currently supports shared-secret REST
credentials. Keep a working private coturn instance until clients have
chosen and accepted a separate spry-turn instance with its own credentials.

Expiring credentials need operator renewal. These device Settings do not
establish an automatic renewal service. Qualify the standing-call,
credential replacement and reconnect behaviour before relying on long
sessions. Room membership and identities remain separate from transport
credential issuance.

## Independent deployment and GrapheneOS gate

Before replacing an existing TURN deployment, test a separately chosen
operator with the [firewall, NAT and certificate plan](operations.md).
Use two different access networks and trusted certificates. Force each
client transport in turn, confirm the actual selected relay pair and
bidirectional displayed media, then repeat with client UDP blocked.
Keep relay-to-peer UDP available: TURN over TLS does not change that leg.

On a physical GrapheneOS device without sandboxed Google Play, configure
the operator in the actual native client. Verify native/web media in both
directions, network changes, a standing call
through allocation and credential renewal, reconnect and explicit expiry
failure. Check that unavailable credentials never silently defeat a
relay-only choice. Record the installed package identity, selected
transport and sanitised counters independently from browser evidence.

No Android device was attached during this source inspection. The existing
native browser interoperability instrumentation is emulator-only; do not
run it on a person's physical phone. Native compilation, emulator checks
and physical GrapheneOS acceptance are distinct gates, and none is supplied
by this web runner. Archy installation follows standalone acceptance.
