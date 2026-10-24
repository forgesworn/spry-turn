# spry-link

Small, bounded Spry transport messages with no sockets, runtime, Archipelago
or media dependencies. MIT, alongside the other Spry libraries.

`control` pins a service identity and 1–4 owner-selected Nostr relays in a
`spry://` URI. Requests and replies are signed NIP-01 events with NIP-44 v2
encryption, addressed recipients, request correlation and a 30-second expiry.
Only pairing claims, self-removal, grants, credentials and peer registration
are allowed. Owner administration remains a separate host-authenticated API.
No default relay list or public directory is included.

`peer` signs short-lived cards for one IPv6 ULA TCP service on port 3745,
proves both node identities against fresh connection challenges, and frames
bounded encrypted datagrams with directional session keys and strict counters.
`registry` applies complete scope-owned allowlists atomically, expires cards,
refuses stale updates and collisions, and remembers withdrawal revisions
through the control replay window. Hosts authenticate the scope owner first.

Cryptographic primitives come from libsecp256k1, HKDF, SHA-256, HMAC and
ChaCha20 dependencies. The protocol glue is ours; no Nostr SDK, codec or
WebRTC engine is included. The native forwarding core imports none of this.

The optional `spry-service` adapters supply sockets, authentication policy,
resource bounds and lifecycle. A host can use another adapter or transport.
The Archipelago package uses its existing OS mesh route; this library has no
FIPS dependency.

Run `cargo test -p spry-link`. `cargo run -p spry-link --example vectors`
generates synthetic wire fixtures for independent clients. The checked-in
fixtures contain generated identities only.
