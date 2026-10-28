# spry-access

An MIT Rust library for owner-authorised pairing, scoped relay grants and
short-lived TURN credentials. ForgeSworn applications and Archipelago
packages use the same authority implementation.

The host supplies owner public keys, the pairing application's HTTPS URL,
the relay endpoint and a private TURN secret. It schedules state expiry and
calls the library after applying its own transport limits. There is no HTTP
server, async runtime, mesh daemon, application directory or default relay
in this crate. Configured origins are limited to the supplied endpoint and
application; the host explicitly adds any further permitted origins.

Use a reviewed full commit when consuming the source:

```toml
[dependencies]
spry-access = { git = "https://github.com/forgesworn/spry-turn.git", rev = "REVIEWED_COMMIT_SHA" }
```

`Config::new` validates configuration. `Authority::authenticate` verifies
the signed request's method, URL, body, timestamp and nonce;
`Authority::handle` applies pairing and grant permissions. A transport
adapter must authenticate every outside request before dispatching it.
The host serialises access to an authority and supplies Unix time.
`Authority::restore` loads private state when persistence is configured;
`Authority::sweep` expires transient state. State writes are atomic and
private on supported Unix hosts.

A paired app may register the signing keys that may redeem a room grant and
seal the grant, so a leaked grant token is useless without a registered key.
`Config::seal` (`Seal::Auto`, `Required` or `Off`) decides when a grant
enforces its list. Registered keys persist with the grant in the same
version 1 state file; an older binary ignores them and loads every grant
unsealed.

Pairing links and grants use the existing version 1 Spry wire format.
Room admission and media keys remain the calling application's concern.
The current endpoint profile requires HTTPS; home-network mesh integration
is separate unfinished work. This extraction does not establish public
network, independent-node or physical-phone acceptance.

Validate from the repository root with `cargo test --locked -p spry-access`.
The integration suite exercises signed requests, replay rejection, owner
permissions, single-use pairing, expiry, renewal, revocation, persistence,
room-grant registration, vouching, sealing modes and overload bounds using
generated fixtures.
