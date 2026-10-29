# spry-turn

A small packet relay. Keep protocol adapters separate from forwarding and
resource limits. WebRTC, SRT, media codecs and media packaging are not runtime
dependencies. Transparent UDP is for an explicitly configured upstream;
TURN is optional. Do not silently turn either into an open arbitrary proxy.

- British English. MIT. Commit as TheCryptoDonkey with a GitHub no-reply email.
- The owner authorised public MIT source and the existing GitHub prereleases
  on 23 October 2026. Package registries, images, Pages and a hosted relay
  remain separate scope; do not add them without the owner's instruction.
- No real endpoints, credentials, private source, media or machine paths in
  committed evidence. Fixtures must be generated locally.
- `unsafe` is forbidden in our code, with one exception: the foreign-function
  boundary in `crates/spry-ffi` (`capi.rs` and `jni.rs` only), where every
  unsafe block states why it is sound. Every other crate keeps
  `unsafe_code = "forbid"`. Keep dependency features small.
- Use this checkout's `target/`. Leave `CARGO_INCREMENTAL` unchanged.
- Test outside-input parsing, authentication, permissions, state expiry and
  overload. Performance claims require reproducible socket measurements.
- Run fmt, clippy, tests, minimal-feature builds, interop and secret scanning.
- Stop task-owned servers and remove generated private fixtures afterwards.
