# spry-turn

A small packet relay. Keep protocol adapters separate from forwarding and
resource limits. WebRTC, SRT, media codecs and media packaging are not runtime
dependencies. Transparent UDP is for an explicitly configured upstream;
TURN is optional. Do not silently turn either into an open arbitrary proxy.

- British English. MIT. Commit as TheCryptoDonkey with a GitHub no-reply email.
- This repository starts private. Do not publish packages, images, releases,
  pages or public repositories without the owner's instruction.
- No real endpoints, credentials, private source, media or machine paths in
  committed evidence. Fixtures must be generated locally.
- `unsafe` is forbidden in our code. Keep dependency features small.
- Use this checkout's `target/`. Leave `CARGO_INCREMENTAL` unchanged.
- Test outside-input parsing, authentication, permissions, state expiry and
  overload. Performance claims require reproducible socket measurements.
- Run fmt, clippy, tests, minimal-feature builds, interop and secret scanning.
- Stop task-owned servers and remove generated private fixtures afterwards.
