# Getting started

This guide runs a local standalone server. It does not expose a public
relay or require a hosted service. See [operations](operations.md) before
configuring an independently operated instance.

## Obtain the source

The repository is private. Use an authorised GitHub account and SSH key:

```sh
git clone git@github.com:forgesworn/spry-turn.git
cd spry-turn
```

Source is the portable installation path. Cargo and npm publication are
disabled. The private v0.1.0 GitHub prerelease also carries a macOS ARM64
TLS-enabled executable archive and a WASM codec archive. It does not make
the source or artefacts publicly downloadable. Authorised users can fetch
and verify the archives in an empty directory:

```sh
gh release download v0.1.0 --repo forgesworn/spry-turn
shasum -a 256 -c SHA256SUMS
```

The macOS executable is not a Linux, Windows or phone build. A release
does not establish production or physical-device acceptance. The source
build below remains available for other supported native environments.

Rust 1.85 or newer is declared; Rust 1.94.1 and 1.96 were used for the
initial verification and native M4 measurements. Current CI checks stable
Rust on Linux and macOS. Python 3, Node 24, OpenSSL and Chromium are test
tools, not server runtime dependencies.

## Build and start

```sh
cargo build --locked --release
export SPRY_TURN_SECRET="$(openssl rand -hex 32)"
./target/release/spry-turn serve
```

The process binds UDP and TCP at `127.0.0.1:3478`. Keep this terminal running;
stop it with Ctrl-C. The secret must contain at least 32 bytes. This example
generates a fresh one; a real operator must store and supply their chosen
secret consistently across restarts and credential generation.

The server blocks loopback peers by default, even when its listener is
local. The following explicit local-test mode allows two local ICE clients
to send traffic through it:

```sh
./target/release/spry-turn serve --allow-loopback-peers
```

Stop the first server before starting the second command on the same port.
Loopback-peer testing is restricted to a loopback-only listener and is
unnecessary for normal public-address peers.

## Generate client credentials

Use the same secret in a separate shell or generate the credential before
starting the server:

```sh
./target/release/spry-turn credential --ttl 3600 --label client
```

The command emits JSON with `username` and `credential`. TTL is 1–86,400
seconds. Labels are 1–64 ASCII letters, digits, hyphens or underscores.
Use an opaque transport label rather than a room name or identity.

Give the client that short-lived pair through an operator-controlled
channel. The client must never receive `SPRY_TURN_SECRET`. Credential output
is sensitive; do not paste it into an issue, log or committed fixture.
See [integration](integration.md) for ICE configuration.

## Optional TLS

```sh
cargo build --locked --release --features tls
./target/release/spry-turn serve --tls-listen 127.0.0.1:5349 \
  --tls-cert certificate.pem --tls-key private-key.pem
```

Provide your own PEM files and client-trusted certificate. The TLS listener
is additional to the UDP/TCP listener. This initial server does not renew
certificates or reload TLS files automatically.

## Check the installation

```sh
./target/release/spry-turn --version
./target/release/spry-turn --help
python3 tests/interop.py --tls
```

The socket suite starts its own loopback server instances, generated secret
and temporary TLS fixtures, then removes them. Build with `--features tls`
before using `--tls`. Browser and WASM validation commands are in
[contributing](../CONTRIBUTING.md).

If allocation succeeds but media does not arrive, check peer policy, UDP
relay reachability and credentials before changing client transports.
The [operations guide](operations.md) explains the current firewall and
relay-port limitations.
