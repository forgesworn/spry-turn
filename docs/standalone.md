# Standalone Spry and reusable libraries

Spry is a standalone ForgeSworn product. Its libraries and service are usable
without Archipelago. Other ForgeSworn products consume the same libraries;
Archipelago packages that product for its node owners.

| Component | Responsibility |
|---|---|
| `spry-turn` | Bounded packet forwarding, TURN authentication and protocol codecs; native library and standalone relay executable |
| `spry-access` | Owner-authorised pairing, scoped grants, short-lived credentials and private state; no network runtime |
| `spry-service` | Reusable HTTP host adapter and standalone `spry-node` executable; supplied UI assets and explicit owner configuration |
| Archipelago package | Installation, node-supplied owner identities, host certificates, permissions and an optional dashboard signing provider |
| Calling application | Pairing consent, room membership, media keys, credential renewal and call controls |

The relay never imports the access service or Archipelago. The service uses
the access library and supervises the separate native relay executable.
Hosts can also embed the relay directly. Shared library configuration has no
hard-coded KithMoot origin allowlist; each host supplies its intended calling
application and any extra permitted origins. The standalone UI uses the
owner's existing NIP-07 signing extension. Archipelago can supply its own
signing-provider assets through the host adapter.

Build both standalone executables:

```sh
cargo build --locked --release --workspace --features tls
```

For the pairing service, supply `SPRY_PUBLIC_URL` (its HTTPS origin),
`SPRY_OWNER_KEYS` (comma-separated owner public keys), `SPRY_TURN_SECRET`
(at least 32 bytes) and `SPRY_RELAY_IP` (the relay's reachable IPv4 address).
Set `SPRY_STATE_FILE` to a private persistent file and, if needed,
`SPRY_KITHMOOT_URL` to the intended calling application's HTTPS URL.
`SPRY_ALLOWED_ORIGINS` explicitly adds HTTPS origins for other clients.

`spry-node` listens on loopback HTTP port 3744 behind the operator's HTTPS
reverse proxy. It finds `spry-turn` beside itself; `SPRY_RELAY_BINARY`
overrides that location. Standard TURN listeners and the bounded peer range
are described in the [operator guide](operations.md). Optional certificate
files for the relay reside under `/data/tls`; an external host adapter can
instead terminate TURN TLS. Setting `SPRY_TLS_GATE=true` advertises that
host's configured TLS transport and does not start or configure a TLS proxy.

No Archipelago daemon, node identity store, dashboard, container runtime or
FIPS installation is required for this standalone path. A reachable relay
and valid HTTPS still require operator configuration. Automatic operation
between two home-network nodes remains unfinished and must be demonstrated
with the VPS absent before that experience can be called delivered.

Networking integrations belong behind optional adapters. An Archipelago
adapter uses its existing mesh and host facilities; reusable improvements to
those facilities can be proposed upstream. Other hosts can supply a different
transport without importing Archipelago into Spry's forwarding or access
libraries.

Within Archipelago, the app manager owns package installation and lifecycle,
the existing identity/signing layer approves owner operations, the app gate
owns its HTTPS integration, and the networking layer owns mesh connectivity.
Those are the integration points for the relevant library or thin adapter.
Each library retains its own narrow purpose and independent build; installing
the package does not transfer those host responsibilities into Spry.

Git dependencies use a reviewed full commit SHA; see the
[access library](../crates/spry-access/README.md) and
[native embedding guide](integration.md#embed-the-native-rust-server).
No new package registry publication is implied by these libraries.
