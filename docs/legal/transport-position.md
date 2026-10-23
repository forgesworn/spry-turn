# Packet transport position

Draft, 23 October 2026. Not legal advice; not reviewed by a lawyer. This is
a design position for the local implementation, not a deployment or
compliance assessment. The reviewed source is identified by file hashes in
the [source manifest](../evidence/source-manifest.json).

The legal source is jurisdiction-kit's [GB online-services
note](https://github.com/forgesworn/jurisdiction-kit/blob/main/law/gb/online-services.md),
verified overall on 28 September 2026 and due for review by 28 March 2027.
The local note includes partial primary-source checks dated 23 October
2026 for transport access facilities, public communications providers and
investigatory powers; those additions may precede the linked public copy.
`[P]` means primary text read in that note, not a settled application.
`[U]` means an unresolved interpretation or application to this design.

## Position today and intended operation

The owner has chosen software publication without a maintainer-operated
default relay or central KithMoot calling entitlement. The repository starts
private, under MIT, with package publication disabled (`Cargo.toml:6`, `:14`).
The owner reports local implementation and tests only: no service is
deployed. Code publication, a build and a running communications service
are separate events. No public operational service is established by the
presence of server source.

The intended deployment is a standalone, coturn-style TURN server on an
independently operated Archy node. KithMoot would select it through ordinary
TURN configuration. Local KithMoot web interoperability is now qualified
with owner-selected credentials and no credential-service request; see the
[application receipt and limits](../kithmoot-acceptance.md). Archy packaging,
actual operator independence, cross-network and physical-device acceptance
remain unproved. Sapflow support is a later optional goal.
Nothing here changes another application's deployment or legal position.

## Implemented boundary

The library's default listener is loopback; the executable requires an
operator-provided secret and explicit configuration to expose another
address (`src/turn.rs:186`, `src/main.rs:54`, `:82`). There is no runtime
hosted endpoint default or discovery lookup. The source has no application
room model, member directory, room-invitation authority or KithMoot
entitlement issuer. TURN resource authentication is separate from admission
to an application conversation. The REST credential
helper accepts an operator secret and a username, while server nonces bind
to address, time and realm (`src/auth.rs:13`, `:29`, `:54`, `:73`). An operator
that holds the secret can issue transport credentials; that fact does not give
it room membership authority (`src/turn.rs:937`).

Allocation, permission, channel and connection state is held in memory,
with expiry and capacity limits (`src/turn.rs:265`, `:433`, `:867`, `:1134`,
`:1170`, `:1358`, `:1369`). The forwarding paths relay datagrams between sockets
and keep aggregate packet/byte/drop counters (`src/turn.rs:977`, `:1427`,
`:1461`; `src/limits.rs:41`). The default optimisation can add a connected
client-facing UDP socket per authenticated UDP allocation for a concrete IPv4
listener on Unix, with a portable fallback (`Cargo.toml:17`, `:23`;
`src/turn.rs:477`, `:1172`). This retains the same transport credentials,
permissions and application-admission boundary. The reviewed code has no
payload-recording or per-client access-log writer. It emits startup/error diagnostics, and the
credential subcommand deliberately prints a credential pair
(`src/main.rs:36`, `:119`, `:152`). Host logs, shell history, process
inspection, crash handling and any service wrapper require a separate
deployment audit; in-memory expiry is not a forensic-erasure claim.

The relay handles network addresses, credential identifiers, permissions,
connection state and forwarded datagram bytes. It is not an end-to-end
media encryption implementation. Payload confidentiality depends on the
endpoints and application protocol. TLS terminates at the relay, which can
inspect the forwarded bytes after that link's protection is removed.
Use opaque transport-only credential labels: do not encode room identities
or personal identifiers merely for relay authentication.

## Legal reasoning and change boundary

The note's sections 1 and 2.2 distinguish software publication from service
operation. For the intended independent node, OSA section 226(12)'s
access-facility distinction exists `[P]` (note 2.11). Applying it to this
TURN deployment, separately from the underlying call service and its
admission authority, remains `[U]`. Replaceable, room-blind transport and
real independence support that distinction; encryption, a separate process
or a licence alone do not establish an exemption. Ordinary room invitations
are not automatically operation of the underlying service `[U]` (note 2.2).

A running node's metadata processing and any public forwarding need their
own conditional data-protection, communications and lawful-notice assessment
(note sections 3, 4.1, 5 and 7); this publisher position does not settle those
roles or promise immunity from legal process.

Before adopting the Archy deployment, confirm its actual operator,
credential control, independent substitution and separation from room
admission. Adding maintainer-run defaults, compulsory calling entitlements,
room control, discovery or media processing requires a fresh assessment.
Do not silently make ordinary client installations transit nodes. No
service-launch deadline or fee is assigned by this local publisher-only
assessment.

Not checked: non-UK law; actual Archy/KithMoot/Sapflow integration; live
infrastructure; real-device acceptance; or a complete public relay operator
assessment.
