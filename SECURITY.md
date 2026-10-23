# Security policy

spry-turn 0.1.0 is an initial implementation. It has local socket/browser
verification and bounded parsing/state, but no independent security audit
or production qualification. See [verification](docs/verification.md) and
[remaining work](GOALS.md).

## Report a vulnerability

The repository is private and no public security inbox is promised. Ask a
maintainer for an agreed private reporting channel using a minimal
access-controlled issue. Do not include an exploit, credential, production
endpoint, private media or personal information in that initial request.
Share the detailed report only through the channel the maintainer confirms.
No response-time guarantee is offered.

For an ordinary synthetic bug report, see [support](SUPPORT.md).

## Boundaries

- The shared TURN secret belongs only to an operator's trusted server or
  credential tool; short-lived usernames/passwords go to clients.
- Nonces, integrity checks, peer policy, allocation expiry and resource
  limits protect transport state. They do not enforce room membership.
- Client TLS ends at the relay. Payload confidentiality depends on the
  endpoint protocol; arbitrary TURN traffic is not automatically opaque.
- Loopback peers require explicit local-test configuration. Do not expose
  a relaxed private-address proxy to untrusted clients.
- The default connected-UDP optimisation costs an extra socket per UDP
  allocation. Bound process descriptors as well as logical allocations.
- WASM framing does not provide network I/O, allocation authorisation or
  permission checks for a host-supplied adapter.

Do not assume unsupported coturn extensions or operational controls exist.
Use [the compatibility map](docs/coturn-compatibility.md) before evaluation.
