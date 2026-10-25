# Pair Spry with the installed KithMoot app

Open Spry and choose **Pair with KithMoot**. Approve the request using your
node's existing owner signer. Spry then shows **Open KithMoot app** and
**Copy pairing link**. Choose the app where you are already signed in.
There is no need to sign into KithMoot again in Safari.

The copy button produces a `kithmoot://join#spry=…` link. If clipboard access
is refused, the complete link is selected for ordinary Copy. In KithMoot
versions with link import, paste it in **Settings → Connections → Spry** and
choose **Pair Spry**. The existing link handler also opens the installed app.
Browser pairing remains an explicit alternative.

The link is a private, short-lived, single-use capability. It stays in the
fragment and in memory, is cleared from the owner screen when expired or
departing, and is never passed to a hosted QR service. Copying or opening the
handoff does not claim it. KithMoot still validates it, shows the node and
requires confirmation before its normal pairing request.

Foregather remains a suitable separate adapter for encrypted invitation
transfer and short-code pairing on an owner's infrastructure. Its existing
public handoff profile carries a locator with a separate secret; it is not
the Spry capability-link format. This copy/paste flow preserves Spry's wire
format, node authorisation, one-use enforcement and account-sync boundary.
It introduces no resolver, directory or publisher-run service.
