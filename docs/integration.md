# Client and host integration

TURN is an optional transport choice in the calling application. The
application or independent operator selects the server and supplies a
short-lived credential pair. spry-turn supplies neither room admission
nor a hosted credential endpoint.

## Browser WebRTC

Use the browser's existing ICE implementation. This example takes a
credential pair already supplied by the selected operator:

```js
function relayConnection({ username, credential }) {
  return new RTCPeerConnection({
    iceServers: [{
      urls: [
        'turn:relay.example:3478?transport=udp',
        'turn:relay.example:3478?transport=tcp',
        'turns:relay.example:5349?transport=tcp',
      ],
      username,
      credential,
    }],
    iceTransportPolicy: 'relay',
  });
}
```

`relay.example` is a placeholder, not an included service. Only list
transports the operator has enabled and made reachable. `relay` forces
TURN for qualification; choose `all` if the application should also try
direct ICE paths. Media tracks, data channels, SDP exchange, consent,
end-to-end encryption and reconnect policy stay with the application.

The `transport=tcp` URLs describe client-to-server transport. The current
server still uses UDP allocations towards the peer. This is different
from TCP relay allocations under RFC 6062, which are not implemented.

The shared server secret must never be bundled into JavaScript, WASM, a
mobile app, a join URL or a browser storage entry. The WASM credential
helper is for trusted operator tools; it does not make exposing the secret
to clients safe.

## Native TURN clients

Existing native WebRTC clients can use the same ICE URLs, username and
password through their platform's ICE configuration. They do not need to
embed this library to use the server. Physical iOS, Android and no-Play
GrapheneOS acceptance against this implementation remain unverified.

## Embed the native Rust server

Rust applications can depend on the public Git repository.
Use a reviewed full commit SHA in place of `REVIEWED_COMMIT_SHA`:

```toml
[dependencies]
spry-turn = { git = "https://github.com/forgesworn/spry-turn.git", rev = "REVIEWED_COMMIT_SHA" }
```

The following host starts a local server and advances its event loop:

```rust
use spry_turn::turn::{Config, Server};
use std::{io, time::Duration};

fn main() -> io::Result<()> {
    let secret = std::env::var("SPRY_TURN_SECRET")
        .map_err(io::Error::other)?
        .into_bytes();
    let mut server = Server::bind(Config::local(secret))?;
    loop {
        server.poll_once(Duration::from_secs(1))?;
    }
}
```

The host owns scheduling, shutdown and credential storage. No worker
thread starts automatically. Drop the server to close its sockets. Use a
dedicated host thread if the surrounding application cannot block in
`poll_once`; Swift/Kotlin bindings are future work. Configuration fields
and feature combinations are listed in [the API reference](api.md).

## Browser WASM packet codec

Build the module and glue using [the API commands](api.md#wasm-build).
Serve these files through the embedding application's existing asset
pipeline; there is no project-operated CDN.

```js
import init, { PacketArena } from './spry_turn.js';

const wasm = await init();
const arena = new PacketArena(2048);
let bytes = new Uint8Array(wasm.memory.buffer, arena.ptr(), arena.capacity());
const payload = new TextEncoder().encode('hello');
bytes.set(payload, 4);
if (!arena.frame_channel(0x4000, payload.length)) {
  throw new Error('packet does not fit');
}
const length = payload.length + 4;
if (arena.channel_payload_len(length) !== payload.length) {
  throw new Error('invalid channel packet');
}
// Consume or send bytes.subarray(0, length) before reusing or freeing the arena.
// Recreate bytes after any WebAssembly memory growth.
arena.free();
```

Framing a packet does not create a TURN allocation or authorise channel
`0x4000`. A host adapter must implement session control and supply actual
I/O. Ordinary browser WASM cannot open the raw UDP/TCP sockets needed to
host a standard TURN server. The codec is useful for protocol adapters and
tests; it does not replace browser WebRTC.

## KithMoot, Archy and Sapflow

KithMoot may point its normal TURN client at an independently selected
instance. An Archy owner may later install and operate that server;
packaging, exposure policy and integration are not implemented here yet.
The publisher operates no default relay, directory or credential service.

Sapflow or another non-WebRTC application would need a TURN-aware transport
adapter. Standard TURN can carry arbitrary datagrams, but unmodified SRT
or RTMP clients do not become TURN clients by changing a destination URL.
No codecs, SRT, RTMP or HLS stack is included.
