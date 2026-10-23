// Exercise the actual browser observer before native constructors start traffic.
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { readFileSync } from 'node:fs';
import vm from 'node:vm';

const source = readFileSync(new URL('./kithmoot.mjs', import.meta.url), 'utf8');
const start = source.indexOf('function installDeviceObservers(');
const end = source.indexOf('\nasync function device()', start);
assert(start >= 0 && end > start, 'Actual device observer function is missing');
const observer = source.slice(start, end);
const owner = { urls: ['turn:127.0.0.1:12345?transport=udp'],
  username: `${Math.floor(Date.now() / 1000) + 60}:generated-guard`,
  credential: randomBytes(32).toString('base64') };

function install(ownerIce) {
  const constructions = [], changes = [];
  class NativePeer {
    constructor(config) { constructions.push(config); }
    setConfiguration(config) { changes.push(config); }
  }
  const context = vm.createContext({ URL, window: { RTCPeerConnection: NativePeer, WebSocket: class {} },
    localStorage: { setItem() {} }, navigator: { mediaDevices: { getUserMedia() {} } } });
  vm.runInContext(observer, context);
  context.installDeviceObservers({ relay: 'ws://127.0.0.1:12346', ownerIce });
  return { Peer: context.window.RTCPeerConnection, constructions, changes };
}

const fixture = install(owner);
const configuration = (urls = owner.urls, fields = {}) => ({ iceTransportPolicy: 'relay',
  iceServers: [{ urls, username: owner.username, credential: owner.credential, ...fields }] });
let checks = 0;
for (const config of [configuration(owner.urls[0]), configuration(),
  configuration(owner.urls, { credentialType: 'password' }),
  { iceTransportPolicy: 'relay', iceServers: [{ urls: 'stun:127.0.0.1:12345' }, ...configuration().iceServers] }]) {
  new fixture.Peer(config);
  assert(fixture.constructions.at(-1) === config, 'Observer must pass the original configuration through');
  checks++;
}
const externalTurn = configuration('turn:relay.invalid:3478?transport=udp');
for (const config of [externalTurn,
  { ...configuration(), iceTransportPolicy: 'all' },
  { ...configuration(), iceServers: [] },
  configuration(owner.urls, { username: 'different generated user' }),
  configuration(owner.urls, { credential: randomBytes(32).toString('base64') }),
  configuration(owner.urls, { credentialType: 'oauth' }),
  { ...configuration(), iceServers: [...configuration().iceServers, { urls: 'stun:relay.invalid:3478' }] },
  { ...configuration(), iceServers: [...configuration().iceServers, ...configuration().iceServers] },
  { ...configuration(), iceServers: [null] },
  { ...configuration(), iceServers: [...configuration().iceServers, { urls: 'stun:127.0.0.1:12345', credential: owner.credential }] }]) {
  const before = fixture.constructions.length;
  assert.throws(() => new fixture.Peer(config), /Application (ICE configuration|did not select relay-only ICE)/);
  assert(fixture.constructions.length === before, 'Rejected configuration reached the native constructor');
  checks++;
}

const active = new fixture.Peer(configuration());
const updated = configuration(owner.urls[0]);
active.setConfiguration(updated);
assert(fixture.changes.at(-1) === updated, 'Accepted reconfiguration must pass its original object through');
const before = fixture.changes.length;
assert.throws(() => active.setConfiguration(externalTurn), /Application ICE configuration/);
assert(fixture.changes.length === before, 'Rejected reconfiguration reached the native connection');
checks += 2;

const mixedOwner = { ...owner, urls: [...owner.urls, 'turns:127.0.0.1:12346?transport=tcp'] };
const mixed = install(mixedOwner);
const mixedConfig = { iceTransportPolicy: 'relay', iceServers: [...mixedOwner.urls].reverse().map(urls =>
  ({ urls, username: owner.username, credential: owner.credential })) };
new mixed.Peer(mixedConfig);
assert(mixed.constructions.at(-1) === mixedConfig, 'URL order or string/array representation changed acceptance');
checks++;
console.log(`KithMoot ICE observer: ${checks} configuration checks passed`);
