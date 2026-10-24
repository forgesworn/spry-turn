// Actual standalone pairing and KithMoot media across two isolated Linux nodes.
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { execFileSync } from 'node:child_process';
import { once } from 'node:events';
import { createRequire } from 'node:module';
import { resolve, join, extname, sep, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { readFile, writeFile, mkdtemp, rm, mkdir, copyFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { randomBytes, createHash } from 'node:crypto';
const args = Object.fromEntries(process.argv.slice(2).reduce((pairs, value, i, values) => i % 2 ? pairs : [...pairs, [value, values[i + 1]]], []));
const root = resolve(args['--kithmoot']), binary = resolve(args['--node-binary']), output = resolve(args['--output']);
const nodeCount = Number(args['--nodes'] ?? 2), standingSeconds = Number(args['--standing-seconds'] ?? 0);
assert(nodeCount === 2 || nodeCount === 3); assert(standingSeconds >= 0 && standingSeconds <= 420);
const fixture = dirname(fileURLToPath(import.meta.url));
const require = createRequire(join(root, 'package.json'));
const { chromium } = require('@playwright/test');
const { finalizeEvent, generateSecretKey, getPublicKey } = require('nostr-tools/pure');
const scratch = await mkdtemp(join(tmpdir(), 'spry-home-'));
// Immutable input: a concurrent build must not change the executable under test.
const snapshot = join(scratch, 'spry-node'); await copyFile(binary, snapshot);
const binarySha256 = createHash('sha256').update(await readFile(snapshot)).digest('hex');
const contextName = execFileSync('docker', ['context', 'show'], { encoding: 'utf8' }).trim();
const docker = (...args) => execFileSync('docker', ['--context', contextName, ...args], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'], timeout: 15000 });
const label = 'spry-home-' + randomBytes(5).toString('hex'), network = label + '-net';
const image = 'python@sha256:a0f57064cbdcd6285fa45f51237ab0b35ea8ebaed06a1f5973e89e19dfb86704';
const prefix = `fd${randomBytes(1).toString('hex')}:${randomBytes(2).toString('hex')}:${randomBytes(2).toString('hex')}:1`;
const names = [], contexts = [], diagnostics = [];
let browser, appServer, networkCreated = false, phase = 'starting';
function mark(value) { phase = value; process.stdout.write(`Home-node acceptance: ${value}\n`); }
async function port() { const server = createServer(); server.listen(0, '127.0.0.1'); await once(server, 'listening'); const port = server.address().port; await new Promise(resolve => server.close(resolve)); return port; }
async function wait(read, test, label, ms = 60000) {
  const until = Date.now() + ms;
  while (Date.now() < until) { try { const value = await read(); if (test(value)) return value; } catch {} await new Promise(resolve => setTimeout(resolve, 100)); }
  throw new Error(label);
}
async function media(page) {
  if (await page.locator('#deviceControls').isHidden()) {
    await page.locator('#callToggle').waitFor({ state: 'visible' });
    await page.locator('#callToggle').click();
  }
  await page.locator('#deviceControls').waitFor({ state: 'visible' });
  for (const id of ['#toggleCamera', '#toggleMic']) {
    if (await page.locator(id).getAttribute('data-on') !== 'true') await page.locator(id).click();
    await wait(() => page.locator(id).getAttribute('data-on'), value => value === 'true', 'Generated capture did not start');
  }
  // The product pauses off-page gallery sinks. Select its full gallery so
  // this transport check deliberately measures every remote camera.
  await page.locator('#callExtras').click();
  await page.locator('#callMoreMenu [role="menuitem"]').filter({ hasText: /^\s*Layout\s*$/ }).click();
  await page.locator('#callMoreMenu .menuSub:not([hidden]) [role="menuitemradio"]').filter({ hasText: /^\s*Gallery\s*$/ }).click();
}
async function evidence(page) {
  return page.evaluate(async () => {
    const pairs = [], media = { frames: 0, audioBytes: 0, audioEnergy: 0 };
    for (const pc of window.__spryPcs ?? []) {
      if (pc.connectionState !== 'connected') continue;
      const stats = await pc.getStats();
      stats.forEach(stat => {
        if (stat.type === 'candidate-pair' && stat.state === 'succeeded' && stat.nominated) pairs.push({ local: stats.get(stat.localCandidateId)?.candidateType, remote: stats.get(stat.remoteCandidateId)?.candidateType });
        if (stat.type === 'inbound-rtp' && stat.kind === 'video') media.frames += stat.framesDecoded ?? 0;
        if (stat.type === 'inbound-rtp' && stat.kind === 'audio') { media.audioBytes += stat.bytesReceived ?? 0; media.audioEnergy += stat.totalAudioEnergy ?? 0; }
      });
    }
    return { ...media, pairs, relayOnly: (window.__spryPcs ?? []).every(pc => pc.getConfiguration().iceTransportPolicy === 'relay'),
      videos: [...document.querySelectorAll('#room .participant video')].filter(video => video.videoWidth > 0 && !video.paused).length };
  });
}
async function joined(page, link, name) {
  await page.goto(link);
  await page.locator('#roomArea:visible, #join:visible, #displayName:visible').first().waitFor({ state: 'visible', timeout: 60000 });
  if (!await page.locator('#roomArea').isVisible()) {
    await wait(() => page.locator('#arrivalTitle').textContent(), text => !!text && text !== 'Opening your invite link' && text.includes('Generated'), 'Invite details did not load');
  }
  if (await page.locator('#displayName').isVisible()) await page.locator('#displayName').fill(name);
  if (await page.locator('#join').isVisible()) await page.locator('#join').click();
  await page.locator('#roomArea').waitFor({ state: 'visible', timeout: 60000 });
}
try {
  const relayPort = await port(), appPort = await port();
  const relay = `wss://relay.example:${relayPort}/`, appOrigin = `https://localhost:${appPort}`;
  const owners = Array.from({ length: nodeCount }, generateSecretKey);
  const controls = await Promise.all(owners.map(() => port())), turnPorts = await Promise.all(owners.map(() => port()));
  const endpoints = controls.map((port, index) => `https://node${index + 1}.example:${port}`);
  const tls = join(scratch, 'tls'); await mkdir(tls);
  await writeFile(join(tls, 'openssl.cnf'), '[req]\ndistinguished_name=dn\nx509_extensions=ext\nprompt=no\n[dn]\nCN=Spry generated fixture\n[ext]\nbasicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign\n');
  execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1', '-config', join(tls, 'openssl.cnf'), '-keyout', join(tls, 'ca.key'), '-out', join(tls, 'ca.pem')], { stdio: 'ignore' });
  execFileSync('openssl', ['req', '-newkey', 'rsa:2048', '-nodes', '-subj', '/CN=relay.example', '-keyout', join(tls, 'server.key'), '-out', join(tls, 'server.csr')], { stdio: 'ignore' });
  await writeFile(join(tls, 'server.ext'), 'subjectAltName=DNS:relay.example\nbasicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n');
  execFileSync('openssl', ['x509', '-req', '-in', join(tls, 'server.csr'), '-CA', join(tls, 'ca.pem'), '-CAkey', join(tls, 'ca.key'), '-CAcreateserial', '-days', '1', '-extfile', join(tls, 'server.ext'), '-out', join(tls, 'server.pem')], { stdio: 'ignore' });
  docker('network', 'create', '--ipv6', '--subnet', prefix + '::/64', network); networkCreated = true;
  assert.equal(JSON.parse(docker('network', 'inspect', network))[0].Internal, false);
  function run(name, options, script) {
    names.push(name);
    docker('run', '-d', '--name', name, '--network', network, '--read-only', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges',
      '--memory', '128m', '--cpus', '1', '--pids-limit', '64', '--tmpfs', '/tmp:size=8m',
      '--env', 'PYTHONDONTWRITEBYTECODE=1', '--mount', `type=bind,source=${fixture},target=/fixture/tests,readonly`,
      '--mount', `type=bind,source=${tls},target=/fixture/tls,readonly`, ...options, image, 'python3', '-u', '/fixture/tests/' + script);
  }
  const relayName = label + '-relay';
  run(relayName, ['--ip6', prefix + '::2', '-p', `127.0.0.1:${relayPort}:${relayPort}`, '--env', `FIXTURE_RELAY_PORT=${relayPort}`], 'control-relay.py');
  const relayIp = JSON.parse(docker('inspect', relayName))[0].NetworkSettings.Networks[network].IPAddress;
  for (let index = 0; index < nodeCount; index++) {
    run(label + '-node' + index, ['--ip6', prefix + '::' + (index + 3), '--add-host', 'relay.example:' + relayIp,
      '-p', `127.0.0.1:${controls[index]}:3844`, '-p', `127.0.0.1:${turnPorts[index]}:${turnPorts[index]}/tcp`, '-p', `127.0.0.1:${turnPorts[index]}:${turnPorts[index]}/udp`,
      '--mount', `type=bind,source=${snapshot},target=/fixture/spry-node,readonly`,
      '--env', 'SPRY_OWNER_URL=' + endpoints[index], '--env', 'SPRY_OWNER_KEYS=' + getPublicKey(owners[index]),
      '--env', 'SPRY_TURN_SECRET=' + randomBytes(32).toString('hex'), '--env', 'SPRY_KITHMOOT_URL=' + appOrigin + '/j/',
      '--env', 'SPRY_STATE_FILE=/tmp/pairings.json', '--env', 'SPRY_PEER_BIND=[' + prefix + '::' + (index + 3) + ']:3745',
      '--env', 'SPRY_TURN_PORT=' + turnPorts[index], '--env', 'SPRY_CLIENT_HOST=127.0.0.1', '--env', 'SPRY_LOCAL_TEST=true',
      '--env', 'SPRY_CONTROL_CA_FILE=/fixture/tls/ca.pem'], 'home-node.py');
  }
  for (const port of controls) await wait(() => fetch(`http://127.0.0.1:${port}/v1/status`).then(response => response.json()), state => state.ready === true && state.privateRelay === true, 'Private Spry did not start', 15000);
  mark('two actual standalone services ready');
  const dist = join(root, 'app/dist');
  appServer = createServer(async (request, response) => {
    try {
      const path = new URL(request.url, 'http://localhost').pathname.replace(/^\/j\//, '');
      const file = resolve(dist, path || 'index.html');
      if (!file.startsWith(dist + sep)) { response.writeHead(404).end(); return; }
      const types = { '.html': 'text/html', '.js': 'text/javascript', '.css': 'text/css', '.wasm': 'application/wasm', '.json': 'application/json', '.svg': 'image/svg+xml', '.png': 'image/png' };
      response.writeHead(200, { 'Content-Type': types[extname(file)] ?? 'application/octet-stream' }); response.end(await readFile(file));
    } catch { response.writeHead(404).end(); }
  });
  appServer.listen(appPort, '127.0.0.1'); await once(appServer, 'listening');
  browser = await chromium.launch({ headless: true, args: ['--use-fake-device-for-media-stream', '--use-fake-ui-for-media-stream', '--autoplay-policy=no-user-gesture-required', '--disable-audio-output', '--ignore-certificate-errors', '--disable-features=LocalNetworkAccessChecks', '--host-resolver-rules=MAP relay.example 127.0.0.1'] });
  async function device(index) {
    const context = await browser.newContext({ viewport: { width: 1920, height: 1080 }, permissions: ['camera', 'microphone'], ignoreHTTPSErrors: true, serviceWorkers: 'block' }); contexts.push(context);
    await context.exposeFunction('__sprySign', event => finalizeEvent(event, owners[index]));
    await context.addInitScript(({ relay }) => {
      if (location.hostname.startsWith('node')) window.nostr = { signEvent: event => window.__sprySign(event), getRelays: async () => ({ [relay]: { read: true, write: true } }) };
      if (location.hostname === 'localhost') {
        localStorage.setItem('kithmoot.relays.v1', JSON.stringify({ default: [{ url: relay, read: true, write: true }] }));
        localStorage.setItem('kithmoot.hide-ip.v1', '1'); localStorage.setItem('kithmoot.call.effectMode', 'off');
      }
      const Native = window.RTCPeerConnection; window.__spryPcs = [];
      window.RTCPeerConnection = class extends Native { constructor(config) { super(config); window.__spryPcs.push(this); } };
      const NativeSocket = window.WebSocket;
      window.WebSocket = class extends NativeSocket { constructor(url, protocols) { if (new URL(url).hostname !== 'relay.example') throw new Error('External signalling refused by fixture'); super(url, protocols); } };
      const gum = navigator.mediaDevices?.getUserMedia.bind(navigator.mediaDevices);
      if (gum) navigator.mediaDevices.getUserMedia = async config => {
        const stream = await gum(config);
        if (config.audio) {
          for (const track of stream.getAudioTracks()) { stream.removeTrack(track); track.stop(); }
          const audio = new AudioContext(), oscillator = audio.createOscillator(), output = audio.createMediaStreamDestination();
          oscillator.frequency.value = 440; oscillator.connect(output); oscillator.start(); await audio.resume();
          for (const track of output.stream.getAudioTracks()) stream.addTrack(track);
        }
        return stream;
      };
    }, { relay });
    await context.route('**/*', async route => {
      const request = route.request(), url = new URL(request.url());
      let mapped;
      if (url.origin === endpoints[index]) mapped = `http://127.0.0.1:${controls[index]}${url.pathname}`;
      else if (url.origin === appOrigin) mapped = `http://127.0.0.1:${appPort}${url.pathname}`;
      else { await route.abort(); return; }
      const headers = { ...request.headers() }; delete headers.host; delete headers['content-length'];
      const response = await fetch(mapped, { method: request.method(), headers, body: request.postDataBuffer() ?? undefined });
      await route.fulfill({ status: response.status, headers: Object.fromEntries(response.headers), body: Buffer.from(await response.arrayBuffer()) });
    });
    const page = await context.newPage();
    page.on('websocket', socket => {
      const wire = { device: index, websocket: new URL(socket.url()).hostname, sent: [], received: [], errors: [] }; diagnostics.push(wire);
      const note = (target, frame) => { try { const value = JSON.parse(String(frame.payload)); if (target.length < 64) target.push([value[0], value[1]?.kind ?? value[2]?.kind ?? null]); } catch {} };
      socket.on('framesent', frame => note(wire.sent, frame)); socket.on('framereceived', frame => note(wire.received, frame));
      socket.on('socketerror', error => wire.errors.push(String(error).slice(0, 200)));
    });
    page.on('pageerror', error => diagnostics.push({ device: index, error: error.stack }));
    page.on('console', message => { if (message.type() === 'error') diagnostics.push({ device: index, error: message.text().slice(0, 2000) }); });
    await page.goto(endpoints[index] + '/');
    await wait(() => page.locator('#pair').isEnabled(), Boolean, 'Pair button not ready');
    await page.getByRole('button', { name: 'Pair with KithMoot', exact: true }).click();
    await page.getByRole('button', { name: 'Pair Spry', exact: true }).click({ timeout: 30000 });
    await wait(() => page.locator('#spryPairingStatus').textContent(), text => text.includes('Paired with your Spry node'), 'Pairing not saved');
    assert.equal(new URL(page.url()).hash, '');
    return page;
  }
  const a = await device(0), b = await device(1); mark('both nodes paired through the actual UI');
  await a.locator('#newRoom:visible, #newMenuButton:visible').first().waitFor({ state: 'visible' });
  if (await a.locator('#newRoom').isVisible()) await a.locator('#newRoom').click();
  else { await a.locator('#newMenuButton').click(); await a.locator('#newMenuRoom').click(); }
  await a.locator('#roomName').fill('Generated home-node call');
  if (await a.locator('#newRoomYourName').isVisible()) await a.locator('#newRoomYourName').fill('Generated A');
  await a.locator('#create').click(); await a.locator('#roomArea').waitFor({ state: 'visible', timeout: 60000 });
  const link = await wait(() => a.locator('#shareUrl').inputValue(), value => value.includes('#'), 'Room link missing');
  await b.goto('about:blank');
  await joined(b, link, 'Generated B');
  await media(a); await media(b); mark('waiting for relay-only audio and video');
  const valid = value => value.frames > 0 && value.audioBytes > 0 && value.audioEnergy > 0 && value.videos >= 2 && value.pairs.length > 0 && value.pairs.every(pair => pair.local === 'relay' && pair.remote === 'relay') && value.relayOnly;
  const two = await Promise.all([a, b].map(page => wait(() => evidence(page), valid, 'Two-node media missing', 90000)));
  mark('two-node call passed without an external VPS');
  const active = [a, b];
  let group;
  if (nodeCount === 3) {
    const c = await device(2); await c.goto('about:blank'); await joined(c, link, 'Generated C'); await media(c); active.push(c);
    group = await Promise.all(active.map(page => wait(() => evidence(page), value => valid(value) && value.pairs.length >= 2 && value.videos >= 3, 'Three-node group media missing', 90000)));
    mark('three-node group call passed');
  }
  await b.reload(); await joined(b, link, 'Generated B'); await media(b);
  const finalValid = value => valid(value) && (nodeCount === 2 || value.pairs.length >= 2 && value.videos >= 3);
  const reloaded = await Promise.all(active.map(page => wait(() => evidence(page), finalValid, 'Reloaded two-node media missing', 90000)));
  mark('reloaded client restored its own relay routes');
  for (let elapsed = 0; elapsed < standingSeconds; elapsed += 15) await new Promise(resolve => setTimeout(resolve, Math.min(15, standingSeconds - elapsed) * 1000));
  const afterDeadline = await Promise.all(active.map(evidence));
  await new Promise(resolve => setTimeout(resolve, 3000));
  const standing = await Promise.all(active.map((page, index) => wait(() => evidence(page), value => finalValid(value) &&
    value.frames > afterDeadline[index].frames && value.audioBytes > afterDeadline[index].audioBytes && value.audioEnergy > afterDeadline[index].audioEnergy,
    'Fresh media stopped after the credential deadline', 30000)));
  await writeFile(output, JSON.stringify({ schema: 1, passed: true, scope: 'two-standalone-node-pairing-and-kithmoot-media',
    binarySha256, twoNetworkNamespaces: true, externalNetworkingDisabled: false,
    pairedThroughActualUi: true, injectedIceServers: false, externalVpsPresent: false, encryptedNostrControl: true, customCaValidatedByServices: true,
    relayOnly: true, nodeCount, standingSeconds, freshMediaAdvancesAfterStanding: true, two, group, reloaded, afterDeadline, standing, limits: ['Local Docker IPv6 bridge permits egress; signalling is pinned to the generated fixture relay. No FIPS daemon or Internet NAT', 'Generated Chromium audio/video, effects off; browser local-network checks disabled', 'Owner HTTPS UI mapped to local HTTP fixtures; no physical phone or node installation proof'] }, null, 2) + '\n');
  mark('receipt saved');
} catch (error) {
  await writeFile(output + '.failure.txt', error.stack ?? String(error), { mode: 0o600 });
  await writeFile(output + '.console.json', JSON.stringify(diagnostics, null, 2), { mode: 0o600 });
  for (const name of names) { try { await writeFile(output + '.' + name + '.log', docker('logs', name), { mode: 0o600 }); } catch {} }
  for (let index = 0; index < contexts.length; index++) for (const page of contexts[index].pages()) {
    await page.screenshot({ path: output + '.' + index + '.png' }).catch(() => {});
    await writeFile(output + '.' + index + '.state.json', JSON.stringify(await page.evaluate(() => ({ text: document.body.innerText.slice(0, 6000) })), null, 2), { mode: 0o600 });
    await writeFile(output + '.' + index + '.media.json', JSON.stringify(await evidence(page).catch(() => ({})), null, 2), { mode: 0o600 });
  }
  process.stderr.write(`Home-node acceptance failed during ${phase}: ${error.name}\n`); process.exitCode = 1;
} finally {
  await Promise.allSettled(contexts.map(context => context.close()));
  if (browser) await browser.close();
  if (appServer) { appServer.closeAllConnections(); await new Promise(resolve => appServer.close(resolve)); }
  for (const name of names.reverse()) { try { docker('rm', '-f', name); } catch {} }
  if (networkCreated) docker('network', 'rm', network);
  await rm(scratch, { recursive: true, force: true });
}
