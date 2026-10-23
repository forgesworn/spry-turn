// Actual KithMoot UI; only generated microphone/camera input and local fixtures.
import assert from 'node:assert/strict';
import { pathToFileURL } from 'node:url';
const modulePath = process.env.SPRY_PLAYWRIGHT_PATH;
const { chromium } = await import(modulePath ? pathToFileURL(modulePath).href : 'playwright');
const origin = process.env.SPRY_KITHMOOT_ORIGIN;
const relay = process.env.SPRY_KITHMOOT_RELAY;
const transport = process.env.SPRY_KITHMOOT_TRANSPORT;
const iceServer = JSON.parse(process.env.SPRY_KITHMOOT_ICE);
const local = value => ['127.0.0.1', 'localhost', '[::1]'].includes(new URL(value).hostname);
assert(local(origin) && local(relay), 'Application fixture must stay on loopback');
assert(['udp', 'tcp', 'tls'].includes(transport));
assert(Array.isArray(iceServer.urls) && iceServer.urls.length > 0 &&
  iceServer.urls.every(url => /^turns?:127\.0\.0\.1:[0-9]{1,5}\?transport=(udp|tcp)$/.test(url)),
  'TURN operator fixture must stay on loopback');
const browser = await chromium.launch({ headless: true, args: [
  '--autoplay-policy=no-user-gesture-required', '--use-fake-device-for-media-stream',
  '--use-fake-ui-for-media-stream', '--disable-audio-output', '--ignore-certificate-errors',
] });
// Playwright owns a separate browser process group. Its synchronous Node exit
// handler kills that group even if graceful browser.close() stops responding.
let stopping = false;
const stopBrowser = code => {
  if (stopping) return;
  stopping = true;
  // Keep this timer referenced so a stalled close cannot strand Chromium.
  const watchdog = setTimeout(() => process.exit(code), 1000);
  void browser.close().finally(() => { clearTimeout(watchdog); process.exit(code); });
};
const deadline = setTimeout(() => stopBrowser(124), 150000);
process.once('SIGTERM', () => stopBrowser(143));
const contexts = [];
const wait = async (read, predicate, description, timeout = 90000) => {
  const deadline = Date.now() + timeout;
  let last;
  do {
    last = await read();
    if (predicate(last)) return last;
    await new Promise(resolve => setTimeout(resolve, 100));
  } while (Date.now() < deadline);
  throw new Error(description);
};

function installDeviceObservers({ relay, ownerIce }) {
  localStorage.setItem('kithmoot.relays.v1', JSON.stringify({ default: [{ url: relay, read: true, write: true }] }));
  localStorage.setItem('kithmoot.hide-ip.v1', '1');
  const NativeSocket = window.WebSocket;
  window.WebSocket = class extends NativeSocket {
    constructor(url, protocols) {
      if (!['127.0.0.1', 'localhost', '[::1]'].includes(new URL(url).hostname)) throw new Error('External signalling is disabled in this fixture');
      super(url, protocols);
    }
  };
  const expectedTurn = [...ownerIce.urls].sort();
  const allowedStun = new Set(ownerIce.urls.filter(url => url.startsWith('turn:'))
    .map(url => url.replace(/^turn:/, 'stun:').split('?')[0]));
  const verifyOperator = config => {
    if (config?.iceTransportPolicy !== 'relay') throw new Error('Application did not select relay-only ICE');
    const servers = config.iceServers;
    const actualTurn = [], actualStun = [];
    const fail = () => { throw new Error('Application ICE configuration differs from the local operator fixture'); };
    if (!Array.isArray(servers) || servers.length === 0) fail();
    for (const server of servers) {
      if (!server || typeof server !== 'object') fail();
      const values = typeof server.urls === 'string' ? [server.urls] : server.urls;
      if (!Array.isArray(values) || values.length === 0) fail();
      for (const value of values) {
        if (expectedTurn.includes(value)) {
          if (server.username !== ownerIce.username || server.credential !== ownerIce.credential ||
              (server.credentialType !== undefined && server.credentialType !== 'password')) fail();
          actualTurn.push(value);
        } else if (allowedStun.has(value)) {
          // The actual app derives uncredentialled STUN for the same operator.
          if (server.username !== undefined || server.credential !== undefined || server.credentialType !== undefined) fail();
          actualStun.push(value);
        } else fail();
      }
    }
    actualTurn.sort();
    if (actualTurn.length !== expectedTurn.length || actualTurn.some((url, index) => url !== expectedTurn[index]) ||
        actualStun.length !== new Set(actualStun).size) fail();
  };
  window.__spryPcs = [];
  const NativePeer = window.RTCPeerConnection;
  window.RTCPeerConnection = class extends NativePeer {
    constructor(config) {
      // Inspect the application's choice before any ICE traffic can start.
      // Pass the original object through; no ICE servers are injected.
      verifyOperator(config);
      super(config);
      window.__spryPcs.push(this);
    }
    setConfiguration(config) {
      verifyOperator(config);
      return super.setConfiguration(config);
    }
  };
  // The synthetic camera comes from Chromium; the tone avoids host sound devices.
  const nativeMedia = navigator.mediaDevices.getUserMedia.bind(navigator.mediaDevices);
  navigator.mediaDevices.getUserMedia = async constraints => {
    if (!constraints?.audio) return nativeMedia(constraints);
    const audio = new AudioContext();
    await audio.resume();
    const oscillator = audio.createOscillator();
    const output = audio.createMediaStreamDestination();
    oscillator.connect(output); oscillator.start();
    const stream = output.stream;
    if (constraints.video) for (const track of (await nativeMedia({ video: constraints.video })).getVideoTracks()) stream.addTrack(track);
    return stream;
  };
}

async function device() {
  const context = await browser.newContext({ permissions: ['camera', 'microphone'], serviceWorkers: 'block' });
  contexts.push(context);
  // A failed local configuration cannot fall back to a public relay or service.
  await context.route('**/*', route => {
    const url = route.request().url();
    if (['http:', 'https:'].includes(new URL(url).protocol) && !local(url)) return route.abort();
    return route.continue();
  });
  await context.addInitScript(installDeviceObservers, { relay, ownerIce: iceServer });
  const page = await context.newPage();
  page.setDefaultTimeout(30000);
  return page;
}

async function media(page) {
  await page.locator('#callToggle').waitFor({ state: 'visible' });
  if (await page.locator('#deviceControls').isHidden()) await page.locator('#callToggle').click();
  await page.locator('#deviceControls').waitFor({ state: 'visible' });
  await page.locator('#toggleCamera').click();
  await wait(() => page.locator('#toggleCamera').getAttribute('data-on'), value => value === 'true', 'Camera did not start', 15000);
  await page.locator('#toggleMic').click();
  await wait(() => page.locator('#toggleMic').getAttribute('data-on'), value => value === 'true', 'Microphone did not start', 15000);
}

async function configure(page) {
  await page.goto(origin);
  await page.locator('#openAppSettings').waitFor({ state: 'attached' });
  await wait(async () => {
    if (!await page.locator('#settingsPane').isVisible()) await page.locator('#openAppSettings').evaluate(button => button.click());
    return page.locator('#settingsPane').isVisible();
  }, Boolean, 'Settings did not open', 30000);
  await page.locator('#settingsPane .infoRow', { has: page.locator('.infoRowTitle', { hasText: /^Connections$/ }) }).click();
  await page.locator('#callRelayUrls').fill(iceServer.urls.join(', '));
  await page.locator('#callRelayUsername').fill(iceServer.username);
  await page.locator('#callRelayPassword').fill(iceServer.credential);
  await page.locator('#callRelaySave').click();
  await wait(() => page.locator('#callRelayStatus').textContent(), text => text.includes('Call relay saved'), 'Relay Settings did not save', 5000);
  await page.locator('#railChats').evaluate(button => button.click());
  await page.locator('#settingsPane').waitFor({ state: 'hidden' });
}

async function evidence(page) {
  return page.evaluate(async () => {
    const pairs = [];
    for (const pc of window.__spryPcs ?? []) {
      const stats = [...(await pc.getStats()).values()];
      const selected = stats.find(s => s.type === 'candidate-pair' && s.state === 'succeeded' && (s.nominated || s.selected));
      if (!selected) continue;
      const local = stats.find(s => s.id === selected.localCandidateId);
      const remote = stats.find(s => s.id === selected.remoteCandidateId);
      pairs.push({ localType: local?.candidateType, remoteType: remote?.candidateType,
        relayProtocol: local?.relayProtocol,
        framesDecoded: stats.filter(s => s.type === 'inbound-rtp' && s.kind === 'video').reduce((n, s) => n + (s.framesDecoded ?? 0), 0),
        audioBytes: stats.filter(s => s.type === 'inbound-rtp' && s.kind === 'audio').reduce((n, s) => n + (s.bytesReceived ?? 0), 0),
        audioEnergy: stats.filter(s => s.type === 'inbound-rtp' && s.kind === 'audio').reduce((n, s) => n + (s.totalAudioEnergy ?? 0), 0) });
    }
    return { pairs, participants: document.querySelectorAll('#room .participant').length,
      displayedVideos: [...document.querySelectorAll('#room .participant')]
        .filter(tile => !(tile.querySelector('h3')?.textContent ?? '').includes('(you)'))
        .flatMap(tile => [...tile.querySelectorAll('video')]).filter(video => video.videoWidth > 0 && video.videoHeight > 0 && !video.paused).length,
      remoteAudioSinks: [...document.querySelectorAll('#room .participant audio')].filter(audio => audio.srcObject !== null).length };
  });
}

try {
  const a = await device(), b = await device();
  await configure(a); await configure(b);
  await a.locator('#newRoom:visible, #newMenuButton:visible').first().waitFor({ state: 'visible' });
  if (await a.locator('#newRoom').isVisible()) await a.locator('#newRoom').click();
  else { await a.locator('#newMenuButton').click(); await a.locator('#newMenuRoom').click(); }
  await a.locator('#roomName').waitFor({ state: 'visible' });
  if (await a.locator('#newRoomYourName').isVisible()) await a.locator('#newRoomYourName').fill('Generated relay A');
  await a.locator('#create').click();
  await a.locator('#roomArea').waitFor({ state: 'visible', timeout: 60000 });
  const join = await wait(() => a.locator('#shareUrl').inputValue(), value => value.includes('#'), 'No room invitation');
  const invitation = Buffer.from(new URL(join).hash.slice(1), 'base64url').toString();
  assert(!invitation.includes(iceServer.credential) && !invitation.includes(iceServer.username), 'Invitation disclosed device credentials');
  await b.goto(join);
  // Settings was already open on this origin; a fragment-only navigation
  // must reload so the application's entry point reads the invitation.
  await b.reload();
  await b.locator('#displayName').fill('Generated relay B');
  await b.locator('#join').waitFor({ state: 'visible' });
  await b.locator('#join').click();
  await b.locator('#roomArea').waitFor({ state: 'visible', timeout: 60000 });
  await media(a); await media(b);
  const expectedProtocol = transport;
  const valid = result => result.participants === 2 && result.displayedVideos > 0 && result.remoteAudioSinks > 0 &&
    result.pairs.length > 0 && result.pairs.every(pair => pair.localType === 'relay' && pair.remoteType === 'relay' &&
      pair.relayProtocol === expectedProtocol && pair.framesDecoded > 0 && pair.audioBytes > 0 && pair.audioEnergy > 0);
  const endpoints = await Promise.all([a, b].map(page => wait(() => evidence(page), valid, `Actual app did not exchange bidirectional ${transport} media`)));
  console.log(JSON.stringify({ transport, passed: true, applicationRelayOnly: true, injectedIceServers: false,
    configuredThroughSettings: true, iceConfigurationMatchesOperator: true, invitationOmitsCredentials: true,
    generatedMediaOnly: true, certificateBypass: true, endpoints }));
} finally {
  clearTimeout(deadline);
  try {
    await Promise.all(contexts.map(context => context.close()));
  } finally {
    await browser.close();
  }
}
