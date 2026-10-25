const status = document.querySelector('#status');
const base = new URL('./', import.meta.url);
let endpoint, audience, privateRelay;
let pairingExpiresAt = 0, pairingTimer;
function clearPairing() {
  clearTimeout(pairingTimer);
  document.querySelector('#handoff').hidden = true;
  document.querySelector('#pairing-link').value = '';
  document.querySelector('#open-app').removeAttribute('href');
  document.querySelector('#open-browser').removeAttribute('href');
  pairingExpiresAt = 0;
}
function currentPairingLink() {
  if (!pairingExpiresAt || Date.now() >= pairingExpiresAt * 1000) {
    clearPairing();
    status.textContent = 'That pairing link has expired. Choose Pair with KithMoot for a fresh link.';
    return undefined;
  }
  return document.querySelector('#pairing-link').value;
}
async function refreshStatus() {
  let ready = false;
  try {
    const response = await fetch(new URL('v1/status', base), { credentials: 'omit', cache: 'no-store', signal: AbortSignal.timeout(5000) });
    if (!response.ok) throw new Error();
    const state = await response.json(); status.textContent = state.message;
    endpoint = state.endpoint; audience = state.audience; privateRelay = state.privateRelay === true;
    ready = state.ready === true;
    document.querySelector('#pair').disabled = !ready;
    if (ready && location.hash === '#pairing') {
      history.replaceState(null, '', location.pathname);
      await action(document.querySelector('#pair'), pair);
    }
  } catch { status.textContent = 'Spry is starting. Waiting for your node…'; }
  if (!ready) setTimeout(refreshStatus, 2000);
}
void refreshStatus();
const hex = bytes => [...bytes].map(value => value.toString(16).padStart(2, '0')).join('');
async function request(path, value = {}) {
  if (!window.nostr) throw new Error(document.body.dataset.ownerHelp || 'Connect your owner signing extension to pair Spry.');
  if (typeof endpoint !== 'string' || new URL(endpoint).protocol !== 'https:') throw new Error('Spry is still starting. Try again shortly.');
  const body = JSON.stringify(value), url = new URL(path, endpoint).href;
  const nonce = btoa(String.fromCharCode(...crypto.getRandomValues(new Uint8Array(32)))).replaceAll('+', '-').replaceAll('/', '_').replaceAll('=', '');
  const event = await window.nostr.signEvent({ kind: 27235, created_at: Math.floor(Date.now() / 1000), content: '',
    tags: [['u', url], ['method', 'POST'], ['payload', hex(new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(body))))], ['nonce', nonce], ...(audience ? [['aud', audience]] : [])] });
  const response = await fetch(new URL(path.slice(1), base), { method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Nostr ${btoa(JSON.stringify(event))}` },
    body, credentials: 'omit', redirect: 'error', referrerPolicy: 'no-referrer', cache: 'no-store', signal: AbortSignal.timeout(20000) });
  const result = await response.json();
  if (!response.ok) throw new Error(typeof result.error === 'string' ? result.error : 'Spry could not complete that. Try again.');
  return result;
}
async function action(button, run) {
  button.disabled = true; status.textContent = 'Waiting for your approval…';
  try { await run(); } catch (error) { status.textContent = error instanceof Error ? error.message : 'Please try again.'; }
  finally { button.disabled = false; }
}
async function pair() {
  clearPairing();
  let relays;
  if (privateRelay && typeof window.nostr?.getRelays === 'function') {
    const selected = await window.nostr.getRelays();
    relays = Object.entries(selected).filter(([, mode]) => mode.read && mode.write)
      .map(([url]) => url).sort().slice(0, 4);
  }
  const { url } = await request('/v1/pairings', relays?.length ? { relays } : {});
  // A separate click retains the user gesture Safari needs to open an app.
  // The one-use code stays in the fragment and is never sent to a QR service.
  const target = new URL(url);
  if (url.length > 4096 || target.protocol !== 'https:' || target.username || target.password || target.search ||
      !/^#spry=[A-Za-z0-9_-]+$/.test(target.hash)) throw new Error('The pairing link was invalid.');
  const payload = JSON.parse(atob(target.hash.slice(6).replaceAll('-', '+').replaceAll('_', '/')));
  const now = Math.floor(Date.now() / 1000);
  if (payload.v !== 1 || !/^[A-Za-z0-9_-]{43}$/.test(payload.code) || !Number.isSafeInteger(payload.expiresAt) ||
      payload.expiresAt <= now || payload.expiresAt > now + 360) throw new Error('The pairing link was invalid or expired.');
  pairingExpiresAt = payload.expiresAt;
  document.querySelector('#pairing-link').value = `kithmoot://join${target.hash}`;
  document.querySelector('#open-app').href = `kithmoot://join${target.hash}`;
  document.querySelector('#open-browser').href = target.href;
  document.querySelector('#handoff').hidden = false;
  status.textContent = 'Pairing link ready. Open KithMoot app or copy the link. You do not need to sign into KithMoot in this browser.';
  pairingTimer = setTimeout(() => { clearPairing(); status.textContent = 'That pairing link has expired. Choose Pair with KithMoot for a fresh link.'; }, Math.max(0, payload.expiresAt * 1000 - Date.now()));
}
document.querySelector('#pairing-link').onclick = event => { if (currentPairingLink()) event.currentTarget.select(); };
for (const id of ['open-app', 'open-browser']) document.querySelector('#' + id).onclick = event => {
  if (!currentPairingLink()) event.preventDefault();
};
document.querySelector('#copy-link').onclick = async () => {
  const value = currentPairingLink();
  if (!value) return;
  try { await navigator.clipboard.writeText(value); status.textContent = 'Pairing link copied. Open it in KithMoot, or paste it in Settings → Connections → Spry.'; }
  catch { const field = document.querySelector('#pairing-link'); field.focus(); field.select(); status.textContent = 'The link is selected. Choose Copy, or press Command-C on Mac or Ctrl-C on Windows/Linux.'; }
};
window.addEventListener('pagehide', clearPairing);
document.querySelector('#pair').onclick = event => {
  if (window !== window.top) {
    // Leave the dashboard iframe with a real user gesture. The new top-level
    // tab can complete node approval then open KithMoot without popup tricks.
    window.open(new URL('#pairing', base).href, '_blank', 'noopener,noreferrer');
    status.textContent = 'Finish pairing in the new tab.';
  } else void action(event.currentTarget, pair);
};
document.querySelector('#load').onclick = event => action(event.currentTarget, async () => {
  const { pairings } = await request('/v1/pairings/list');
  const list = document.querySelector('#devices'); list.replaceChildren();
  for (const pair of pairings) {
    const row = document.createElement('li'); row.textContent = `Paired ${new Date(pair.createdAt * 1000).toLocaleDateString()}`;
    const remove = document.createElement('button'); remove.textContent = 'Remove';
    remove.onclick = event => action(event.currentTarget, async () => { await request('/v1/pairings/remove', { id: pair.id }); row.remove(); status.textContent = 'Pairing removed.'; });
    row.append(remove); list.append(row);
  }
  status.textContent = pairings.length ? '' : 'No paired devices yet.';
});
