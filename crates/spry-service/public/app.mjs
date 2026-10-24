const status = document.querySelector('#status');
const base = new URL('./', import.meta.url);
let endpoint;
fetch(new URL('v1/status', base), { credentials: 'omit', cache: 'no-store', signal: AbortSignal.timeout(5000) }).then(async response => {
  const state = await response.json(); status.textContent = state.message;
  endpoint = state.endpoint;
  document.querySelector('#pair').disabled = state.ready !== true;
  if (state.ready && location.hash === '#pairing') {
    history.replaceState(null, '', location.pathname);
    await action(document.querySelector('#pair'), pair);
  }
}).catch(() => { status.textContent = 'Spry is not ready yet. Refresh in a moment.'; });
const hex = bytes => [...bytes].map(value => value.toString(16).padStart(2, '0')).join('');
async function request(path, value = {}) {
  if (!window.nostr) throw new Error('Connect your owner signing extension to pair Spry.');
  if (typeof endpoint !== 'string' || new URL(endpoint).protocol !== 'https:') throw new Error('Spry is still starting. Try again shortly.');
  const body = JSON.stringify(value), url = new URL(path, endpoint).href;
  const nonce = btoa(String.fromCharCode(...crypto.getRandomValues(new Uint8Array(32)))).replaceAll('+', '-').replaceAll('/', '_').replaceAll('=', '');
  const event = await window.nostr.signEvent({ kind: 27235, created_at: Math.floor(Date.now() / 1000), content: '',
    tags: [['u', url], ['method', 'POST'], ['payload', hex(new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(body))))], ['nonce', nonce]] });
  const response = await fetch(new URL(path.slice(1), base), { method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Nostr ${btoa(JSON.stringify(event))}` },
    body, credentials: 'omit', redirect: 'error', referrerPolicy: 'no-referrer', cache: 'no-store', signal: AbortSignal.timeout(10000) });
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
  const { url } = await request('/v1/pairings');
  // Navigate only to the configured KithMoot app; never place the pairing code in a query/referrer.
  const target = new URL(url);
  if (target.protocol !== 'https:' || !target.hash.startsWith('#spry=')) throw new Error('The pairing link was invalid.');
  location.replace(target.href);
}
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
