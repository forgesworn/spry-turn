// Synthetic owner UI: no live node, signer, account or one-use code.
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { chromium } from 'playwright';
const files = new Map(await Promise.all(['index.html', 'app.mjs', 'style.css'].map(async name =>
  ['/' + name, await readFile(new URL('../crates/spry-service/public/' + name, import.meta.url))])));
const browser = await chromium.launch({ headless: true });
try {
  for (const denied of [false, true]) {
    const context = await browser.newContext({ viewport: { width: 360, height: 800 } });
    let requests = 0;
    const expiresAt = Math.floor(Date.now() / 1000) + 100;
    const hash = '#spry=' + Buffer.from(JSON.stringify({ v: 1, endpoint: 'https://relay.example', code: 'a'.repeat(43), expiresAt })).toString('base64url');
    await context.addInitScript(denied => {
      window.nostr = { signEvent: async event => ({ ...event, pubkey: '1'.repeat(64), id: '2'.repeat(64), sig: '3'.repeat(128) }) };
      window.fixtureCopied = undefined;
      Object.defineProperty(navigator, 'clipboard', { configurable: true, value: {
        writeText: async text => { if (denied) throw new Error('Fixture refused'); window.fixtureCopied = text; },
      } });
    }, denied);
    await context.route('**/*', async route => {
      const u = new URL(route.request().url());
      if (u.origin !== 'https://relay.example') throw new Error('Unexpected network request');
      if (u.pathname === '/v1/status') return route.fulfill({ json: { ready: true, endpoint: u.origin, message: 'Ready' } });
      if (u.pathname === '/v1/pairings') {
        requests++;
        assert.equal(route.request().method(), 'POST');
        assert.ok(route.request().headers().authorization?.startsWith('Nostr '));
        return route.fulfill({ json: { url: 'https://app.example/j/' + hash } });
      }
      const name = u.pathname === '/' ? '/index.html' : u.pathname;
      assert.ok(files.has(name));
      return route.fulfill({ body: files.get(name), contentType: name.endsWith('.mjs') ? 'text/javascript' : name.endsWith('.css') ? 'text/css' : 'text/html' });
    });
    const page = await context.newPage();
    await page.clock.install({ time: new Date() });
    await page.goto('https://relay.example/');
    await page.getByRole('button', { name: 'Pair with KithMoot', exact: true }).click();
    await page.locator('#handoff').waitFor({ state: 'visible' });
    assert.equal(page.url(), 'https://relay.example/');
    assert.equal(await page.locator('#open-app').getAttribute('href'), 'kithmoot://join' + hash);
    assert.equal(await page.locator('#open-browser').getAttribute('href'), 'https://app.example/j/' + hash);
    await page.getByRole('button', { name: 'Copy pairing link', exact: true }).click();
    if (denied) {
      await page.waitForFunction(() => document.querySelector('#status').textContent.includes('link is selected'));
      assert.equal(await page.locator('#pairing-link').evaluate(input => input.selectionEnd - input.selectionStart), ('kithmoot://join' + hash).length);
    } else {
      await page.waitForFunction(() => typeof window.fixtureCopied === 'string');
      assert.equal(await page.evaluate(() => window.fixtureCopied), 'kithmoot://join' + hash);
    }
    assert.equal(requests, 1);
    assert.ok(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth));
    await page.clock.fastForward(101000);
    assert.equal(await page.locator('#handoff').isHidden(), true);
    assert.equal(await page.locator('#pairing-link').inputValue(), '');
    assert.equal(await page.locator('#open-app').getAttribute('href'), null);
    assert.equal(requests, 1);
    await context.close();
  }
  console.log('Owner approval, app/copy handoff, clipboard refusal, mobile reflow and expiry passed without navigating to KithMoot web.');
} finally { await browser.close(); }
