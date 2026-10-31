#!/usr/bin/env node
// Drive the real PocketBase admin UI in headless Chrome and check that it can
// log in against the server under test.
//
// Usage: node tools/ui_login_check.mjs <base-url> <email> <password>
//
// Exits 0 when the UI stored a `pb_auth` session for the given email, 1
// otherwise. Prints every failed network request so missing endpoints are
// obvious.

const [base, email, password] = process.argv.slice(2);
if (!base || !email || !password) {
  console.error('usage: ui_login_check.mjs <base-url> <email> <password>');
  process.exit(2);
}

const CDP_HTTP = process.env.CDP_HTTP || 'http://127.0.0.1:9333';

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function browserWs() {
  for (let i = 0; i < 60; i++) {
    try {
      const res = await fetch(`${CDP_HTTP}/json/version`);
      const json = await res.json();
      if (json.webSocketDebuggerUrl) return json.webSocketDebuggerUrl;
    } catch {
      /* not up yet */
    }
    await sleep(250);
  }
  throw new Error('chrome devtools endpoint never came up');
}

class Cdp {
  constructor(ws) {
    this.ws = ws;
    this.id = 0;
    this.pending = new Map();
    this.events = [];
    ws.addEventListener('message', (ev) => {
      const msg = JSON.parse(ev.data);
      if (msg.id && this.pending.has(msg.id)) {
        const { resolve, reject } = this.pending.get(msg.id);
        this.pending.delete(msg.id);
        msg.error ? reject(new Error(JSON.stringify(msg.error))) : resolve(msg.result);
      } else if (msg.method) {
        this.events.push(msg);
      }
    });
  }

  send(method, params = {}, sessionId) {
    const id = ++this.id;
    const payload = { id, method, params };
    if (sessionId) payload.sessionId = sessionId;
    this.ws.send(JSON.stringify(payload));
    return new Promise((resolve, reject) => {
      this.pending.set(id, { resolve, reject });
      setTimeout(() => {
        if (this.pending.delete(id)) reject(new Error(`${method} timed out`));
      }, 30000);
    });
  }
}

async function main() {
  const ws = new WebSocket(await browserWs());
  await new Promise((resolve, reject) => {
    ws.addEventListener('open', resolve);
    ws.addEventListener('error', reject);
  });

  const cdp = new Cdp(ws);
  const { targetId } = await cdp.send('Target.createTarget', { url: 'about:blank' });
  const { sessionId } = await cdp.send('Target.attachToTarget', { targetId, flatten: true });

  await cdp.send('Page.enable', {}, sessionId);
  await cdp.send('Runtime.enable', {}, sessionId);
  await cdp.send('Network.enable', {}, sessionId);

  const evaluate = async (expression) => {
    const res = await cdp.send(
      'Runtime.evaluate',
      { expression, awaitPromise: true, returnByValue: true },
      sessionId,
    );
    if (res.exceptionDetails) {
      throw new Error(res.exceptionDetails.text + ' ' + JSON.stringify(res.exceptionDetails.exception));
    }
    return res.result.value;
  };

  const url = `${base.replace(/\/$/, '')}/_/`;
  await cdp.send('Page.navigate', { url }, sessionId);

  // Wait for the SPA to render a login form.
  const formReady = await (async () => {
    for (let i = 0; i < 80; i++) {
      const found = await evaluate(`
        (() => {
          const pw = document.querySelector('input[type=password]');
          const em = document.querySelector('input[type=email], input[name=email], input[autocomplete=username]');
          return Boolean(pw && em);
        })()
      `).catch(() => false);
      if (found) return true;
      await sleep(250);
    }
    return false;
  })();

  if (!formReady) {
    const dom = await evaluate(`document.body ? document.body.innerText.slice(0, 800) : ''`);
    console.log('UI_LOGIN: no login form rendered');
    console.log('DOM:', dom);
    process.exit(1);
  }

  // Fill the form the way a user would (native setter + input/change events, so
  // Svelte's bindings update).
  await evaluate(`
    (() => {
      const setValue = (el, value) => {
        const proto = Object.getPrototypeOf(el);
        const desc = Object.getOwnPropertyDescriptor(proto, 'value');
        desc.set.call(el, value);
        el.dispatchEvent(new Event('input', { bubbles: true }));
        el.dispatchEvent(new Event('change', { bubbles: true }));
      };
      const em = document.querySelector('input[type=email], input[name=email], input[autocomplete=username]');
      const pw = document.querySelector('input[type=password]');
      setValue(em, ${JSON.stringify(email)});
      setValue(pw, ${JSON.stringify(password)});
      return true;
    })()
  `);

  await sleep(200);

  await evaluate(`
    (() => {
      const form = document.querySelector('input[type=password]').closest('form');
      if (form) { form.requestSubmit(); return 'submit'; }
      const btn = [...document.querySelectorAll('button')].find(b => /sign in|login|masuk/i.test(b.textContent));
      if (btn) { btn.click(); return 'click'; }
      return 'none';
    })()
  `);

  // Wait for the auth store to be populated. The storage key has changed
  // between UI versions (`pb_auth`, `pocketbase_auth`), so scan every entry for
  // a JSON object carrying a token.
  let auth = null;
  for (let i = 0; i < 80; i++) {
    auth = await evaluate(`
      (() => {
        for (const key of Object.keys(localStorage)) {
          const raw = localStorage.getItem(key);
          if (!raw || !raw.includes('token')) continue;
          try {
            const parsed = JSON.parse(raw);
            const token = parsed && (parsed.token || (parsed.value && parsed.value.token));
            if (token) return { key, ...parsed };
          } catch { /* not json */ }
        }
        return null;
      })()
    `).catch(() => null);
    if (auth && auth.token) break;
    await sleep(250);
  }

  // Endpoints that belong to later milestones are listed explicitly rather than
  // ignored wholesale, so an unexpected failure still fails the check.
  //
  // M2 covers auth + collections/settings reads. Record listing (the collection
  // detail page the UI opens after login) is M3.
  const PENDING = (process.env.UI_PENDING || '/records').split(',').filter(Boolean);

  const allRequests = cdp.events
    .filter((e) => e.method === 'Network.responseReceived' && e.params.response.url.includes('/api/'))
    .map((e) => `${e.params.response.status} ${e.params.response.url.replace(base, '')}`);
  const failedRequests = allRequests.filter((r) => !r.startsWith('2'));
  const unexpected = failedRequests.filter((r) => !PENDING.some((p) => r.includes(p)));
  const pending = failedRequests.filter((r) => PENDING.some((p) => r.includes(p)));

  if (process.env.UI_VERBOSE) {
    console.log('UI_LOGIN: api requests:');
    for (const r of allRequests) console.log('  ' + r);
  }

  const route = await evaluate('location.hash');

  if (auth && auth.token) {
    const model = auth.model || auth.record || {};
    console.log(`UI_LOGIN: ok (route=${route})`);
    console.log(`UI_LOGIN: stored email=${model.email} verified=${model.verified}`);
    if (model.email !== email) {
      console.log(`UI_LOGIN: wrong email stored`);
      process.exit(1);
    }
    if (pending.length) {
      console.log('UI_LOGIN: pending later milestones (not a failure):');
      for (const r of pending) console.log('  ' + r);
    }
    if (unexpected.length) {
      console.log('UI_LOGIN: failed requests during login:');
      for (const r of unexpected) console.log('  ' + r);
      process.exit(1);
    }
    process.exit(0);
  }

  console.log(`UI_LOGIN: no auth stored (route=${route})`);
  const keys = await evaluate('JSON.stringify(Object.keys(localStorage))');
  console.log('UI_LOGIN: localStorage keys:', keys);
  const bodyText = await evaluate('document.body.innerText.slice(0, 800)');
  console.log('DOM:', bodyText);
  if (failedRequests.length) {
    console.log('UI_LOGIN: failed requests:');
    for (const r of failedRequests) console.log('  ' + r);
  }
  process.exit(1);
}

main().catch((e) => {
  console.error('UI_LOGIN: error', e.message);
  process.exit(1);
});
