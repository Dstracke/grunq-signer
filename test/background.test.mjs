// Background wiring test: loads src/background/index.js with a minimal
// WebExtension stub and drives it through the popup message channel. Covers
// the multi-identity flow (add/switch/protect/lock/unlock/remove), the
// per-identity scoping of NIP-46 sessions and the profile, plus the audit
// handlers. No real relays or approval windows are involved.
import test from 'node:test';
import assert from 'node:assert/strict';
import { pathToFileURL } from 'node:url';
import { encodeNsec } from '../src/lib/keys.js';

// The background builds a real RelayPool; keep it offline and timer-free so
// the test process can exit (no relay traffic, no reconnect backoff).
class DeadSocket {
  static CONNECTING = 0;
  static OPEN = 1;
  static CLOSING = 2;
  static CLOSED = 3;
  constructor(url) {
    this.url = url;
    this.readyState = DeadSocket.CONNECTING;
  }
  send() {}
  close() {}
}
globalThis.WebSocket = DeadSocket;

const local = new Map();
const session = new Map();

function memoryArea(map) {
  return {
    get: async (key) => (typeof key === 'string'
      ? { [key]: map.get(key) }
      : Object.fromEntries([].concat(key).map((k) => [k, map.get(k)]))),
    set: async (obj) => {
      for (const [k, v] of Object.entries(obj)) map.set(k, v);
    },
    remove: async (key) => {
      for (const k of [].concat(key)) map.delete(k);
    },
  };
}

let handler = null;

globalThis.browser = {
  i18n: {
    getMessage: (key, subs) => (Array.isArray(subs)
      ? subs.reduce((acc, v, i) => acc.replace('$' + (i + 1) + '$', v), key)
      : key),
  },
  runtime: {
    id: 'test',
    getURL: (p) => 'moz-extension://test/' + p,
    onMessage: { addListener: (fn) => (handler = fn) },
    onStartup: { addListener: () => {} },
    onInstalled: { addListener: () => {} },
    sendMessage: async () => ({}),
    openOptionsPage: () => {},
  },
  storage: { local: memoryArea(local), session: memoryArea(session) },
  alarms: { create: () => {}, onAlarm: { addListener: () => {} } },
  windows: { create: async () => ({}), remove: async () => {}, onRemoved: { addListener: () => {} } },
};
globalThis.chrome = globalThis.browser;

await import(pathToFileURL(new URL('../src/background/index.js', import.meta.url).pathname).href);

const call = (msg) =>
  new Promise((resolve) => {
    assert.ok(handler, 'background registered a message listener');
    handler({ type: 'popup', ...msg }, {}, resolve);
  });

const priv = (n) => n.repeat(64).slice(0, 64);

test('background: multi-identity flow end to end', async () => {
  let r = await call({ action: 'state' });
  assert.equal(r.hasKey, false);
  assert.equal(r.identityCount, 0);

  r = await call({ action: 'import', input: encodeNsec(priv('a')), label: 'Streamer' });
  assert.equal(r.label, 'Streamer');
  assert.match(r.npub, /^npub1/);
  const streamerId = r.id;

  r = await call({ action: 'generate', label: 'Chat' });
  const chatId = r.id;
  assert.ok(chatId && chatId !== streamerId);

  r = await call({ action: 'state' });
  assert.equal(r.identity.label, 'Chat', 'newest identity is active');
  assert.equal(r.identityCount, 2);

  const list = await call({ action: 'identity.list' });
  assert.equal(list.length, 2);
  assert.deepEqual(list.map((i) => i.label).sort(), ['Chat', 'Streamer']);
  assert.equal(list.filter((i) => i.active).length, 1);

  r = await call({ action: 'identity.switch', id: streamerId });
  assert.equal(r.label, 'Streamer');

  r = await call({ action: 'protect', password: 'mein-langes-passwort', repeat: 'mein-langes-passwort' });
  assert.match(r.ncryptsec, /^ncryptsec1/);

  r = await call({ action: 'lock' });
  assert.equal(r.ok, true);
  r = await call({ action: 'export', what: 'nsec', confirm: true });
  assert.equal(r.error?.code, 'locked');

  r = await call({ action: 'unlock', password: 'mein-langes-passwort' });
  assert.equal(r.error, undefined);
  assert.equal(r.encrypted, true);
  r = await call({ action: 'export', what: 'nsec', confirm: true });
  assert.equal(r.nsec, encodeNsec(priv('a')));
});

test('background: profile and sessions are scoped per identity', async () => {
  const list = await call({ action: 'identity.list' });
  const streamer = list.find((i) => i.label === 'Streamer');
  const chat = list.find((i) => i.label === 'Chat');

  // Seed storage the way the signer/profile writers would.
  local.set('grunq_signer:profile:' + streamer.id, { fields: { name: 'streamer' }, publishedAt: 1 });
  local.set('grunq_signer:sessions:' + chat.id, [{ secret: 'chat-session', bound: true, relays: [] }]);

  await call({ action: 'identity.switch', id: streamer.id });
  let r = await call({ action: 'profile.get' });
  assert.equal(r.fields.name, 'streamer');
  r = await call({ action: 'state' });
  assert.deepEqual(r.sessions, [], 'streamer has no bunker sessions');

  await call({ action: 'identity.switch', id: chat.id });
  r = await call({ action: 'profile.get' });
  assert.deepEqual(r.fields, {}, 'chat identity has its own profile');
  r = await call({ action: 'state' });
  assert.equal(r.sessions.length, 1);
  assert.equal(r.sessions[0].id, 'chat-ses');
});

test('background: removing the active identity falls back, audit handlers answer', async () => {
  const list = await call({ action: 'identity.list' });
  const chat = list.find((i) => i.label === 'Chat');
  const r = await call({ action: 'identity.remove', id: chat.id });
  assert.equal(r.hasKey, true);
  assert.equal(r.count, 1);

  assert.ok(Array.isArray(await call({ action: 'audit.list' })));
  assert.equal(await call({ action: 'audit.clear' }), true);
});
