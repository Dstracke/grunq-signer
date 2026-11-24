// Options page test: drives src/options/options.js in a minimal fake DOM and a
// stubbed background channel. Covers the profile fetch button (the fetched
// fields must land in the editor instead of being wiped by a local reload) and
// renaming an identity (label is local metadata, `identity.rename`).
import test from 'node:test';
import assert from 'node:assert/strict';

// ---------- fake DOM ----------

function makeElement(tag = 'div') {
  const node = {
    tagName: String(tag).toUpperCase(),
    id: '',
    className: '',
    value: '',
    title: '',
    type: '',
    alt: '',
    href: '',
    src: '',
    placeholder: '',
    hidden: false,
    checked: false,
    disabled: false,
    maxLength: 0,
    dataset: {},
    style: {},
    children: [],
    listeners: {},
    onerror: null,
    addEventListener(type, fn) {
      (node.listeners[type] ??= []).push(fn);
    },
    removeEventListener(type, fn) {
      const list = node.listeners[type];
      if (list) node.listeners[type] = list.filter((f) => f !== fn);
    },
    append(...kids) {
      for (const kid of kids) {
        if (typeof kid === 'string') text += kid;
        else node.children.push(kid);
      }
    },
    appendChild(kid) {
      node.append(kid);
      return kid;
    },
    setAttribute(key, value) {
      node[key] = value;
    },
    getAttribute(key) {
      return node[key] ?? null;
    },
    removeAttribute(key) {
      delete node[key];
    },
    focus() {},
    select() {},
    scrollIntoView() {},
    remove() {},
    classList: { add() {}, remove() {}, toggle() {}, contains: () => false },
  };
  // Like the real DOM: assigning textContent replaces all children.
  let text = '';
  Object.defineProperty(node, 'textContent', {
    get: () => text,
    set: (value) => {
      text = String(value);
      node.children = [];
    },
  });
  return node;
}

function installDom() {
  const byId = new Map();
  const document = {
    getElementById(id) {
      if (!byId.has(id)) {
        const node = makeElement();
        node.id = id;
        byId.set(id, node);
      }
      return byId.get(id);
    },
    createElement(tag) {
      return makeElement(tag);
    },
    querySelectorAll() {
      return [];
    },
  };
  const previous = {
    document: globalThis.document,
    location: globalThis.location,
    browser: globalThis.browser,
    chrome: globalThis.chrome,
  };
  globalThis.document = document;
  globalThis.location = { search: '', hash: '' };
  return { byId, restore: () => Object.assign(globalThis, previous) };
}

function click(node) {
  for (const fn of node.listeners.click ?? []) fn({ preventDefault() {} });
}

function keydown(node, key) {
  for (const fn of node.listeners.keydown ?? []) fn({ key, preventDefault() {} });
}

/** Let the page's promise chains (refresh -> ... -> render) run to the end. */
async function settle() {
  for (let i = 0; i < 40; i++) await new Promise((r) => setImmediate(r));
}

// ---------- fake background ----------

const FETCHED = {
  name: 'luku',
  display_name: 'Luku',
  about: 'test stream',
  picture: 'https://example.com/avatar.png',
  lud16: 'luku@getalive.me',
};

function installBackground() {
  const calls = [];
  const identities = [{
    id: 'id1',
    label: '',
    npub: 'npub1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq',
    pubkey: 'a'.repeat(64),
    active: true,
    encrypted: false,
    unlocked: true,
  }];
  const api = {
    i18n: { getMessage: (key) => key },
    runtime: {
      async sendMessage(msg) {
        calls.push(msg);
        switch (msg.action) {
          case 'state':
            return {
              hasKey: true,
              approvals: [],
              sessions: [],
              relays: ['wss://relay.grunq.com'],
              security: {},
              identity: { npub: identities[0].npub },
              encrypted: false,
              unlocked: true,
            };
          case 'identity.list':
            return identities.map((i) => ({ ...i }));
          case 'identity.rename': {
            const item = identities.find((i) => i.id === msg.id);
            if (!item) return { error: { code: 'invalid_input', message: 'invalid_input' } };
            item.label = String(msg.label ?? '').trim().slice(0, 40);
            return { ...item };
          }
          case 'profile.get':
            return { fields: {}, eventId: null, publishedAt: null, pubkey: identities[0].pubkey };
          case 'profile.fetch':
            return { fields: { ...FETCHED } };
          case 'audit.list':
            return [];
          default:
            return {};
        }
      },
    },
  };
  globalThis.browser = api;
  delete globalThis.chrome;
  return { calls, identities };
}

// ---------- tests ----------

test('options page', async (t) => {
  const dom = installDom();
  const bg = installBackground();
  // flash() uses a 2.5 s hide timer; keep the test process from waiting it out.
  const realSetTimeout = globalThis.setTimeout;
  globalThis.setTimeout = () => 0;
  try {
    await import('../src/options/options.js');
    await settle();
    globalThis.setTimeout = realSetTimeout;

    assert.equal(bg.calls.filter((c) => c.action === 'profile.get').length, 1);

    await t.test('load from relays fills the editor instead of wiping it', async () => {
      assert.equal(dom.byId.get('pf-name').value, '');

      click(dom.byId.get('btn-profile-fetch'));
      await settle();

      assert.ok(bg.calls.some((c) => c.action === 'profile.fetch'));
      assert.equal(dom.byId.get('pf-name').value, 'luku');
      assert.equal(dom.byId.get('pf-display-name').value, 'Luku');
      assert.equal(dom.byId.get('pf-about').value, 'test stream');
      assert.equal(dom.byId.get('pf-picture').value, 'https://example.com/avatar.png');
      assert.equal(dom.byId.get('pf-lud16').value, 'luku@getalive.me');
      assert.equal(dom.byId.get('pp-display').textContent, 'Luku');
      // The fetch must not reload the (empty) local store afterwards.
      assert.equal(bg.calls.filter((c) => c.action === 'profile.get').length, 1);
      assert.equal(dom.byId.get('profile-status').textContent, 'profileFetched');
    });

    await t.test('identity labels can be renamed', async () => {
      const list = dom.byId.get('identities');
      const li = list.children[0];
      const rename = li.children.find((c) => c.textContent === 'btnRenameIdentity');
      assert.ok(rename, 'rename button rendered');

      click(rename);
      assert.equal(li.children.length, 1, 'row switched to edit mode');
      const row = li.children[0];
      const input = row.children[0];
      const save = row.children[1];
      assert.equal(input.value, '', 'label starts empty');
      assert.equal(save.textContent, 'btnRenameSave');

      input.value = 'Streamer';
      click(save);
      await settle();

      const renameCall = bg.calls.find((c) => c.action === 'identity.rename');
      assert.deepEqual(renameCall, { type: 'popup', action: 'identity.rename', id: 'id1', label: 'Streamer' });
      assert.equal(bg.identities[0].label, 'Streamer');
      const renamed = dom.byId.get('identities').children[0];
      assert.ok(renamed.children.some((c) => c.textContent.trim() === 'Streamer'), 'list shows the new label');
    });

    await t.test('escape cancels a rename without writing', async () => {
      const before = bg.calls.filter((c) => c.action === 'identity.rename').length;
      const li = dom.byId.get('identities').children[0];
      click(li.children.find((c) => c.textContent === 'btnRenameIdentity'));
      const input = li.children[0].children[0];
      input.value = 'Verworfen';
      keydown(input, 'Escape');
      await settle();
      assert.equal(bg.calls.filter((c) => c.action === 'identity.rename').length, before);
      assert.equal(bg.identities[0].label, 'Streamer');
    });
  } finally {
    globalThis.setTimeout = realSetTimeout;
    dom.restore();
  }
});
