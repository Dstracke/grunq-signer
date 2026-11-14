// NIP-46 signer tests: unit tests with a fake transport plus an optional
// end-to-end run against a real relay (RELAY_WS env, default the Grunq test
// relay; the E2E block is skipped when the relay is unreachable).
import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes, bytesToHex } from '@noble/hashes/utils.js';

import {
  createSignerCore,
  SESSIONS_STORE,
  SETTINGS_STORE,
  buildBunkerUri,
  DEFAULT_RELAYS,
} from '../src/signer/core.js';
import { randomIdentity, derivePubkeyHex, verifyEvent } from '../src/lib/keys.js';
import { nip44Decrypt, nip44Encrypt } from '../src/lib/signing.js';
import { MiniClient } from './mini-client.mjs';
import { RelayPool } from '../src/lib/relay-pool.js';

function fakeEnv(overrides = {}) {
  const store = new Map();
  const priv = overrides.privHex ?? randomIdentity().privHex;
  const env = {
    storage: {
      get: async (key) => store.get(key),
      set: async (key, value) => store.set(key, value),
    },
    transport: {
      subscriptions: [],
      subscribe(relays, filter, onEvent) {
        const sub = { relays, filter, onEvent, closed: false };
        env.transport.subscriptions.push(sub);
        return {
          close() {
            sub.closed = true;
            const i = env.transport.subscriptions.indexOf(sub);
            if (i >= 0) env.transport.subscriptions.splice(i, 1);
          },
        };
      },
      publishes: [],
      async publish(relays, event) {
        env.transport.publishes.push({ relays, event });
      },
    },
    requestApproval: overrides.requestApproval ?? (async () => 'allow'),
    now: () => overrides.now?.() ?? Date.now(),
    signerPrivHex: async () => priv,
    log: () => {},
  };
  env.priv = priv;
  env.pub = derivePubkeyHex(priv);
  env.store = store;
  return env;
}

/** Deliver a kind-24133 request event to the signer core and capture the reply. */
import { finalizeEvent } from '../src/lib/keys.js';

async function requestViaCore(env, core, client, method, params) {
  const payload = JSON.stringify({
    id: bytesToHex(randomBytes(8)),
    method,
    params,
  });
  const ciphertext = nip44Encrypt(client.priv, env.pub, payload);
  const signed = finalizeEvent(client.priv, {
    kind: 24133,
    tags: [['p', env.pub]],
    content: ciphertext,
    created_at: Math.floor(Date.now() / 1000),
  });
  let response = null;
  const origPublish = env.transport.publish;
  env.transport.publish = async (relays, ev) => {
    response = ev;
    return origPublish(relays, ev);
  };
  for (const sub of env.transport.subscriptions) await sub.onEvent(signed);
  env.transport.publish = origPublish;
  assert.ok(response, 'signer published a response');
  const plain = nip44Decrypt(client.priv, env.pub, response.content);
  return JSON.parse(plain);
}

test('buildBunkerUri: hex pubkey, relays and secret', () => {
  const uri = buildBunkerUri('a'.repeat(64), ['wss://r1', 'wss://r2'], 's3cret');
  assert.match(uri, /^bunker:\/\/a{64}\?/);
  assert.ok(uri.includes('relay=wss%3A%2F%2Fr1') || uri.includes('relay=wss://r1'));
  assert.ok(uri.includes('secret=s3cret'));
});

test('core: default settings use the Grunq bootstrap relay', async () => {
  const env = fakeEnv();
  const core = createSignerCore(env);
  const settings = await core.getRelaySettings();
  assert.deepEqual(settings.relays, DEFAULT_RELAYS);
  const map = await core.relaysMap();
  assert.deepEqual(map[DEFAULT_RELAYS[0]], { read: true, write: true });
});

test('core: connect with unknown secret is rejected', async () => {
  const env = fakeEnv();
  const core = createSignerCore(env);
  await core.start();
  const client = makeClient();
  const resp = await requestViaCore(env, core, client, 'connect', [
    env.pub,
    'wrong-secret',
    'sign_event',
    JSON.stringify({ name: 'Evil' }),
  ]);
  assert.equal(resp.error, 'error:unauthorized');
  assert.equal(resp.result, '');
});

test('core: bunker handshake connects and answers get_public_key/ping', async () => {
  const env = fakeEnv();
  env.store.set(SETTINGS_STORE, { relays: ['wss://relay.example'], idleMinutes: 30 });
  const core = createSignerCore(env);
  await core.start();
  const invite = await core.createInvite();
  assert.match(invite.uri, /^bunker:\/\//);
  const client = makeClient();

  const ack = await requestViaCore(env, core, client, 'connect', [
    env.pub,
    invite.secret,
    'sign_event,get_public_key',
    JSON.stringify({ name: 'Grunq' }),
  ]);
  assert.equal(ack.result, 'ack');
  assert.equal(ack.error, '');

  const pk = await requestViaCore(env, core, client, 'get_public_key', []);
  assert.equal(pk.result, env.pub);

  const pong = await requestViaCore(env, core, client, 'ping', []);
  assert.equal(pong.result, 'pong');

  const sessions = await core.listSessions();
  assert.equal(sessions.length, 1);
  assert.equal(sessions[0].bound, true);
  assert.equal(sessions[0].clientPub, client.pub);
  assert.equal(sessions[0].clientName, 'Grunq');
});

test('core: sign_event requires approval and returns a signed event', async () => {
  const env = fakeEnv();
  const approvals = [];
  env.requestApproval = async (info) => {
    approvals.push(info);
    return 'allow';
  };
  const core = createSignerCore(env);
  await core.start();
  const invite = await core.createInvite();
  const client = makeClient();
  await requestViaCore(env, core, client, 'connect', [env.pub, invite.secret, '', '']);

  const ev = { kind: 1, created_at: 1700000000, tags: [['t', 'test']], content: 'hello from client' };
  const resp = await requestViaCore(env, core, client, 'sign_event', [JSON.stringify(ev)]);
  const signed = JSON.parse(resp.result);
  assert.equal(signed.kind, 1);
  assert.equal(signed.pubkey, env.pub);
  assert.ok(verifyEvent(signed));
  assert.equal(approvals.length, 1);
  assert.equal(approvals[0].kind, 'nip46-sign');
  assert.equal(approvals[0].clientPub, client.pub);
  assert.equal(approvals[0].event.kind, 1);
});

test('core: denied sign_event answers error', async () => {
  const env = fakeEnv({ requestApproval: async () => 'deny' });
  const core = createSignerCore(env);
  await core.start();
  const invite = await core.createInvite();
  const client = makeClient();
  await requestViaCore(env, core, client, 'connect', [env.pub, invite.secret, '', '']);
  const resp = await requestViaCore(env, core, client, 'sign_event', [
    JSON.stringify({ kind: 1, content: 'nope', created_at: 1, tags: [] }),
  ]);
  assert.equal(resp.error, 'error:unauthorized');
  assert.equal(resp.result, '');
});

test('core: nip44 roundtrip uses the user key', async () => {
  const env = fakeEnv();
  const core = createSignerCore(env);
  await core.start();
  const invite = await core.createInvite();
  const client = makeClient();
  await requestViaCore(env, core, client, 'connect', [env.pub, invite.secret, '', '']);

  const resp = await requestViaCore(env, core, client, 'nip44_encrypt', [client.pub, 'geheimnis']);
  const cipher = resp.result;
  assert.equal(nip44Decrypt(client.priv, env.pub, cipher), 'geheimnis');

  const inner = nip44Encrypt(client.priv, env.pub, 'to decrypt');
  const dec = await requestViaCore(env, core, client, 'nip44_decrypt', [client.pub, inner]);
  assert.equal(dec.result, 'to decrypt');
});

test('core: switch_relays returns the configured relays', async () => {
  const env = fakeEnv();
  env.store.set(SETTINGS_STORE, { relays: ['wss://mine.example'], idleMinutes: 30 });
  const core = createSignerCore(env);
  await core.start();
  const invite = await core.createInvite();
  const client = makeClient();
  await requestViaCore(env, core, client, 'connect', [env.pub, invite.secret, '', '']);
  const resp = await requestViaCore(env, core, client, 'switch_relays', []);
  assert.deepEqual(JSON.parse(resp.result), ['wss://mine.example']);
});

test('core: unknown method and unknown client', async () => {
  const env = fakeEnv();
  const core = createSignerCore(env);
  await core.start();
  const invite = await core.createInvite();
  const client = makeClient();
  await requestViaCore(env, core, client, 'connect', [env.pub, invite.secret, '', '']);
  const unknown = await requestViaCore(env, core, client, 'make_coffee', []);
  assert.equal(unknown.error, 'error:unknown_method');

  // stranger (no session) asking for a signature
  const stranger = makeClient();
  const noSession = await requestViaCore(env, core, stranger, 'sign_event', ['{}']);
  assert.equal(noSession.error, 'error:unauthorized');
});

test('core: revocation cuts the client off', async () => {
  const env = fakeEnv();
  const core = createSignerCore(env);
  await core.start();
  const invite = await core.createInvite();
  const client = makeClient();
  await requestViaCore(env, core, client, 'connect', [env.pub, invite.secret, '', '']);
  const sessions = await core.listSessions();
  await core.revoke(sessions[0].id);
  const after = await requestViaCore(env, core, client, 'ping', []);
  assert.equal(after.error, 'error:unauthorized');
});

test('core: unpaired invitations expire on tick', async () => {
  const env = fakeEnv();
  let now = 1_000_000_000_000;
  env.now = () => now;
  const core = createSignerCore(env);
  await core.start();
  await core.createInvite();
  assert.equal((await core.listSessions()).length, 1);
  now += 11 * 60 * 1000; // past the 10 min invite TTL
  await core.tick();
  assert.equal((await core.listSessions()).length, 0);
});

test('core: reconnect re-binds the same secret to a new client key', async () => {
  const env = fakeEnv();
  const core = createSignerCore(env);
  await core.start();
  const invite = await core.createInvite();
  const first = makeClient();
  await requestViaCore(env, core, first, 'connect', [env.pub, invite.secret, '', '']);
  const second = makeClient(); // new ephemeral key, same bunker URI
  const ack = await requestViaCore(env, core, second, 'connect', [env.pub, invite.secret, '', '']);
  assert.equal(ack.result, 'ack');
  const sessions = await core.listSessions();
  assert.equal(sessions.length, 1);
  assert.equal(sessions[0].clientPub, second.pub);
  const pong = await requestViaCore(env, core, second, 'ping', []);
  assert.equal(pong.result, 'pong');
});

// ---------- E2E against a real relay ----------

const RELAY_WS = process.env.RELAY_WS ?? 'ws://archserver:7777';

async function relayReachable(url, timeoutMs = 5000) {
  return await new Promise((resolve) => {
    try {
      const ws = new WebSocket(url);
      const done = (ok) => {
        try { ws.close(); } catch { /* ignore */ }
        clearTimeout(timer);
        resolve(ok);
      };
      const timer = setTimeout(() => done(false), timeoutMs);
      ws.onopen = () => done(true);
      ws.onerror = () => done(false);
    } catch {
      resolve(false);
    }
  });
}

test('E2E: mini client pairs via bunker URI and signs over a real relay', { skip: !process.env.FORCE_E2E && !(await relayReachable(RELAY_WS)) ? 'relay unreachable' : false }, async (t) => {
  const env = fakeEnv();
  env.transport = new RelayPool(); // real transport for the real relay
  env.store.set(SETTINGS_STORE, { relays: [RELAY_WS], idleMinutes: 30 });
  const core = createSignerCore(env);
  await core.start();
  // give the relay REQ a moment to register
  await new Promise((r) => setTimeout(r, 500));

  const invite = await core.createInvite();
  const client = new MiniClient(invite.uri);
  await client.connect();
  t.after(() => client.close());

  const ack = await client.request('connect', [
    invite.signerPub,
    invite.secret,
    'sign_event,get_public_key',
    JSON.stringify({ name: 'MiniTest' }),
  ]);
  assert.equal(ack, 'ack');

  assert.equal(await client.request('get_public_key'), env.pub);
  assert.equal(await client.request('ping'), 'pong');

  const signedJson = await client.request('sign_event', [
    JSON.stringify({ kind: 1, created_at: Math.floor(Date.now() / 1000), tags: [['t', 'e2e']], content: 'e2e hello' }),
  ]);
  const signed = JSON.parse(signedJson);
  assert.equal(signed.pubkey, env.pub);
  assert.ok(verifyEvent(signed));

  const cipher = await client.request('nip44_encrypt', [client.pub, 'roundtrip']);
  assert.equal(nip44Decrypt(client.priv, env.pub, cipher), 'roundtrip');
});

// ---------- helpers ----------

function makeClient() {
  const id = randomIdentity();
  return { priv: id.privHex, pub: id.pubkeyHex };
}
