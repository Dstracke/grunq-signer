// Audit log tests: bounded storage, newest-first listing, per-client and
// per-origin filters, clearing.
import assert from 'node:assert/strict';
import test from 'node:test';
import { AUDIT_LIMIT, AUDIT_STORE, createAuditLog } from '../src/signer/audit.js';

function fakeStorage() {
  const map = new Map();
  return {
    map,
    async get(key) {
      return map.get(key);
    },
    async set(key, value) {
      map.set(key, value);
    },
  };
}

test('audit: records entries newest first with scope and outcome', async () => {
  const storage = fakeStorage();
  let clock = 1000;
  const audit = createAuditLog({ storage, now: () => clock++ });
  await audit.record({ scope: 'nip46', method: 'sign_event', kind: 1311, clientPub: 'a'.repeat(64), clientName: 'Grunq-Knoten' });
  await audit.record({ scope: 'nip46', method: 'nip44_decrypt', ok: false, code: 'unauthorized', clientPub: 'a'.repeat(64) });
  await audit.record({ scope: 'nip07', method: 'signEvent', origin: 'http://localhost:8080', kind: 1 });
  const list = await audit.list();
  assert.equal(list.length, 3);
  assert.deepEqual(list.map((e) => e.method), ['signEvent', 'nip44_decrypt', 'sign_event']);
  assert.equal(list[0].scope, 'nip07');
  assert.equal(list[1].ok, false);
  assert.equal(list[1].code, 'unauthorized');
  assert.equal(list[2].kind, 1311);
  assert.equal(list[2].clientName, 'Grunq-Knoten');
});

test('audit: filters by client and origin, caps per session', async () => {
  const storage = fakeStorage();
  const audit = createAuditLog({ storage });
  const client = 'c'.repeat(64);
  for (let i = 0; i < 60; i++) {
    await audit.record({ scope: 'nip46', method: 'sign_event', kind: 1311, clientPub: client });
  }
  await audit.record({ scope: 'nip07', method: 'signEvent', origin: 'https://example.org', kind: 1 });
  const mine = await audit.list({ clientPub: client });
  assert.equal(mine.length, 50, 'per-session cap');
  assert.ok(mine.every((e) => e.clientPub === client));
  const site = await audit.list({ origin: 'https://example.org' });
  assert.equal(site.length, 1);
  assert.equal(site[0].origin, 'https://example.org');
});

test('audit: storage stays bounded', async () => {
  const storage = fakeStorage();
  const audit = createAuditLog({ storage, limit: 5 });
  for (let i = 0; i < 8; i++) await audit.record({ scope: 'nip46', method: 'ping', clientPub: 'k' });
  const all = storage.map.get(AUDIT_STORE);
  assert.equal(all.length, 5);
  assert.equal((await audit.list()).length, 5);
  assert.equal(AUDIT_LIMIT, 300);
});

test('audit: ignores malformed entries and clears', async () => {
  const storage = fakeStorage();
  const audit = createAuditLog({ storage });
  assert.equal(await audit.record(null), null);
  assert.equal(await audit.record({ scope: 'nip46' }), null);
  await audit.record({ scope: 'nip46', method: 'get_public_key', clientPub: 'x' });
  await audit.clear();
  assert.deepEqual(await audit.list(), []);
});
