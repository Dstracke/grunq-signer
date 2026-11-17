// Profile (kind 0) tests: sanitizing, publishing to relays, reading the
// newest profile back (multi-relay, dedupe, timeout) and NIP-09 deletion.
// Signing is the real BIP-340 path with a throwaway key; the transport is a
// fake that records publishes and lets the test emit events.
import assert from 'node:assert/strict';
import test from 'node:test';
import {
  PROFILE_STORE,
  PROFILE_FIELDS,
  createProfileService,
  planRepublish,
  sanitizeProfile,
} from '../src/signer/profile.js';
import { derivePubkeyHex, finalizeEvent, randomIdentity } from '../src/lib/keys.js';

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

function fakeTransport() {
  const publishes = [];
  const subs = [];
  return {
    publishes,
    subs,
    async publish(relays, event) {
      publishes.push({ relays, event });
    },
    subscribe(relays, filter, onEvent) {
      const sub = { relays, filter, onEvent, closed: false };
      subs.push(sub);
      return {
        close: () => {
          sub.closed = true;
        },
      };
    },
    emit(sub, event) {
      sub.onEvent(event);
    },
  };
}

function setup() {
  const id = randomIdentity();
  const storage = fakeStorage();
  const transport = fakeTransport();
  const service = createProfileService({ storage, transport, now: () => 1_700_000_000_000 });
  const sign = async (draft) => finalizeEvent(id.privHex, draft, 1_700_000_000);
  return { id, service, storage, transport, sign };
}

test('profile: sanitize keeps known fields, trims and caps lengths', () => {
  const clean = sanitizeProfile({
    name: '  luku  ',
    display_name: 'Nostr Fan',
    about: 'x'.repeat(5000),
    picture: 'https://example.org/a.png',
    nip05: 'name@example.com',
    lud16: 'name@wallet.example',
    website: 'https://ignored.example',
    bot: true,
    extra: 42,
  });
  assert.deepEqual(Object.keys(clean), ['name', 'display_name', 'about', 'picture', 'nip05', 'lud16']);
  assert.equal(clean.name, 'luku');
  assert.equal(clean.about.length, PROFILE_FIELDS.about);
  assert.equal(clean.website, undefined);
  assert.deepEqual(sanitizeProfile(null), {});
  assert.deepEqual(sanitizeProfile({ name: '   ' }), {});
});

test('profile: publish signs a kind 0 and stores event id + fields', async () => {
  const { id, service, storage, transport, sign } = setup();
  const res = await service.publish(
    { name: 'nostr', display_name: 'Nostr Fan', about: 'streaming notes', lud16: 'name@wallet.example' },
    ['wss://relay.grunq.com'],
    sign,
  );
  assert.match(res.eventId, /^[0-9a-f]{64}$/);
  const sent = transport.publishes.at(-1);
  assert.deepEqual(sent.relays, ['wss://relay.grunq.com']);
  assert.equal(sent.event.kind, 0);
  assert.equal(sent.event.pubkey, derivePubkeyHex(id.privHex));
  assert.deepEqual(JSON.parse(sent.event.content), {
    name: 'nostr',
    display_name: 'Nostr Fan',
    about: 'streaming notes',
    lud16: 'name@wallet.example',
  });
  const stored = storage.map.get(PROFILE_STORE);
  assert.equal(stored.eventId, res.eventId);
  assert.equal(stored.publishedAt, 1_700_000_000_000);
  assert.deepEqual((await service.load()).fields.name, 'nostr');
});

test('profile: publish rejects empty profiles and missing relays', async () => {
  const { service, sign } = setup();
  await assert.rejects(service.publish({}, ['wss://relay'], sign), (e) => e.code === 'empty_profile');
  await assert.rejects(service.publish({ name: 'x' }, [], sign), (e) => e.code === 'no_relays');
});

test('profile: a failed publish keeps the locally saved fields', async () => {
  const { service, storage } = setup();
  const broken = async () => {
    throw new Error('no relay accepted the event');
  };
  await assert.rejects(service.publish({ name: 'nostr' }, ['wss://relay'], broken), /no relay/);
  assert.deepEqual(storage.map.get(PROFILE_STORE).fields, { name: 'nostr' });
  assert.equal(storage.map.get(PROFILE_STORE).eventId, undefined);
});

test('profile: fetchLatest picks the newest event across relays', async () => {
  const { id, service, transport, sign } = setup();
  const me = derivePubkeyHex(id.privHex);
  const publish = async (content, created) => {
    const ev = finalizeEvent(id.privHex, { kind: 0, created_at: created, tags: [], content: JSON.stringify(content) }, created);
    transport.emit(transport.subs.at(-1), ev);
  };
  // The fetch subscribes first, then events trickle in from two relays.
  const pending = service.fetchLatest(me, ['wss://a', 'wss://b'], { graceMs: 20, timeoutMs: 1000 });
  await publish({ name: 'alt' }, 1000);
  await publish({ name: 'neu', about: 'aktuell' }, 2000);
  const fields = await pending;
  assert.equal(fields.name, 'neu');
  assert.equal(fields.about, 'aktuell');
  assert.equal(transport.subs[0].filter.authors[0], me);
  assert.ok(transport.subs[0].closed, 'subscription is closed after the fetch');
  assert.equal(transport.publishes.length, 0, 'fetching never publishes');
  // Signing was not needed for reading.
  assert.equal(typeof sign, 'function');
});

test('profile: fetchLatest resolves null when nothing arrives', async () => {
  const { id, service } = setup();
  const me = derivePubkeyHex(id.privHex);
  const fields = await service.fetchLatest(me, ['wss://a'], { graceMs: 10, timeoutMs: 40 });
  assert.equal(fields, null);
});

test('profile: delete publishes NIP-09 with e and a tags and clears the store', async () => {
  const { id, service, storage, transport, sign } = setup();
  const me = derivePubkeyHex(id.privHex);
  const { eventId } = await service.publish({ name: 'nostr' }, ['wss://relay'], sign);
  await service.remove(me, ['wss://relay'], sign);
  const del = transport.publishes.at(-1).event;
  assert.equal(del.kind, 5);
  assert.deepEqual(del.tags, [['e', eventId], ['a', `0:${me}:`]]);
  assert.equal(storage.map.get(PROFILE_STORE).eventId, null);
  assert.deepEqual(storage.map.get(PROFILE_STORE).fields, {});
});

test('profile: planRepublish names only the relays missing the profile', () => {
  const local = { fields: { name: 'nostr' }, publishedAt: 1_700_000_000_000 };
  const perRelay = [
    { relay: 'wss://a', present: true },
    { relay: 'wss://b', present: false },
    { relay: 'wss://c', present: false },
  ];
  assert.deepEqual(planRepublish(local, perRelay), ['wss://b', 'wss://c']);
  // Nothing to repair when the local side never published.
  assert.deepEqual(planRepublish({ fields: { name: 'x' }, publishedAt: null }, perRelay), []);
  assert.deepEqual(planRepublish({ fields: {}, publishedAt: 1 }, perRelay), []);
  assert.deepEqual(planRepublish(local, []), []);
  // Everything present -> nothing to do.
  assert.deepEqual(
    planRepublish(local, perRelay.map((r) => ({ ...r, present: true }))),
    [],
  );
});

test('profile: delete without a published profile is refused', async () => {
  const { id, service, sign } = setup();
  await assert.rejects(
    service.remove(derivePubkeyHex(id.privHex), ['wss://relay'], sign),
    (e) => e.code === 'no_profile',
  );
});
