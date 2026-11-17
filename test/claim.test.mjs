// NIP-05 claim tests: signature roundtrip, tampering, freshness, names and the
// nostr.json editing helpers.
import assert from 'node:assert/strict';
import test from 'node:test';
import {
  CLAIM_MAX_AGE_MS,
  claimMessage,
  npubToHex,
  signClaim,
  verifyClaim,
} from '../src/signer/claim.js';
import {
  normalizeDoc,
  removeName,
  serializeDoc,
  upsertName,
} from '../src/signer/nip05store.js';
import { derivePubkeyHex, encodeNpub, randomIdentity } from '../src/lib/keys.js';

const NOW = Date.parse('2026-11-17T12:00:00.000Z');

function claim() {
  const id = randomIdentity();
  const issuedAt = '2026-11-17T11:00:00.000Z';
  const signed = signClaim({ privHex: id.privHex, name: 'luku', pubkey: id.pubkeyHex, issuedAt });
  return { id, issuedAt, signed, pubkey: id.pubkeyHex, name: 'luku' };
}

test('claim: valid signature verifies', () => {
  const { id, name, issuedAt, signed } = claim();
  assert.equal(signed.message, claimMessage(name, id.pubkeyHex, issuedAt));
  assert.deepEqual(
    verifyClaim({ pubkey: id.pubkeyHex, name, issuedAt, signature: signed.signature, now: NOW }),
    { ok: true },
  );
});

test('claim: any change invalidates the signature', () => {
  const { id, name, issuedAt, signed } = claim();
  const base = { pubkey: id.pubkeyHex, name, issuedAt, signature: signed.signature, now: NOW };
  assert.equal(verifyClaim({ ...base, name: 'other' }).ok, false, 'name is bound');
  assert.equal(verifyClaim({ ...base, issuedAt: '2026-11-17T11:01:00.000Z' }).ok, false, 'time is bound');
  const other = randomIdentity();
  assert.equal(verifyClaim({ ...base, pubkey: other.pubkeyHex }).ok, false, 'pubkey is bound');
  assert.equal(
    verifyClaim({ ...base, signature: signed.signature.replace(/^../, '00') }).ok,
    false,
    'signature is bound',
  );
});

test('claim: freshness rules', () => {
  const { id, name, issuedAt, signed } = claim();
  const base = { pubkey: id.pubkeyHex, name, issuedAt, signature: signed.signature };
  assert.equal(verifyClaim({ ...base, now: NOW + CLAIM_MAX_AGE_MS + 1000 }).code, 'stale');
  assert.equal(verifyClaim({ ...base, now: NOW - 2 * 60 * 60 * 1000 }).code, 'future');
  const issued = Date.parse(issuedAt);
  assert.equal(verifyClaim({ ...base, now: issued + CLAIM_MAX_AGE_MS - 1000 }).ok, true);
  assert.equal(verifyClaim({ ...base, now: issued + CLAIM_MAX_AGE_MS + 1000 }).code, 'stale');
});

test('claim: input validation', () => {
  const { id, signed } = claim();
  const base = { pubkey: id.pubkeyHex, name: 'luku', issuedAt: '2026-11-17T11:00:00.000Z', signature: signed.signature, now: NOW };
  assert.equal(verifyClaim({ ...base, name: 'Luku' }).code, 'invalid_name');
  assert.equal(verifyClaim({ ...base, name: 'a' }).code, 'invalid_name');
  assert.equal(verifyClaim({ ...base, pubkey: 'xyz' }).code, 'invalid_pubkey');
  assert.equal(verifyClaim({ ...base, signature: 'abc' }).code, 'bad_signature');
  assert.equal(verifyClaim({ ...base, issuedAt: 'nope' }).code, 'invalid_time');
  assert.throws(() => signClaim({ privHex: id.privHex, name: 'Bad Name', pubkey: id.pubkeyHex, issuedAt: base.issuedAt }));
});

test('claim: npub decoding', () => {
  const id = randomIdentity();
  assert.equal(npubToHex(encodeNpub(id.pubkeyHex)), id.pubkeyHex);
  assert.throws(() => npubToHex('nsec1xyz'));
});

test('nip05store: upsert adds names, relays and keeps the doc sorted', () => {
  const a = randomIdentity();
  const b = randomIdentity();
  let doc = normalizeDoc({});
  doc = upsertName(doc, { name: 'luku', pubkey: a.pubkeyHex }).doc;
  doc = upsertName(doc, { name: 'alice', pubkey: b.pubkeyHex }).doc;
  assert.deepEqual(Object.keys(doc.names), ['alice', 'luku']);
  assert.deepEqual(doc.relays[a.pubkeyHex], ['wss://relay.grunq.com']);
  assert.equal(serializeDoc(doc).endsWith('\n'), true);
  // idempotent for the same key
  const again = upsertName(doc, { name: 'luku', pubkey: a.pubkeyHex });
  assert.equal(again.created, false);
  assert.equal(again.doc.names.luku, a.pubkeyHex);
});

test('nip05store: a name owned by another key is refused', () => {
  const a = randomIdentity();
  const b = randomIdentity();
  const doc = upsertName(normalizeDoc({}), { name: 'luku', pubkey: a.pubkeyHex }).doc;
  assert.throws(
    () => upsertName(doc, { name: 'luku', pubkey: b.pubkeyHex }),
    (e) => e.code === 'name_taken',
  );
  // Replacing explicitly is still possible by removing first.
  const { doc: without, removed } = removeName(doc, 'luku');
  assert.equal(removed, true);
  assert.equal(without.names.luku, undefined);
  assert.equal(upsertName(without, { name: 'luku', pubkey: b.pubkeyHex }).doc.names.luku, b.pubkeyHex);
});

test('nip05store: normalize drops invalid entries and sorts relays', () => {
  const id = randomIdentity();
  const doc = normalizeDoc({
    names: { luku: id.pubkeyHex, 'Bad Name': id.pubkeyHex, x: 'npub1nope' },
    relays: {
      [id.pubkeyHex]: ['wss://b.example', 'wss://a.example', 'wss://a.example', 'http://x'],
      nothex: ['wss://x'],
    },
  });
  assert.deepEqual(Object.keys(doc.names), ['luku']);
  assert.deepEqual(doc.relays[id.pubkeyHex], ['wss://a.example', 'wss://b.example']);
  assert.equal(doc.relays.nothex, undefined);
});
