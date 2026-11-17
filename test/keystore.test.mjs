// Key store tests: plaintext and NIP-49-encrypted identities, unlock/lock,
// auto-lock after idle, export gating and removal. scrypt is driven with a
// low work factor (2^12) so the suite stays fast; the wire format is covered
// by test/nip49.test.mjs against the official vector.
import assert from 'node:assert/strict';
import test from 'node:test';
import {
  IDENTITY_STORE,
  KEY_STORE,
  MIN_PASSWORD_LENGTH,
  SESSION_STORE,
  createKeystore,
} from '../src/signer/keystore.js';
import { encodeNsec, randomIdentity } from '../src/lib/keys.js';

function memoryStore() {
  const map = new Map();
  return {
    map,
    async get(key) {
      return map.get(key);
    },
    async set(key, value) {
      map.set(key, value);
    },
    async remove(key) {
      map.delete(key);
    },
  };
}

function setup({ logN = 12 } = {}) {
  const local = memoryStore();
  const session = memoryStore();
  let clock = 1_700_000_000_000;
  const ks = createKeystore({ local, session, now: () => clock, logN });
  return { ks, local, session, tick: (ms) => (clock += ms) };
}

test('keystore: import stores a plaintext identity and reports unlocked', async () => {
  const { ks, local } = setup();
  const id = randomIdentity();
  await ks.importSecret(encodeNsec(id.privHex));
  assert.deepEqual(await ks.status(), {
    hasKey: true,
    encrypted: false,
    unlocked: true,
    created: 1_700_000_000_000,
  });
  assert.equal(await ks.privateKeyHex(), id.privHex);
  assert.equal(await ks.pubkeyHex(), id.pubkeyHex);
  assert.equal(local.map.get(KEY_STORE).privHex, id.privHex);
});

test('keystore: generate creates a fresh identity', async () => {
  const { ks } = setup();
  const { pubkey } = await ks.generate();
  assert.equal(await ks.pubkeyHex(), pubkey);
  assert.match(await ks.npub(), /^npub1/);
});

test('keystore: protect encrypts at rest and keeps working until locked', async () => {
  const { ks, local, session } = setup();
  const id = randomIdentity();
  await ks.importSecret(encodeNsec(id.privHex));
  const { ncryptsec } = await ks.protect('secret-passphrase', 'secret-passphrase');
  assert.match(ncryptsec, /^ncryptsec1/);
  const stored = local.map.get(KEY_STORE);
  assert.equal(stored.privHex, undefined, 'plaintext key must be gone');
  assert.equal(stored.ncryptsec, ncryptsec);
  assert.equal((await ks.status()).encrypted, true);
  assert.equal((await ks.status()).unlocked, true, 'protecting keeps the session open');
  assert.equal(await ks.privateKeyHex(), id.privHex);
  assert.equal(session.map.get(SESSION_STORE).privHex, id.privHex);

  await ks.lock();
  assert.equal((await ks.status()).unlocked, false);
  await assert.rejects(ks.privateKeyHex(), (e) => e.code === 'locked');
  // The public identity stays readable while locked.
  assert.equal(await ks.pubkeyHex(), id.pubkeyHex);
});

test('keystore: unlock with the right passphrase, reject the wrong one', async () => {
  const { ks } = setup();
  const id = randomIdentity();
  await ks.importSecret(id.privHex);
  await ks.protect('mein-langes-passwort');
  await ks.lock();
  await assert.rejects(ks.unlock('falsches-passwort'), (e) => e.code === 'wrong_password');
  assert.equal((await ks.status()).unlocked, false);
  const res = await ks.unlock('mein-langes-passwort');
  assert.equal(res.encrypted, true);
  assert.deepEqual(res.npub, await ks.npub());
  assert.equal(await ks.privateKeyHex(), id.privHex);
});

test('keystore: re-keying (change passphrase) keeps the identity', async () => {
  const { ks } = setup();
  const id = randomIdentity();
  await ks.importSecret(id.privHex);
  await ks.protect('altes-passwort');
  const { ncryptsec } = await ks.protect('neues-passwort');
  assert.match(ncryptsec, /^ncryptsec1/);
  await ks.lock();
  await assert.rejects(ks.unlock('altes-passwort'), (e) => e.code === 'wrong_password');
  const res = await ks.unlock('neues-passwort');
  assert.deepEqual(res.npub, await ks.npub());
});

test('keystore: passphrase policy (length + repeat)', async () => {
  const { ks } = setup();
  await ks.generate();
  await assert.rejects(ks.protect('kurz'), (e) => e.code === 'weak_password');
  await assert.rejects(
    ks.protect('lang-genug-1', 'lang-genug-2'),
    (e) => e.code === 'password_mismatch',
  );
  assert.equal(MIN_PASSWORD_LENGTH, 8);
});

test('keystore: auto-lock drops the session key after idle minutes', async () => {
  const { ks, tick } = setup();
  await ks.generate();
  await ks.protect('mein-langes-passwort');
  tick(29 * 60 * 1000);
  assert.equal(await ks.autoLockIfIdle(30), false, 'not idle yet');
  tick(2 * 60 * 1000);
  assert.equal(await ks.autoLockIfIdle(30), true);
  assert.equal((await ks.status()).unlocked, false);
  // A touch before the deadline postpones the lock again.
  await ks.unlock('mein-langes-passwort');
  tick(20 * 60 * 1000);
  await ks.touch();
  tick(20 * 60 * 1000);
  assert.equal(await ks.autoLockIfIdle(30), false);
});

test('keystore: auto-lock never touches plaintext identities', async () => {
  const { ks, tick } = setup();
  await ks.generate();
  tick(24 * 60 * 60 * 1000);
  assert.equal(await ks.autoLockIfIdle(30), false);
  assert.equal(await ks.autoLockIfIdle(1), false);
});

test('keystore: import of an ncryptsec requires the passphrase and unlocks', async () => {
  const { ks } = setup();
  const id = randomIdentity();
  await ks.importSecret(id.privHex);
  const { ncryptsec } = await ks.protect('mein-langes-passwort');
  await ks.remove();

  await assert.rejects(ks.importNcryptsec(ncryptsec, 'falsch'), (e) => e.code === 'wrong_password');
  assert.equal((await ks.status()).hasKey, false);
  const res = await ks.importNcryptsec(ncryptsec, 'mein-langes-passwort');
  assert.equal(res.pubkey, id.pubkeyHex);
  assert.equal((await ks.status()).encrypted, true);
  assert.equal((await ks.status()).unlocked, true);
});

test('keystore: nsec export needs confirmation and an unlocked store', async () => {
  const { ks } = setup();
  const id = randomIdentity();
  await ks.importSecret(id.privHex);
  await assert.rejects(ks.exportNsec(false), (e) => e.code === 'denied');
  assert.equal((await ks.exportNsec(true)).nsec, encodeNsec(id.privHex));

  await ks.protect('mein-langes-passwort');
  await ks.lock();
  await assert.rejects(ks.exportNsec(true), (e) => e.code === 'locked');
});

test('keystore: unprotect writes the plaintext key back', async () => {
  const { ks, local } = setup();
  const id = randomIdentity();
  await ks.importSecret(id.privHex);
  await ks.protect('mein-langes-passwort');
  assert.equal((await ks.exportNcryptsec()).ncryptsec.startsWith('ncryptsec1'), true);
  await ks.unprotect();
  assert.equal(local.map.get(KEY_STORE).privHex, id.privHex);
  assert.equal((await ks.status()).encrypted, false);
  assert.equal(await ks.exportNcryptsec(), null);
});

test('keystore: remove deletes key, identity and session', async () => {
  const { ks, local, session } = setup();
  await ks.generate();
  await ks.protect('mein-langes-passwort');
  await ks.remove();
  assert.equal((await ks.status()).hasKey, false);
  assert.equal(local.map.get(IDENTITY_STORE), undefined);
  assert.equal(session.map.get(SESSION_STORE), undefined);
  await assert.rejects(ks.privateKeyHex(), (e) => e.code === 'no_key');
});
