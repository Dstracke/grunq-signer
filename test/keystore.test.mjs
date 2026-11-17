// Key store tests: multiple identities, migration from the single-identity
// layout, NIP-49 protection per identity, unlock/lock, auto-lock, session
// scoping and removal. scrypt uses a low work factor so the suite stays fast.
import assert from 'node:assert/strict';
import test from 'node:test';
import {
  IDENTITIES_STORE,
  MIN_PASSWORD_LENGTH,
  UNLOCK_STORE,
  createKeystore,
  profileKey,
  sessionsKey,
} from '../src/signer/keystore.js';
import { encodeNsec, randomIdentity } from '../src/lib/keys.js';
import { sealBundle } from '../src/lib/bundle.js';

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

function setup() {
  const local = memoryStore();
  const session = memoryStore();
  let clock = 1_700_000_000_000;
  let seq = 0;
  const ks = createKeystore({
    local,
    session,
    now: () => clock,
    logN: 12,
    newId: () => `id-${++seq}`,
  });
  return { ks, local, session, tick: (ms) => (clock += ms) };
}

const active = (db) => db.items.find((i) => i.id === db.active);

test('keystore: starts empty and reports no identity', async () => {
  const { ks } = setup();
  assert.deepEqual(await ks.status(), {
    hasKey: false,
    count: 0,
    encrypted: false,
    unlocked: false,
    created: null,
    label: '',
  });
  assert.deepEqual(await ks.list(), []);
  await assert.rejects(ks.privateKeyHex(), (e) => e.code === 'no_key');
});

test('keystore: import creates the first identity and makes it active', async () => {
  const { ks, local } = setup();
  const id = randomIdentity();
  const item = await ks.importSecret(encodeNsec(id.privHex), 'Streamer');
  assert.equal(item.label, 'Streamer');
  assert.equal(item.pubkey, id.pubkeyHex);
  assert.match(item.npub, /^npub1/);
  assert.equal(await ks.privateKeyHex(), id.privHex);
  assert.equal(await ks.pubkeyHex(), id.pubkeyHex);
  const db = local.map.get(IDENTITIES_STORE);
  assert.equal(db.items.length, 1);
  assert.equal(db.active, item.id);
  assert.equal(active(db).secret.privHex, id.privHex);
});

test('keystore: a second identity switches the active key', async () => {
  const { ks, local } = setup();
  const a = randomIdentity();
  const b = randomIdentity();
  const itemA = await ks.importSecret(a.privHex, 'Streamer');
  const itemB = await ks.importSecret(b.privHex, 'Chat');
  assert.equal(await ks.privateKeyHex(), b.privHex, 'newest import becomes active');
  assert.equal(await ks.status().then((s) => s.label), 'Chat');
  assert.equal((await ks.status()).count, 2);

  const list = await ks.list();
  assert.equal(list.length, 2);
  assert.equal(list.find((i) => i.id === itemB.id).active, true);
  assert.equal(list.find((i) => i.id === itemA.id).active, false);

  await ks.switchTo(itemA.id);
  assert.equal(await ks.privateKeyHex(), a.privHex);
  const db = local.map.get(IDENTITIES_STORE);
  assert.equal(db.active, itemA.id);
});

test('keystore: protect/lock/unlock work per identity', async () => {
  const { ks, session } = setup();
  const a = randomIdentity();
  const b = randomIdentity();
  const itemA = await ks.importSecret(a.privHex, 'A');
  await ks.importSecret(b.privHex, 'B');
  // Protect the active identity (B) only.
  await ks.protect('mein-langes-passwort');
  assert.equal((await ks.status()).encrypted, true);
  await ks.switchTo(itemA.id);
  assert.equal((await ks.status()).encrypted, false, 'A is still plaintext');

  await ks.switchTo((await ks.list()).find((i) => i.label === 'B').id);
  await ks.lock();
  assert.equal((await ks.status()).unlocked, false);
  await assert.rejects(ks.privateKeyHex(), (e) => e.code === 'locked');
  assert.equal(await ks.pubkeyHex(), b.pubkeyHex, 'public key readable while locked');
  await assert.rejects(ks.unlock('falsches-passwort'), (e) => e.code === 'wrong_password');
  await ks.unlock('mein-langes-passwort');
  assert.equal(await ks.privateKeyHex(), b.privHex);
  const unlocks = session.map.get(UNLOCK_STORE);
  assert.ok(Object.keys(unlocks).length >= 1);
});

test('keystore: re-keying keeps the identity and rejects the old passphrase', async () => {
  const { ks } = setup();
  const id = randomIdentity();
  await ks.importSecret(id.privHex);
  await ks.protect('altes-passwort');
  const { ncryptsec } = await ks.protect('neues-passwort');
  assert.match(ncryptsec, /^ncryptsec1/);
  await ks.lock();
  await assert.rejects(ks.unlock('altes-passwort'), (e) => e.code === 'wrong_password');
  await ks.unlock('neues-passwort');
  assert.equal(await ks.pubkeyHex(), id.pubkeyHex);
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

test('keystore: auto-lock drops idle keys and reports the active lock', async () => {
  const { ks, tick } = setup();
  await ks.generate('A');
  await ks.protect('mein-langes-passwort');
  tick(29 * 60 * 1000);
  assert.equal(await ks.autoLockIfIdle(30), false, 'not idle yet');
  tick(2 * 60 * 1000);
  assert.equal(await ks.autoLockIfIdle(30), true);
  assert.equal((await ks.status()).unlocked, false);

  await ks.unlock('mein-langes-passwort');
  tick(20 * 60 * 1000);
  await ks.touch();
  tick(20 * 60 * 1000);
  assert.equal(await ks.autoLockIfIdle(30), false, 'touch postpones the lock');
});

test('keystore: auto-lock never touches plaintext identities', async () => {
  const { ks, tick } = setup();
  await ks.generate();
  tick(24 * 60 * 60 * 1000);
  assert.equal(await ks.autoLockIfIdle(1), false);
});

test('keystore: ncryptsec import needs the passphrase and unlocks', async () => {
  const { ks } = setup();
  const id = randomIdentity();
  await ks.importSecret(id.privHex);
  const { ncryptsec } = await ks.protect('mein-langes-passwort');
  await ks.remove();

  await assert.rejects(ks.importNcryptsec(ncryptsec, 'falsch'), (e) => e.code === 'wrong_password');
  const item = await ks.importNcryptsec(ncryptsec, 'mein-langes-passwort', 'Backup');
  assert.equal(item.pubkey, id.pubkeyHex);
  assert.equal(item.encrypted, true);
  assert.equal(item.unlocked, true);
  assert.equal(await ks.privateKeyHex(), id.privHex);
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

test('keystore: unprotect writes the plaintext secret back', async () => {
  const { ks, local } = setup();
  const id = randomIdentity();
  await ks.importSecret(id.privHex);
  await ks.protect('mein-langes-passwort');
  assert.ok((await ks.exportNcryptsec()).ncryptsec.startsWith('ncryptsec1'));
  await ks.unprotect();
  assert.equal(active(local.map.get(IDENTITIES_STORE)).secret.privHex, id.privHex);
  assert.equal((await ks.status()).encrypted, false);
  assert.equal(await ks.exportNcryptsec(), null);
});

test('keystore: removing an identity falls back to the most recent remaining', async () => {
  const { ks } = setup();
  const a = randomIdentity();
  const b = randomIdentity();
  const itemA = await ks.importSecret(a.privHex, 'A');
  const itemB = await ks.importSecret(b.privHex, 'B');
  await ks.removeIdentity(itemB.id);
  assert.equal((await ks.status()).count, 1);
  assert.equal(await ks.pubkeyHex(), a.pubkeyHex);
  await ks.removeIdentity(itemA.id);
  assert.equal((await ks.status()).hasKey, false);
});

test('keystore: rename keeps the key and trims the label', async () => {
  const { ks } = setup();
  const id = randomIdentity();
  const item = await ks.importSecret(id.privHex, 'Alt');
  const renamed = await ks.rename(item.id, '  Chat-Key  ');
  assert.equal(renamed.label, 'Chat-Key');
  assert.equal(await ks.privateKeyHex(), id.privHex);
});

test('keystore: backup exports all identities and imports them elsewhere', async () => {
  const source = setup();
  const a = randomIdentity();
  const b = randomIdentity();
  await source.ks.importSecret(a.privHex, 'Streamer');
  await source.ks.importSecret(b.privHex, 'Chat');
  await source.ks.protect('mein-langes-passwort'); // protects the active (Chat)
  const { file, count } = await source.ks.exportBackup('backup-passphrase', 'backup-passphrase');
  assert.equal(count, 2);
  assert.equal(file.format, 'grunq-signer-backup');
  assert.match(file.payload, /^[0-9a-f]+$/);

  const target = setup();
  await assert.rejects(
    target.ks.importBackup(JSON.stringify(file), 'falsch'),
    (e) => e.code === 'wrong_password',
  );
  const res = await target.ks.importBackup(JSON.stringify(file), 'backup-passphrase');
  assert.deepEqual(res, { added: 2, skipped: 0, count: 2, profiles: {} });
  const list = await target.ks.list();
  assert.deepEqual(list.map((i) => i.label).sort(), ['Chat', 'Streamer']);
  assert.equal(list.find((i) => i.label === 'Chat').encrypted, true);
  assert.equal(list.filter((i) => i.active).length, 1);
  // The plaintext identity is usable right away, the encrypted one is locked.
  assert.equal(await target.ks.list().then((l) => l.find((i) => i.label === 'Streamer').unlocked), true);
});

test('keystore: backup import merges, skips duplicates and can replace', async () => {
  const source = setup();
  const a = randomIdentity();
  await source.ks.importSecret(a.privHex, 'Streamer');
  const { file } = await source.ks.exportBackup('backup-passphrase');

  const target = setup();
  const own = randomIdentity();
  await target.ks.importSecret(own.privHex, 'Own');
  assert.deepEqual(await target.ks.importBackup(JSON.stringify(file), 'backup-passphrase'), {
    added: 1,
    skipped: 0,
    count: 2,
    profiles: {},
  });
  // Importing the same backup again skips the duplicate and keeps the active
  // identity (the local "Own" key).
  assert.deepEqual(await target.ks.importBackup(JSON.stringify(file), 'backup-passphrase'), {
    added: 0,
    skipped: 1,
    count: 2,
    profiles: {},
  });
  assert.equal(await target.ks.pubkeyHex(), own.pubkeyHex, 'active identity unchanged');

  // replace=true drops the local identity first.
  const res = await target.ks.importBackup(JSON.stringify(file), 'backup-passphrase', { replace: true });
  assert.deepEqual(res, { added: 1, skipped: 0, count: 1, profiles: {} });
  assert.equal(await target.ks.pubkeyHex(), a.pubkeyHex);
});

test('keystore: backup carries extra profile data', async () => {
  const source = setup();
  const id = randomIdentity();
  await source.ks.importSecret(id.privHex, 'Streamer');
  const profiles = { [id.pubkeyHex]: { fields: { name: 'alice', website: 'https://example.org/' }, publishedAt: 123 } };
  const { file } = await source.ks.exportBackup('backup-passphrase', undefined, { profiles });
  const target = setup();
  const res = await target.ks.importBackup(JSON.stringify(file), 'backup-passphrase');
  assert.deepEqual(res.profiles, profiles);
  assert.equal(res.added, 1);
});

test('keystore: backup import refuses broken files and mismatched keys', async () => {
  const ks = setup();
  await assert.rejects(ks.ks.importBackup('not json', 'x'), (e) => e.code === 'invalid_backup');
  await assert.rejects(
    ks.ks.importBackup(JSON.stringify({ format: 'other' }), 'x'),
    (e) => e.code === 'invalid_backup',
  );

  // A payload whose privHex does not derive the advertised pubkey is skipped.
  const other = randomIdentity();
  const fake = sealBundle(
    {
      kind: 'grunq-signer-identities',
      version: 2,
      items: [
        { label: 'Fake', pubkey: other.pubkeyHex, secret: { privHex: 'b'.repeat(64) } },
        { label: 'Kein Secret', pubkey: 'c'.repeat(64) },
      ],
    },
    'backup-passphrase',
    { logN: 12 },
  );
  assert.deepEqual(await ks.ks.importBackup(JSON.stringify(fake), 'backup-passphrase'), {
    added: 0,
    skipped: 0,
    count: 0,
    profiles: {},
  });
});

test('keystore: migrates the legacy single-identity storage', async () => {
  const { ks, local, session } = setup();
  const legacy = randomIdentity();
  // Prefill the v1 layout before the keystore is used (setup() does not touch
  // storage until a method runs).
  local.map.set('grunq_signer:key', { privHex: legacy.privHex, created: 1_600_000_000_000 });
  local.map.set('grunq_signer:identity', { pubkey: legacy.pubkeyHex, created: 1_600_000_000_000 });
  local.map.set('grunq_signer:sessions', [{ secret: 'abc', bound: true, relays: ['wss://r'] }]);
  local.map.set('grunq_signer:profile', { fields: { name: 'legacy' }, publishedAt: 42 });
  session.map.set('grunq_signer:session', { privHex: legacy.privHex, unlockedAt: 1_600_000_100_000 });

  const status = await ks.status();
  assert.equal(status.hasKey, true);
  assert.equal(status.created, 1_600_000_000_000);

  const item = active(local.map.get(IDENTITIES_STORE));
  assert.equal(item.secret.privHex, legacy.privHex);
  assert.equal(item.pubkey, legacy.pubkeyHex);
  assert.equal(item.created, 1_600_000_000_000);

  // The decrypted key was carried into the per-identity unlock map.
  assert.equal(session.map.get(UNLOCK_STORE)[item.id].privHex, legacy.privHex);
  assert.equal(session.map.get(UNLOCK_STORE)[item.id].unlockedAt, 1_600_000_100_000);

  // NIP-46 sessions and the profile moved into the identity namespace.
  assert.equal(local.map.get(sessionsKey(item.id))[0].secret, 'abc');
  assert.equal(local.map.get(profileKey(item.id)).fields.name, 'legacy');

  // Legacy keys are gone.
  assert.equal(local.map.get('grunq_signer:key'), undefined);
  assert.equal(local.map.get('grunq_signer:identity'), undefined);
  assert.equal(local.map.get('grunq_signer:sessions'), undefined);
  assert.equal(local.map.get('grunq_signer:profile'), undefined);
  assert.equal(session.map.get('grunq_signer:session'), undefined);

  assert.equal(await ks.privateKeyHex(), legacy.privHex);
  assert.equal(await ks.pubkeyHex(), legacy.pubkeyHex);
});
