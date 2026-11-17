// Backup bundle tests: sealing/opening, wrong passphrase, tampering and the
// file format guards. Work factor is lowered for speed; the primitives are the
// same as NIP-49 (covered against the official vector in nip49.test.mjs).
import assert from 'node:assert/strict';
import test from 'node:test';
import {
  BACKUP_FORMAT,
  openBundle,
  openBundleText,
  sealBundle,
} from '../src/lib/bundle.js';

const DATA = { kind: 'grunq-signer-identities', items: [{ label: 'Streamer', secret: { privHex: 'a'.repeat(64) } }] };

test('bundle: seal/open roundtrip', () => {
  const file = sealBundle(DATA, 'mein-langes-passwort', { logN: 12 });
  assert.equal(file.format, BACKUP_FORMAT);
  assert.equal(file.version, 1);
  assert.equal(file.kdf.name, 'scrypt');
  assert.equal(file.cipher.name, 'xchacha20poly1305');
  assert.match(file.payload, /^[0-9a-f]+$/);
  assert.deepEqual(openBundle(file, 'mein-langes-passwort'), DATA);
});

test('bundle: wrong passphrase is rejected without leaking data', () => {
  const file = sealBundle(DATA, 'mein-langes-passwort', { logN: 12 });
  assert.throws(() => openBundle(file, 'falsch'), (e) => e.code === 'wrong_password');
});

test('bundle: the payload is bound to the format (tamper detection)', () => {
  const file = sealBundle(DATA, 'mein-langes-passwort', { logN: 12 });
  const tampered = { ...file, payload: file.payload.replace(/^../, '00') };
  assert.equal(tampered.payload === file.payload ? 'no-change' : 'changed', 'changed');
  assert.throws(() => openBundle(tampered, 'mein-langes-passwort'), (e) => e.code === 'wrong_password');
});

test('bundle: rejects foreign or broken files', () => {
  assert.throws(() => openBundle(null, 'x'), (e) => e.code === 'invalid_backup');
  assert.throws(() => openBundle({ format: 'other' }, 'x'), (e) => e.code === 'invalid_backup');
  const file = sealBundle(DATA, 'pw-123456', { logN: 12 });
  assert.throws(
    () => openBundle({ ...file, version: 99 }, 'pw-123456'),
    (e) => e.code === 'invalid_backup',
  );
  assert.throws(
    () => openBundle({ ...file, kdf: { ...file.kdf, salt: 'zz' } }, 'pw-123456'),
    (e) => e.code === 'invalid_backup',
  );
  assert.throws(() => openBundleText('not json', 'x'), (e) => e.code === 'invalid_backup');
});

test('bundle: text roundtrip and NFKC-normalized passphrases', () => {
  const file = sealBundle(DATA, '\u212B\u2126\u1E9B\u0323', { logN: 12 });
  const text = JSON.stringify(file);
  assert.deepEqual(openBundleText(text, '\u00C5\u03A9\u1E69'), DATA);
});

test('bundle: rejects weak or missing passwords on sealing', () => {
  assert.throws(() => sealBundle(DATA, ''), /password required/);
  assert.throws(() => sealBundle(DATA, 'pw', { logN: 30 }), /out of range/);
});
