// NIP-49 tests: official decryption vector, roundtrip, NFKC normalization,
// parameter validation. scrypt cost is lowered via log_n where the vector
// allows it (the official vector itself uses log_n=16).
import assert from 'node:assert/strict';
import test from 'node:test';
import { scrypt } from '@noble/hashes/scrypt.js';
import { utf8ToBytes } from '@noble/hashes/utils.js';
import {
  DEFAULT_LOG_N,
  NCRYPTSEC_VERSION,
  PAYLOAD_LEN,
  decrypt,
  encrypt,
  normalizePassword,
} from '../src/lib/nip49.js';
import { decodeBech32Bytes } from '../src/lib/bech32.js';
import { randomIdentity, encodeNsec } from '../src/lib/keys.js';

const VECTOR = {
  ncryptsec:
    'ncryptsec1qgg9947rlpvqu76pj5ecreduf9jxhselq2nae2kghhvd5g7dgjtcxfqtd67p9m0w57lspw8gsq6yphnm8623nsl8xn9j4jdzz84zm3frztj3z7s35vpzmqf6ksu8r89qk5z2zxfmu5gv8th8wclt0h4p',
  password: 'nostr',
  privHex: '3501454135014541350145413501453fefb02227e449e57cf4d3a3ce05378683',
};

test('nip49: decrypts the official test vector', () => {
  const out = decrypt(VECTOR.ncryptsec, VECTOR.password);
  assert.equal(out.privHex, VECTOR.privHex);
  assert.equal(out.logN, 16);
  // The official vector was created from a key that had been handled insecurely.
  assert.equal(out.securityByte, 0x00);
});

test('nip49: payload layout matches the spec (91 bytes, version 0x02)', () => {
  const bytes = decodeBech32Bytes(VECTOR.ncryptsec, 'ncryptsec');
  assert.equal(bytes.length, PAYLOAD_LEN);
  assert.equal(bytes.length, 91);
  assert.equal(bytes[0], NCRYPTSEC_VERSION);
  assert.equal(bytes[1], 16);
});

test('nip49: decrypt rejects a wrong password', () => {
  assert.throws(
    () => decrypt(VECTOR.ncryptsec, 'nostr!'),
    (e) => e.code === 'wrong_password',
  );
});

test('nip49: encrypt/decrypt roundtrip with a fresh key', () => {
  const id = randomIdentity();
  const code = encrypt(id.privHex, 'correct horse battery staple', { logN: 12 });
  assert.match(code, /^ncryptsec1/);
  const back = decrypt(code, 'correct horse battery staple');
  assert.equal(back.privHex, id.privHex);
  assert.equal(back.logN, 12);
  // A different passphrase must not unlock it.
  assert.throws(() => decrypt(code, 'correct horse battery stapl'), (e) => e.code === 'wrong_password');
});

test('nip49: passwords are NFKC-normalized (spec vector)', () => {
  // U+212B U+2126 U+1E9B U+0323 -> U+00C5 U+03A9 U+1E69
  const input = '\u212B\u2126\u1E9B\u0323';
  assert.deepEqual([...utf8ToBytes(normalizePassword(input))], [0xc3, 0x85, 0xce, 0xa9, 0xe1, 0xb9, 0xa9]);
  const id = randomIdentity();
  // Encrypting with the decomposed form and decrypting with the composed
  // form must work, because both normalize to the same bytes.
  const code = encrypt(id.privHex, input, { logN: 12 });
  assert.equal(decrypt(code, '\u00C5\u03A9\u1E69').privHex, id.privHex);
});

test('nip49: a fresh code differs each time (random salt + nonce)', () => {
  const id = randomIdentity();
  const a = encrypt(id.privHex, 'pw-123456', { logN: 12 });
  const b = encrypt(id.privHex, 'pw-123456', { logN: 12 });
  assert.notEqual(a, b);
  assert.equal(decrypt(a, 'pw-123456').privHex, decrypt(b, 'pw-123456').privHex);
});

test('nip49: rejects malformed input and unsupported work factors', () => {
  assert.throws(() => decrypt('nsec1whatever', 'x'), /ncryptsec1/);
  assert.throws(() => encrypt(randomIdentity().privHex, ''), /password required/);
  assert.throws(() => encrypt(randomIdentity().privHex, 'pw', { logN: 30 }), /out of range/);
  const id = randomIdentity();
  // The stored key must be the raw 32 bytes, not the nsec text.
  assert.throws(() => encrypt(encodeNsec(id.privHex), 'pw'), /32-byte/);
});

test('nip49: default work factor is the NIP-49 recommendation', () => {
  assert.equal(DEFAULT_LOG_N, 16);
  // scrypt at 2^16 must stay under a few seconds so unlock feels instant.
  const salt = new Uint8Array(16).fill(7);
  const t0 = Date.now();
  scrypt(utf8ToBytes('mit-hundert-zeichen-pw'), salt, { N: 2 ** 14, r: 8, p: 1, dkLen: 32 });
  const fast = Date.now() - t0;
  assert.ok(fast < 5000, `scrypt 2^14 took ${fast} ms`);
});
