// Encrypted identity backup bundle: one JSON file with all identities of the
// extension, sealed with a passphrase (scrypt + XChaCha20-Poly1305, the same
// primitives NIP-49 uses for a single key).
//
// File layout:
//   { format: "grunq-signer-backup", version: 1, createdAt,
//     kdf: { name: "scrypt", logN, salt }, cipher: { name, nonce },
//     payload: "<hex ciphertext>" }
//
// The passphrase never leaves the extension; nothing is uploaded anywhere.
import { xchacha20poly1305 } from '@noble/ciphers/chacha.js';
import { scrypt } from '@noble/hashes/scrypt.js';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js';
import { utf8ToBytes } from '@noble/hashes/utils.js';
import { randomBytes } from '@noble/hashes/utils.js';
import { normalizePassword } from './nip49.js';

export const BACKUP_FORMAT = 'grunq-signer-backup';
export const BACKUP_VERSION = 1;
export const DEFAULT_BACKUP_LOG_N = 16;
export const MIN_BACKUP_LOG_N = 12;
export const MAX_BACKUP_LOG_N = 22;

const AD = utf8ToBytes(`${BACKUP_FORMAT}:${BACKUP_VERSION}`);

function deriveKey(password, salt, logN) {
  if (!Number.isInteger(logN) || logN < MIN_BACKUP_LOG_N || logN > MAX_BACKUP_LOG_N) {
    throw new Error('backup: scrypt work factor out of range');
  }
  return scrypt(utf8ToBytes(normalizePassword(password)), salt, {
    N: 2 ** logN,
    r: 8,
    p: 1,
    dkLen: 32,
    maxmem: 2 ** logN * 8 * 128 * 2 + 1024 * 1024,
  });
}

function fail(code, message) {
  const e = new Error(message ?? code);
  e.code = code;
  return e;
}

/** Seal an object into the backup file format. */
export function sealBundle(data, password, options = {}) {
  if (typeof password !== 'string' || password.length === 0) {
    throw fail('weak_password', 'backup: password required');
  }
  const logN = options.logN ?? DEFAULT_BACKUP_LOG_N;
  const salt = options.salt ?? randomBytes(16);
  const nonce = options.nonce ?? randomBytes(24);
  const key = deriveKey(password, salt, logN);
  const plaintext = utf8ToBytes(JSON.stringify(data));
  const ciphertext = xchacha20poly1305(key, nonce, AD).encrypt(plaintext);
  return {
    format: BACKUP_FORMAT,
    version: BACKUP_VERSION,
    createdAt: options.createdAt ?? Date.now(),
    kdf: { name: 'scrypt', logN, salt: bytesToHex(salt) },
    cipher: { name: 'xchacha20poly1305', nonce: bytesToHex(nonce) },
    payload: bytesToHex(ciphertext),
  };
}

/** Open a parsed backup file; throws code "wrong_password" on mismatch. */
export function openBundle(file, password) {
  if (!file || typeof file !== 'object') throw fail('invalid_backup');
  if (file.format !== BACKUP_FORMAT || file.version !== BACKUP_VERSION) {
    throw fail('invalid_backup');
  }
  if (!file.kdf || !file.cipher || typeof file.payload !== 'string') {
    throw fail('invalid_backup');
  }
  let salt, nonce, payload;
  try {
    salt = hexToBytes(String(file.kdf.salt ?? ''));
    nonce = hexToBytes(String(file.cipher.nonce ?? ''));
    payload = hexToBytes(file.payload);
  } catch {
    throw fail('invalid_backup');
  }
  if (salt.length !== 16 || nonce.length !== 24) throw fail('invalid_backup');
  const key = deriveKey(password, salt, file.kdf.logN);
  let plaintext;
  try {
    plaintext = xchacha20poly1305(key, nonce, AD).decrypt(payload);
  } catch {
    throw fail('wrong_password');
  }
  try {
    return JSON.parse(new TextDecoder().decode(plaintext));
  } catch {
    throw fail('invalid_backup');
  }
}

/** Parse + open a backup file from its JSON text. */
export function openBundleText(text, password) {
  let file;
  try {
    file = JSON.parse(String(text ?? ''));
  } catch {
    throw fail('invalid_backup');
  }
  return openBundle(file, password);
}
