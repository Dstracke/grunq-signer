// NIP-49 private key encryption ("ncryptsec"): scrypt over an NFKC-normalized
// passphrase + XChaCha20-Poly1305 over the 32-byte secret key.
//
// Payload (91 bytes before bech32):
//   version (1) | log_n (1) | salt (16) | nonce (24) | ad (1) | ciphertext (48)
// `ad` is the NIP-49 key-security byte (0x00 handled insecurely, 0x01 never
// handled insecurely, 0x02 not tracked). The ciphertext carries the
// Poly1305 tag, hence 32 + 16 bytes.
import { xchacha20poly1305 } from '@noble/ciphers/chacha.js';
import { scrypt } from '@noble/hashes/scrypt.js';
import { concatBytes, randomBytes, utf8ToBytes } from '@noble/hashes/utils.js';
import { decodeBech32Bytes, encodeBech32Bytes } from './bech32.js';
import { bytesToHex, hexToBytes } from './keys.js';

export const NCRYPTSEC_VERSION = 0x02;
export const DEFAULT_LOG_N = 16; // 64 MiB, the NIP-49 recommendation
export const MIN_LOG_N = 12;
export const MAX_LOG_N = 22;

export const SECURITY_INSECURE = 0x00;
export const SECURITY_SECURE = 0x01;
export const SECURITY_UNKNOWN = 0x02;

export const PAYLOAD_LEN = 1 + 1 + 16 + 24 + 1 + 48;

// NIP-49 requires NFKC so the password can be typed identically on other
// devices (e.g. "Å" as U+212B normalizes to U+00C5).
export function normalizePassword(password) {
  return String(password ?? '').normalize('NFKC');
}

function deriveKey(password, salt, logN) {
  if (!Number.isInteger(logN) || logN < MIN_LOG_N || logN > MAX_LOG_N) {
    throw new Error('ncryptsec: scrypt work factor out of range');
  }
  return scrypt(utf8ToBytes(normalizePassword(password)), salt, {
    N: 2 ** logN,
    r: 8,
    p: 1,
    dkLen: 32,
    maxmem: 2 ** logN * 8 * 128 * 2 + 1024 * 1024,
  });
}

function assertPassword(password) {
  if (typeof password !== 'string' || password.length === 0) {
    throw new Error('ncryptsec: password required');
  }
}

// Encrypt a 32-byte private key. Options are for tests (fixed salt/nonce) and
// for choosing a work factor; the security byte defaults to "not tracked".
export function encrypt(privBytes, password, options = {}) {
  assertPassword(password);
  if (typeof privBytes === 'string' && !/^[0-9a-fA-F]{64}$/.test(privBytes)) {
    throw new Error('ncryptsec: expected a 32-byte private key');
  }
  const priv = typeof privBytes === 'string' ? hexToBytes(privBytes) : privBytes;
  if (!(priv instanceof Uint8Array) || priv.length !== 32) {
    throw new Error('ncryptsec: expected a 32-byte private key');
  }
  const logN = options.logN ?? DEFAULT_LOG_N;
  const securityByte = options.securityByte ?? SECURITY_UNKNOWN;
  if (![SECURITY_INSECURE, SECURITY_SECURE, SECURITY_UNKNOWN].includes(securityByte)) {
    throw new Error('ncryptsec: invalid key security byte');
  }
  const salt = options.salt ?? randomBytes(16);
  const nonce = options.nonce ?? randomBytes(24);
  if (salt.length !== 16 || nonce.length !== 24) throw new Error('ncryptsec: bad salt/nonce');
  const key = deriveKey(password, salt, logN);
  const associatedData = Uint8Array.of(securityByte);
  const ciphertext = xchacha20poly1305(key, nonce, associatedData).encrypt(priv);
  const payload = concatBytes(
    Uint8Array.of(NCRYPTSEC_VERSION, logN),
    salt,
    nonce,
    associatedData,
    ciphertext,
  );
  return encodeBech32Bytes('ncryptsec', payload);
}

// Decrypt an ncryptsec string. Throws "wrong password" when the Poly1305 tag
// does not verify, which is what any wrong passphrase looks like.
export function decrypt(ncryptsec, password) {
  assertPassword(password);
  const raw = String(ncryptsec ?? '').trim().toLowerCase();
  if (!/^ncryptsec1[02-9ac-hj-np-z]+$/.test(raw)) {
    throw new Error('ncryptsec: expected an ncryptsec1... string');
  }
  const payload = decodeBech32Bytes(raw, 'ncryptsec');
  if (payload.length !== PAYLOAD_LEN) throw new Error('ncryptsec: bad payload length');
  const version = payload[0];
  if (version !== NCRYPTSEC_VERSION) throw new Error('ncryptsec: unsupported version');
  const logN = payload[1];
  const salt = payload.subarray(2, 18);
  const nonce = payload.subarray(18, 42);
  const securityByte = payload[42];
  const ciphertext = payload.subarray(43);
  const key = deriveKey(password, salt, logN);
  let priv;
  try {
    priv = xchacha20poly1305(key, nonce, Uint8Array.of(securityByte)).decrypt(ciphertext);
  } catch {
    const e = new Error('ncryptsec: wrong password');
    e.code = 'wrong_password';
    throw e;
  }
  if (priv.length !== 32) throw new Error('ncryptsec: bad key length');
  return { privHex: bytesToHex(priv), logN, securityByte };
}
