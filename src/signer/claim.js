// NIP-05 claim tokens for names on grunq.com.
//
// A claim is a Schnorr signature over
//   "grunq-nip05-claim:<name>:<pubkey-hex>:<issued-at-ISO>"
// made with the identity's own key. The operator verifies it with
// `tools/nip05-claim.mjs` before adding the name to
// `.well-known/nostr.json`, so no account or central database is needed.
import { schnorr } from '@noble/curves/secp256k1.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex, hexToBytes, utf8ToBytes } from '@noble/hashes/utils.js';
import { decodeBech32Bytes } from '../lib/bech32.js';

export const CLAIM_PREFIX = 'grunq-nip05-claim';
// 2–30 characters, lowercase, digits, dash and underscore (server policy).
export const CLAIM_NAME_RE = /^[a-z0-9][a-z0-9_-]{1,29}$/;
export const CLAIM_MAX_AGE_MS = 7 * 24 * 60 * 60 * 1000;
export const CLAIM_CLOCK_SKEW_MS = 10 * 60 * 1000;

export function claimMessage(name, pubkey, issuedAt) {
  return `${CLAIM_PREFIX}:${name}:${pubkey}:${issuedAt}`;
}

function claimHash(name, pubkey, issuedAt) {
  return sha256(utf8ToBytes(claimMessage(name, pubkey, issuedAt)));
}

/** Sign a claim; returns the message, its hash and the signature (hex). */
export function signClaim({ privHex, name, pubkey, issuedAt }) {
  if (!CLAIM_NAME_RE.test(String(name))) throw new Error('invalid name');
  const hash = claimHash(name, pubkey, issuedAt);
  return {
    message: claimMessage(name, pubkey, issuedAt),
    hash: bytesToHex(hash),
    signature: bytesToHex(schnorr.sign(hash, hexToBytes(privHex))),
  };
}

/**
 * Verify a claim: name/pubkey/time sanity plus the signature. Returns
 * { ok: true } or { ok: false, code }.
 */
export function verifyClaim({ pubkey, name, issuedAt, signature, now = Date.now() }) {
  if (!CLAIM_NAME_RE.test(String(name ?? ''))) return { ok: false, code: 'invalid_name' };
  if (!/^[0-9a-f]{64}$/.test(String(pubkey ?? ''))) return { ok: false, code: 'invalid_pubkey' };
  if (!/^[0-9a-f]{128}$/.test(String(signature ?? ''))) return { ok: false, code: 'bad_signature' };
  const time = Date.parse(String(issuedAt ?? ''));
  if (!Number.isFinite(time)) return { ok: false, code: 'invalid_time' };
  if (time > now + CLAIM_CLOCK_SKEW_MS) return { ok: false, code: 'future' };
  if (now - time > CLAIM_MAX_AGE_MS) return { ok: false, code: 'stale' };
  let valid = false;
  try {
    valid = schnorr.verify(hexToBytes(signature), claimHash(name, pubkey, issuedAt), hexToBytes(pubkey));
  } catch {
    valid = false;
  }
  return valid ? { ok: true } : { ok: false, code: 'bad_signature' };
}

/** Decode an npub to lowercase hex; throws on invalid input. */
export function npubToHex(npub) {
  return bytesToHex(decodeBech32Bytes(String(npub ?? '').trim(), 'npub'));
}
