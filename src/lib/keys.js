// Identity + NIP-01 event helpers: nsec/npub, pubkey derivation, event id + schnorr signing.
import { schnorr } from '@noble/curves/secp256k1.js';
import { sha256 } from '@noble/hashes/sha2.js';
import {
  bytesToHex,
  concatBytes,
  hexToBytes,
  randomBytes,
  utf8ToBytes,
} from '@noble/hashes/utils.js';
import { decodeBech32Bytes, encodeBech32Bytes } from './bech32.js';

export { bytesToHex, hexToBytes };

// BIP-340 x-only pubkey (32-byte hex) from a 32-byte secret key.
export function derivePubkeyHex(privHex) {
  const priv = typeof privHex === 'string' ? hexToBytes(privHex) : privHex;
  return bytesToHex(schnorr.getPublicKey(priv));
}

// Create a fresh identity { privHex, pubkeyHex }.
export function randomIdentity() {
  const priv = randomBytes(32);
  return { privHex: bytesToHex(priv), pubkeyHex: derivePubkeyHex(priv) };
}

export function encodeNsec(privHex) {
  return encodeBech32Bytes('nsec', hexToBytes(privHex));
}

export function encodeNpub(pubkeyHex) {
  return encodeBech32Bytes('npub', hexToBytes(pubkeyHex));
}

// Accepts "nsec1..." or 64-char hex; validates against the curve. Returns hex private key.
export function parseSecretInput(input) {
  if (typeof input !== 'string') throw new Error('Invalid key: expected nsec1... or 64-char hex.');
  const s = input.trim();
  let privBytes;
  if (/^nsec1[02-9ac-hj-np-z]{58}$/i.test(s)) {
    privBytes = decodeBech32Bytes(s, 'nsec');
  } else if (/^[0-9a-fA-F]{64}$/.test(s)) {
    privBytes = hexToBytes(s);
  } else {
    throw new Error('Invalid key: expected an nsec1... string or a 64-character hex key.');
  }
  if (privBytes.length !== 32) throw new Error('Invalid key: wrong length.');
  const privHex = bytesToHex(privBytes);
  try {
    schnorr.getPublicKey(privBytes); // range/curve check
  } catch {
    throw new Error('Invalid key: not a valid secp256k1 private key.');
  }
  return privHex;
}

// NIP-01 event id: sha256 over the serialized form (sorted field order is fixed by the array).
export function serializeEvent(ev) {
  return JSON.stringify([0, ev.pubkey, ev.created_at, ev.kind, ev.tags, ev.content]);
}

export function eventIdHex(ev) {
  return bytesToHex(sha256(utf8ToBytes(serializeEvent(ev))));
}

// Fill pubkey/id/sig into the event (BIP-340 schnorr). `now` overrides created_at (tests).
export function finalizeEvent(privHex, event, now) {
  const ev = { ...event };
  ev.created_at = Number.isInteger(ev.created_at)
    ? ev.created_at
    : (now ?? Math.floor(Date.now() / 1000));
  ev.kind = Number(ev.kind);
  if (!Array.isArray(ev.tags)) ev.tags = [];
  ev.content = String(ev.content ?? '');
  ev.pubkey = derivePubkeyHex(privHex);
  ev.id = eventIdHex(ev);
  ev.sig = bytesToHex(schnorr.sign(hexToBytes(ev.id), hexToBytes(privHex)));
  return ev;
}

export function verifyEvent(ev) {
  const id = eventIdHex({ ...ev, id: undefined, sig: undefined });
  if (id !== ev.id) return false;
  return schnorr.verify(hexToBytes(ev.sig), hexToBytes(ev.id), hexToBytes(ev.pubkey));
}
