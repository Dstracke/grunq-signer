// Editing helpers for grunq.com/.well-known/nostr.json (NIP-05).
// Pure functions so the CLI (`tools/nip05-claim.mjs`) and tests share them.
import { CLAIM_NAME_RE } from './claim.js';

export const DEFAULT_RELAYS = ['wss://relay.grunq.com'];

function assertPubkey(pubkey) {
  if (!/^[0-9a-f]{64}$/.test(String(pubkey ?? ''))) {
    const e = new Error('invalid pubkey');
    e.code = 'invalid_pubkey';
    throw e;
  }
}

function sortedObject(obj) {
  const out = {};
  for (const key of Object.keys(obj).sort()) out[key] = obj[key];
  return out;
}

/** Validate + normalise a NIP-05 document (never mutates the input). */
export function normalizeDoc(raw) {
  const names = {};
  for (const [name, pubkey] of Object.entries(raw?.names ?? {})) {
    if (!CLAIM_NAME_RE.test(name)) continue;
    if (!/^[0-9a-f]{64}$/.test(String(pubkey))) continue;
    names[name] = String(pubkey);
  }
  const relays = {};
  for (const [pubkey, list] of Object.entries(raw?.relays ?? {})) {
    if (!/^[0-9a-f]{64}$/.test(pubkey)) continue;
    if (!Array.isArray(list)) continue;
    const clean = [...new Set(list.filter((r) => typeof r === 'string' && /^wss?:\/\//.test(r)))].sort();
    if (clean.length) relays[pubkey] = clean;
  }
  return { names: sortedObject(names), relays: sortedObject(relays) };
}

/**
 * Add or update a name. Throws code "name_taken" when the name belongs to a
 * different pubkey. Idempotent for the same key.
 */
export function upsertName(raw, { name, pubkey, relays = DEFAULT_RELAYS }) {
  if (!CLAIM_NAME_RE.test(String(name ?? ''))) {
    const e = new Error('invalid name');
    e.code = 'invalid_name';
    throw e;
  }
  assertPubkey(pubkey);
  const doc = normalizeDoc(raw);
  const existing = doc.names[name];
  if (existing && existing !== pubkey) {
    const e = new Error('name already taken');
    e.code = 'name_taken';
    throw e;
  }
  doc.names[name] = pubkey;
  if (Array.isArray(relays) && relays.length) {
    const list = [...new Set([...(doc.relays[pubkey] ?? []), ...relays])].sort();
    doc.relays[pubkey] = list;
  }
  return { doc: normalizeDoc(doc), created: !existing };
}

/** Remove a name (and its relay entry when no other name uses the key). */
export function removeName(raw, name) {
  const doc = normalizeDoc(raw);
  if (!doc.names[name]) return { doc, removed: false };
  const pubkey = doc.names[name];
  delete doc.names[name];
  if (!Object.values(doc.names).includes(pubkey)) delete doc.relays[pubkey];
  return { doc: normalizeDoc(doc), removed: true };
}

export function serializeDoc(doc) {
  return JSON.stringify(normalizeDoc(doc), null, 2) + '\n';
}
