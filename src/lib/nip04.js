// NIP-04 (deprecated) encryption - kept for compatibility with older clients.
// Format: "<iv hex>:<ciphertext base64>", AES-256-CBC, key = sha256(shared x-coordinate).
import { secp256k1 } from '@noble/curves/secp256k1.js';
import { sha256 } from '@noble/hashes/sha2.js';
import {
  bytesToHex,
  concatBytes,
  hexToBytes,
  randomBytes,
  utf8ToBytes,
} from '@noble/hashes/utils.js';
import { base64Decode, base64Encode } from './base64.js';

function sharedSecret(privHex, pubkeyHex) {
  const shared = secp256k1.getSharedSecret(
    hexToBytes(privHex),
    concatBytes(new Uint8Array([2]), hexToBytes(pubkeyHex)),
  );
  return sha256(shared.subarray(1, 33));
}

export async function encrypt(privHex, pubkeyHex, text) {
  const key = sharedSecret(privHex, pubkeyHex);
  const iv = randomBytes(16);
  const cryptoKey = await crypto.subtle.importKey('raw', key, 'AES-CBC', false, ['encrypt']);
  const cipher = await crypto.subtle.encrypt(
    { name: 'AES-CBC', iv },
    cryptoKey,
    utf8ToBytes(String(text ?? '')),
  );
  return `${bytesToHex(iv)}:${base64Encode(new Uint8Array(cipher))}`;
}

export async function decrypt(privHex, pubkeyHex, payload) {
  const s = String(payload ?? '');
  const sep = s.indexOf(':');
  if (sep < 0) throw new Error('invalid NIP-04 format (missing separator)');
  const iv = hexToBytes(s.slice(0, sep));
  const cipher = base64Decode(s.slice(sep + 1));
  if (iv.length !== 16) throw new Error('invalid NIP-04 IV length');
  const key = sharedSecret(privHex, pubkeyHex);
  const cryptoKey = await crypto.subtle.importKey('raw', key, 'AES-CBC', false, ['decrypt']);
  const plain = await crypto.subtle.decrypt({ name: 'AES-CBC', iv }, cryptoKey, cipher);
  return new TextDecoder().decode(plain);
}
