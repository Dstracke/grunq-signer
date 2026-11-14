// High-level signing/encryption API over the keypair: (privHex, pubkeyHex, text).
// Wraps the raw NIP-04/NIP-44 primitives so the background stays simple.
import { hexToBytes } from '@noble/hashes/utils.js';
import {
  decrypt as nip44DecryptRaw,
  encrypt as nip44EncryptRaw,
  getConversationKey,
} from './nip44.js';
import { decrypt as nip04DecryptRaw, encrypt as nip04EncryptRaw } from './nip04.js';

export async function nip04Encrypt(privHex, pubkeyHex, text) {
  return nip04EncryptRaw(privHex, pubkeyHex, text);
}

export async function nip04Decrypt(privHex, pubkeyHex, payload) {
  return nip04DecryptRaw(privHex, pubkeyHex, payload);
}

export function nip44Encrypt(privHex, pubkeyHex, text) {
  const conversationKey = getConversationKey(hexToBytes(privHex), pubkeyHex);
  return nip44EncryptRaw(text, conversationKey);
}

export function nip44Decrypt(privHex, pubkeyHex, payload) {
  const conversationKey = getConversationKey(hexToBytes(privHex), pubkeyHex);
  return nip44DecryptRaw(payload, conversationKey);
}
