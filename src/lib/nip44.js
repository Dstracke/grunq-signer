// NIP-44 v2 encryption (per reference implementation paulmillr/nip44, matches vectors).
// Note: the NIP text has a newer "extended length prefix" proposal; the reference
// implementation and the whole ecosystem still cap at 65535 bytes - we follow that
// for interoperability.
import { chacha20 } from '@noble/ciphers/chacha.js';
import { secp256k1 } from '@noble/curves/secp256k1.js';
import { extract as hkdfExtract, expand as hkdfExpand } from '@noble/hashes/hkdf.js';
import { hmac } from '@noble/hashes/hmac.js';
import { sha256 } from '@noble/hashes/sha2.js';
import {
  concatBytes,
  hexToBytes,
  randomBytes,
  utf8ToBytes,
} from '@noble/hashes/utils.js';
import { base64Decode, base64Encode } from './base64.js';

const MIN_PLAINTEXT = 1;
const MAX_PLAINTEXT = 0xffff; // 65535

function utf8Decode(bytes) {
  return new TextDecoder().decode(bytes);
}

export function getConversationKey(privBytes, pubkeyHex) {
  const shared = secp256k1.getSharedSecret(privBytes, concatBytes(new Uint8Array([2]), hexToBytes(pubkeyHex)));
  const sharedX = shared.subarray(1, 33); // raw, unhashed x-coordinate per NIP-44
  return hkdfExtract(sha256, sharedX, utf8ToBytes('nip44-v2'));
}

export function getMessageKeys(conversationKey, nonce) {
  if (conversationKey.length !== 32) throw new Error('invalid conversation_key length');
  if (nonce.length !== 32) throw new Error('invalid nonce length');
  const keys = hkdfExpand(sha256, conversationKey, nonce, 76);
  return {
    chachaKey: keys.subarray(0, 32),
    chachaNonce: keys.subarray(32, 44),
    hmacKey: keys.subarray(44, 76),
  };
}

export function calcPaddedLen(len) {
  if (!Number.isSafeInteger(len) || len < 1) throw new Error('expected positive integer');
  if (len <= 32) return 32;
  const nextPower = 2 ** (Math.floor(Math.log2(len - 1)) + 1);
  const chunk = nextPower <= 256 ? 32 : nextPower / 8;
  return chunk * (Math.floor((len - 1) / chunk) + 1);
}

function pad(plaintext) {
  const unpadded = utf8ToBytes(plaintext);
  const unpaddedLen = unpadded.length;
  if (unpaddedLen < MIN_PLAINTEXT || unpaddedLen > MAX_PLAINTEXT) {
    throw new Error('invalid plaintext size: must be between 1 and 65535 bytes');
  }
  const prefix = new Uint8Array([(unpaddedLen >> 8) & 0xff, unpaddedLen & 0xff]);
  const suffix = new Uint8Array(calcPaddedLen(unpaddedLen) - unpaddedLen);
  return concatBytes(prefix, unpadded, suffix);
}

function unpad(padded) {
  const view = new DataView(padded.buffer, padded.byteOffset, padded.byteLength);
  const unpaddedLen = view.getUint16(0, false);
  const unpadded = padded.subarray(2, 2 + unpaddedLen);
  if (
    unpaddedLen < MIN_PLAINTEXT ||
    unpaddedLen > MAX_PLAINTEXT ||
    unpadded.length !== unpaddedLen ||
    padded.length !== 2 + calcPaddedLen(unpaddedLen)
  ) {
    throw new Error('invalid padding');
  }
  return utf8Decode(unpadded);
}

function hmacAad(key, message, aad) {
  if (aad.length !== 32) throw new Error('AAD associated data must be 32 bytes');
  return hmac(sha256, key, concatBytes(aad, message));
}

function decodePayload(payload) {
  if (typeof payload !== 'string') throw new Error('payload must be a valid string');
  const plen = payload.length;
  if (plen < 132 || plen > 87472) throw new Error('invalid payload length: ' + plen);
  if (payload[0] === '#') throw new Error('unknown encryption version');
  let data;
  try {
    data = base64Decode(payload);
  } catch (err) {
    throw new Error('invalid base64: ' + (err instanceof Error ? err.message : String(err)));
  }
  const dlen = data.length;
  if (dlen < 99 || dlen > 65603) throw new Error('invalid data length: ' + dlen);
  const vers = data[0];
  if (vers !== 2) throw new Error('unknown encryption version ' + vers);
  return {
    nonce: data.subarray(1, 33),
    ciphertext: data.subarray(33, dlen - 32),
    mac: data.subarray(dlen - 32),
  };
}

// Constant-time byte comparison.
function equalCt(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

export function encrypt(plaintext, conversationKey, nonce = randomBytes(32)) {
  const { chachaKey, chachaNonce, hmacKey } = getMessageKeys(conversationKey, nonce);
  const padded = pad(plaintext);
  const ciphertext = chacha20(chachaKey, chachaNonce, padded);
  const mac = hmacAad(hmacKey, ciphertext, nonce);
  return base64Encode(concatBytes(new Uint8Array([2]), nonce, ciphertext, mac));
}

export function decrypt(payload, conversationKey) {
  const { nonce, ciphertext, mac } = decodePayload(payload);
  const { chachaKey, chachaNonce, hmacKey } = getMessageKeys(conversationKey, nonce);
  const calculatedMac = hmacAad(hmacKey, ciphertext, nonce);
  if (!equalCt(calculatedMac, mac)) throw new Error('invalid MAC');
  const padded = chacha20(chachaKey, chachaNonce, ciphertext);
  return unpad(padded);
}
