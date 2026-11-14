// Crypto tests: bech32 (BIP-173), NIP-44 (official vectors), event signing, NIP-04 roundtrip.
import assert from 'node:assert/strict';
import test from 'node:test';
import { readFileSync } from 'node:fs';
import { sha256 } from '@noble/hashes/sha2.js';
import { hexToBytes, utf8ToBytes } from '@noble/hashes/utils.js';
import { schnorr } from '@noble/curves/secp256k1.js';
import { bytesToHex } from '../src/lib/keys.js';
import {
  decodeBech32,
  decodeBech32Bytes,
  encodeBech32,
  encodeBech32Bytes,
} from '../src/lib/bech32.js';
import {
  derivePubkeyHex,
  eventIdHex,
  encodeNpub,
  encodeNsec,
  finalizeEvent,
  parseSecretInput,
  randomIdentity,
  verifyEvent,
} from '../src/lib/keys.js';
import {
  calcPaddedLen,
  decrypt as nip44Decrypt,
  encrypt as nip44Encrypt,
  getConversationKey,
  getMessageKeys,
} from '../src/lib/nip44.js';
import { decrypt as nip04Decrypt, encrypt as nip04Encrypt } from '../src/lib/nip04.js';

// ---------- bech32: BIP-173 vectors ----------

test('bech32: BIP-173 valid strings roundtrip', () => {
  const valid = [
    'A12UEL5L',
    'a12uel5l',
    'an83characterlonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbio1tt5tgs',
    'abcdef1qpzry9x8gf2tvdw0s3jn54khce6mua7lmqqqxw',
  ];
  for (const s of valid) {
    const { hrp, data } = decodeBech32(s);
    assert.equal(encodeBech32(hrp, data), s.toLowerCase());
  }
});

test('bech32: BIP-173 invalid strings rejected', () => {
  const invalid = [
    'pzry9x0s0muk', // no separator
    '1pzry9x0s0muk', // empty hrp
    'x1b4n0q5v', // invalid data char
    'li1dgmt3', // too short checksum
    'A1G7SGD8', // checksum calculated with uppercase hrp
    'abcdef1qpzry9x8gf2tvdw0s3jn54khce6mua7lmqqqwj', // bad checksum
  ];
  for (const s of invalid) {
    assert.throws(() => decodeBech32(s), undefined, `should reject: ${s}`);
  }
});

test('bech32: 8-to-5 conversion rejects non-zero padding', () => {
  // A 32-byte key encodes to 52 five-bit chunks; the last one holds padding bits.
  const id = randomIdentity();
  const npub = encodeNpub(id.pubkeyHex);
  const { hrp, data } = decodeBech32(npub);
  // corrupt the padding bits of the last chunk, then re-checksum and decode
  data[data.length - 1] ^= 0x1f;
  const re = encodeBech32(hrp, data);
  assert.throws(() => decodeBech32Bytes(re, hrp));
});

test('nsec/npub roundtrip', () => {
  const id = randomIdentity();
  const nsec = encodeNsec(id.privHex);
  const npub = encodeNpub(id.pubkeyHex);
  assert.match(nsec, /^nsec1[02-9ac-hj-np-z]+$/);
  assert.match(npub, /^npub1[02-9ac-hj-np-z]+$/);
  assert.equal(bytesToHex(decodeBech32Bytes(nsec, 'nsec')), id.privHex);
  assert.equal(bytesToHex(decodeBech32Bytes(npub, 'npub')), id.pubkeyHex);
});

// ---------- NIP-44: official vectors ----------

const V = JSON.parse(readFileSync(new URL('./nip44.vectors.json', import.meta.url), 'utf8')).v2;

test('nip44: get_conversation_key vectors', () => {
  for (const t of V.valid.get_conversation_key) {
    const conv = getConversationKey(hexToBytes(t.sec1), t.pub2);
    assert.equal(bytesToHex(conv), t.conversation_key);
  }
});

test('nip44: get_message_keys vectors', () => {
  const convKey = hexToBytes(V.valid.get_message_keys.conversation_key);
  for (const k of V.valid.get_message_keys.keys) {
    const keys = getMessageKeys(convKey, hexToBytes(k.nonce));
    const expected = {
      chacha_key: k.chacha_key,
      chacha_nonce: k.chacha_nonce,
      hmac_key: k.hmac_key,
    };
    const got = {
      chacha_key: bytesToHex(keys.chachaKey),
      chacha_nonce: bytesToHex(keys.chachaNonce),
      hmac_key: bytesToHex(keys.hmacKey),
    };
    assert.deepEqual(got, expected);
  }
});

test('nip44: calc_padded_len vectors', () => {
  for (const [inp, out] of V.valid.calc_padded_len) {
    assert.equal(calcPaddedLen(inp), out, `calcPaddedLen(${inp})`);
  }
});

test('nip44: encrypt_decrypt vectors', () => {
  for (const t of V.valid.encrypt_decrypt) {
    const conv = getConversationKey(hexToBytes(t.sec1), derivePubkeyHex(t.sec2));
    assert.equal(bytesToHex(conv), t.conversation_key);
    const payload = nip44Encrypt(t.plaintext, conv, hexToBytes(t.nonce));
    assert.equal(payload, t.payload);
    assert.equal(nip44Decrypt(t.payload, conv), t.plaintext);
    // roles swapped
    const conv2 = getConversationKey(hexToBytes(t.sec2), derivePubkeyHex(t.sec1));
    assert.equal(bytesToHex(conv2), t.conversation_key);
    assert.equal(nip44Decrypt(t.payload, conv2), t.plaintext);
  }
});

test('nip44: encrypt_decrypt_long_msg vectors (checksummed)', () => {
  for (const t of V.valid.encrypt_decrypt_long_msg) {
    const plaintext = t.pattern.repeat(t.repeat); // pattern is the literal unit string
    const conv = hexToBytes(t.conversation_key);
    const payload = nip44Encrypt(plaintext, conv, hexToBytes(t.nonce));
    assert.equal(
      bytesToHex(sha256(utf8ToBytes(payload))),
      t.payload_sha256,
      `payload sha256 (repeat=${t.repeat})`,
    );
    assert.equal(nip44Decrypt(payload, conv), plaintext);
  }
});

test('nip44: invalid get_conversation_key throws', () => {
  for (const t of V.invalid.get_conversation_key) {
    assert.throws(() => getConversationKey(hexToBytes(t.sec1), t.pub2));
  }
});

test('nip44: invalid decrypt throws', () => {
  for (const t of V.invalid.decrypt) {
    const conv = hexToBytes(t.conversation_key);
    assert.throws(() => nip44Decrypt(t.payload, conv), undefined, t.payload?.slice(0, 40));
  }
});

test('nip44: invalid plaintext lengths throw', () => {
  const id = randomIdentity();
  const conv = getConversationKey(hexToBytes(id.privHex), id.pubkeyHex);
  assert.throws(() => nip44Encrypt('', conv));
  // Reference implementation caps at 65535 (u16 prefix only)
  assert.throws(() => nip44Encrypt('a'.repeat(65536), conv));
});

test('nip44: random roundtrip', () => {
  const id = randomIdentity();
  const conv = getConversationKey(hexToBytes(id.privHex), id.pubkeyHex);
  const msg = 'Grüße aus dem P2P-Swarm! 🦄 '.repeat(7);
  const payload = nip44Encrypt(msg, conv);
  assert.equal(nip44Decrypt(payload, conv), msg);
  assert.notEqual(nip44Encrypt(msg, conv), payload); // fresh nonce
});

// ---------- event signing ----------

test('events: finalize + verify roundtrip', () => {
  const id = randomIdentity();
  const ev = finalizeEvent(id.privHex, {
    kind: 1,
    content: 'Hallo Welt',
    tags: [['t', 'grunq']],
  });
  assert.equal(ev.pubkey, id.pubkeyHex);
  assert.equal(ev.id, eventIdHex(ev));
  assert.ok(schnorr.verify(hexToBytes(ev.sig), hexToBytes(ev.id), hexToBytes(ev.pubkey)));
  assert.ok(verifyEvent(ev));
});

test('events: id is deterministic and matches NIP-01 serialization', () => {
  const id = randomIdentity();
  const base = { kind: 1, content: 'x', created_at: 1700000000, tags: [] };
  const a = finalizeEvent(id.privHex, base);
  const b = finalizeEvent(id.privHex, base);
  assert.equal(a.id, b.id);
  // direct check of the serialization rule
  const serialized = JSON.stringify([0, a.pubkey, 1700000000, 1, [], 'x']);
  assert.equal(a.id, bytesToHex(sha256(utf8ToBytes(serialized))));
});

test('events: pubkey derivation matches schnorr', () => {
  const id = randomIdentity();
  assert.equal(derivePubkeyHex(id.privHex), id.pubkeyHex);
});

test('keys: parseSecretInput accepts nsec and hex, rejects junk', () => {
  const id = randomIdentity();
  assert.equal(parseSecretInput(encodeNsec(id.privHex)), id.privHex);
  assert.equal(parseSecretInput(id.privHex), id.privHex);
  assert.equal(parseSecretInput(`  ${id.privHex} \n`), id.privHex);
  assert.throws(() => parseSecretInput('npub1abc'));
  assert.throws(() => parseSecretInput('zz'));
  assert.throws(() => parseSecretInput(null));
});

// ---------- NIP-04 ----------

test('nip04: encrypt/decrypt roundtrip between two identities', async () => {
  const a = randomIdentity();
  const b = randomIdentity();
  const msg = 'vertrauliche Nachricht 🦄';
  const payload = await nip04Encrypt(a.privHex, b.pubkeyHex, msg);
  assert.match(payload, /^[0-9a-f]{32}:.+$/);
  assert.equal(await nip04Decrypt(b.privHex, a.pubkeyHex, payload), msg);
  assert.equal(await nip04Decrypt(a.privHex, b.pubkeyHex, payload), msg);
});

test('nip04: wrong key cannot decrypt', async () => {
  const a = randomIdentity();
  const b = randomIdentity();
  const c = randomIdentity();
  const payload = await nip04Encrypt(a.privHex, b.pubkeyHex, 'geheim');
  await assert.rejects(() => nip04Decrypt(c.privHex, a.pubkeyHex, payload));
});
