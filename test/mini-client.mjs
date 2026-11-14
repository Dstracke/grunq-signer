// Minimal NIP-46 CLIENT for tests: connects over a real relay, runs the
// bunker handshake and issues requests against the signer core. Mirrors the
// Grunq node's pkg/nip46 behavior (kind 24133, NIP-44, #p tag).
import { randomBytes, bytesToHex } from '@noble/hashes/utils.js';
import { nip44Decrypt, nip44Encrypt } from '../src/lib/signing.js';
import { decodeBech32Bytes } from '../src/lib/bech32.js';
import { finalizeEvent, verifyEvent, derivePubkeyHex } from '../src/lib/keys.js';

export function parseBunkerUri(raw) {
  const url = new URL(String(raw).trim());
  let pubkey = url.hostname;
  if (!/^[0-9a-f]{64}$/.test(pubkey)) {
    pubkey = bytesToHex(decodeBech32Bytes(pubkey, 'npub'));
  }
  return {
    signerPub: pubkey,
    relays: [...new URLSearchParams(url.search).getAll('relay')],
    secret: url.searchParams.get('secret') ?? '',
  };
}

export class MiniClient {
  constructor(uri) {
    const parsed = parseBunkerUri(uri);
    this.signerPub = parsed.signerPub;
    this.relays = parsed.relays;
    this.secret = parsed.secret;
    this.priv = bytesToHex(randomBytes(32)); // ephemeral client key per session
    this.pub = undefined; // set after connect()
    this.pending = new Map();
    this.subId = 'mini-' + Math.random().toString(36).slice(2);
  }

  connect() {
    return new Promise((resolve, reject) => {
      this.ws = new WebSocket(this.relays[0]);
      const fail = (e) => reject(new Error('relay connect failed: ' + (e?.message ?? e)));
      const timer = setTimeout(() => fail(new Error('timeout')), 5000);
      this.ws.onopen = () => {
        clearTimeout(timer);
        // client pubkey derives from the ephemeral key lazily
        import('../src/lib/keys.js').then(({ derivePubkeyHex }) => {
          this.pub = derivePubkeyHex(this.priv);
          this.ws.send(JSON.stringify(['REQ', this.subId, {
            kinds: [24133],
            '#p': [this.pub],
            since: Math.floor(Date.now() / 1000) - 30,
          }]));
          resolve();
        });
      };
      this.ws.onmessage = (ev) => {
        if (typeof ev.data !== 'string') return;
        let msg;
        try { msg = JSON.parse(ev.data); } catch { return; }
        if (!Array.isArray(msg)) return;
        if (msg[0] === 'EVENT' && msg[1] === this.subId && msg[2]) {
          this.onEvent(msg[2]);
        }
      };
      this.ws.onerror = (e) => { clearTimeout(timer); fail(e); };
    });
  }

  onEvent(event) {
    if (event.kind !== 24133) return;
    if (!verifyEvent(event)) return;
    const pTags = (event.tags ?? []).filter((t) => t[0] === 'p').map((t) => t[1]);
    if (!pTags.includes(this.pub)) return;
    let payload;
    try {
      payload = JSON.parse(nip44Decrypt(this.priv, this.signerPub, event.content));
    } catch {
      return;
    }
    const p = this.pending.get(payload.id);
    if (p) {
      this.pending.delete(payload.id);
      p(payload);
    }
  }

  request(method, params = [], timeoutMs = 12000) {
    const id = bytesToHex(randomBytes(8));
    const payload = JSON.stringify({ id, method, params });
    const ciphertext = nip44Encrypt(this.priv, this.signerPub, payload);
    const event = finalizeEvent(this.priv, {
      kind: 24133,
      tags: [['p', this.signerPub]],
      content: ciphertext,
    });
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this.pending.delete(id);
        reject(new Error('request timeout: ' + method));
      }, timeoutMs);
      this.pending.set(id, (resp) => {
        clearTimeout(timer);
        if (resp.error) reject(new Error(resp.error));
        else resolve(resp.result);
      });
      this.ws.send(JSON.stringify(['EVENT', event]));
    });
  }

  close() {
    try { this.ws?.close(); } catch { /* ignore */ }
  }
}
