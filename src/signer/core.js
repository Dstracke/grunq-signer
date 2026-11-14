// NIP-46 remote-signer core: receives Kind-24133 requests from NIP-46
// clients over relays and answers them with the extension identity.
//
// The core is environment-injected (storage, transport, approval, time,
// randomness) so it runs unmodified in the browser background AND in node
// tests (see test/nip46.test.mjs, which drives it end-to-end over a real
// relay with a mini client).
//
// Wire protocol (mirrors the Grunq node client in pkg/nip46):
//   - request  { id, method, params: [...] }  NIP-44-encrypted to the signer
//   - response { id, result, error }          NIP-44-encrypted to the client
//   - Kind 24133, #p tag points at the receiving party.
//
// bunker:// flow: the extension hands out one invitation URI per connection
// (secret + relays). The client sends `connect` with that secret; the
// secret stays valid for reconnects (clients regenerate their ephemeral
// keys and re-run the handshake with the stored URI), so a token binds to
// the most recent client key instead of being one-time.
import { hexToBytes, bytesToHex, randomBytes } from '@noble/hashes/utils.js';
import { decrypt as nip44DecryptRaw, getConversationKey } from '../lib/nip44.js';
import { decodeBech32Bytes } from '../lib/bech32.js';
import {
  derivePubkeyHex,
  encodeNpub,
  finalizeEvent,
  verifyEvent,
} from '../lib/keys.js';
import {
  nip04Decrypt,
  nip04Encrypt,
  nip44Decrypt,
  nip44Encrypt,
} from '../lib/signing.js';
import { normalizeRelayList } from '../lib/relay-pool.js';

export const REQUEST_KIND = 24133;

export const SESSIONS_STORE = 'grunq_signer:sessions';
export const SETTINGS_STORE = 'grunq_signer:settings';

export const MAX_SESSIONS = 16;
export const INVITE_TTL_MS = 10 * 60 * 1000; // unpaired invitations expire
export const DEFAULT_RELAYS = ['wss://relay.grunq.com'];

const err = (code, message) => {
  const e = new Error(message ?? code);
  e.nip46Code = code;
  return e;
};

function secretError(code) {
  // NIP-46 error responses are strings "error:<reason>" in the error field.
  return 'error:' + code;
}

export async function defaultSettings(store) {
  const settings = (await store.get(SETTINGS_STORE)) ?? {};
  if (!Array.isArray(settings.relays) || settings.relays.length === 0) {
    settings.relays = [...DEFAULT_RELAYS];
  }
  if (!Number.isFinite(settings.idleMinutes)) settings.idleMinutes = 30;
  return settings;
}

export function buildBunkerUri(signerPubHex, relays, secret) {
  const qs = new URLSearchParams();
  for (const relay of relays) qs.append('relay', relay);
  qs.set('secret', secret);
  return `bunker://${signerPubHex}?${qs.toString()}`;
}

export function createSignerCore(env) {
  const {
    storage, // { get(key), set(key, value) } - local persistence
    transport, // { subscribe(relays, filter, onEvent), publish(relays, event) }
    requestApproval, // (info) => Promise<'allow' | 'deny'>
    now = () => Date.now(),
    randomHex = (bytes) => bytesToHex(randomBytes(bytes)),
    signerPrivHex, // () => Promise<string>
    log = () => {},
  } = env;

  let started = false;
  /** @type {{close: Function}[]} */
  let subHandles = [];
  /** @type {object[]|null} */
  let sessionsCache = null;

  async function loadSessions() {
    if (sessionsCache) return sessionsCache;
    sessionsCache = (await storage.get(SESSIONS_STORE)) ?? [];
    if (!Array.isArray(sessionsCache)) sessionsCache = [];
    return sessionsCache;
  }

  async function saveSessions() {
    if (!sessionsCache) return;
    await storage.set(SESSIONS_STORE, sessionsCache);
  }

  function signerPub() {
    // derived on demand; cheap (one scalar mult) and always current
    return signerPubPromise ?? (signerPubPromise = signerPrivHex().then((priv) => derivePubkeyHex(priv)));
  }
  let signerPubPromise = null;

  function relayUnion(sessions, settings) {
    const set = new Set(settings.relays);
    for (const s of sessions) for (const r of s.relays) set.add(r);
    return normalizeRelayList([...set]);
  }

  async function refreshSubscriptions() {
    for (const h of subHandles) h.close();
    subHandles = [];
    const [sessions, settings, priv] = await Promise.all([
      loadSessions(),
      defaultSettings(storage),
      signerPrivHex(),
    ]);
    const relays = relayUnion(sessions, settings);
    if (relays.length === 0) return;
    const since = Math.floor(now() / 1000) - 300; // small clock tolerance
    const filter = {
      kinds: [REQUEST_KIND],
      '#p': [derivePubkeyHex(priv)],
      since,
    };
    const handle = transport.subscribe(relays, filter, (event) => {
      // return the promise so test harnesses can await delivery; relays
      // process events synchronously anyway
      return onEvent(event).catch((e) => log('nip46 onEvent error', e));
    });
    subHandles = [handle];
  }

  async function onEvent(event) {
    if (!event || event.kind !== REQUEST_KIND) return;
    const priv = await signerPrivHex();
    const myPub = derivePubkeyHex(priv);
    if (event.pubkey === myPub) return; // our own publish echo
    if (!verifyEvent(event)) return;
    const pTags = (event.tags ?? []).filter((t) => t[0] === 'p').map((t) => t[1]);
    if (!pTags.includes(myPub)) return;

    let req;
    try {
      const ck = getConversationKey(hexToBytes(priv), event.pubkey);
      const plaintext = nip44DecryptRaw(event.content, ck);
      req = JSON.parse(plaintext);
    } catch {
      return; // not for us / malformed - ignore silently
    }
    if (!req || typeof req.id !== 'string' || typeof req.method !== 'string') return;
    if (!Array.isArray(req.params)) req.params = [];

    const [sessions, settings] = await Promise.all([loadSessions(), defaultSettings(storage)]);
    let result;
    try {
      result = await dispatch(event, req, sessions, settings);
      await respond(event.pubkey, settings, req.id, result, null);
    } catch (e) {
      const code = e?.nip46Code ?? 'internal';
      log('nip46 request failed', req.method, code);
      try {
        await respond(event.pubkey, settings, req.id, null, secretError(code));
      } catch (sendErr) {
        log('nip46 respond failed', sendErr);
      }
    }
  }

  function sessionForClient(sessions, clientPub) {
    return sessions.find((s) => s.bound && s.clientPub === clientPub) ?? null;
  }

  function touch(s) {
    s.lastActive = now();
  }

  async function dispatch(clientEvent, req, sessions, settings) {
    const { method, params } = req;
    const clientPub = clientEvent.pubkey;
    const priv = await signerPrivHex();

    switch (method) {
      case 'connect': {
        // params: [remotePub(optional), secret, perms(optional), metadata(optional)]
        const [, secret, perms, metadata] = params;
        if (typeof secret !== 'string' || !secret) throw err('unauthorized', 'missing secret');
        const token = sessions.find((s) => s.secret === secret);
        if (!token) throw err('unauthorized', 'unknown secret');
        if (typeof params[0] === 'string' && params[0]) {
          const wanted = decodeSignerParam(params[0]);
          const mine = await signerPub();
          if (wanted && wanted !== mine) throw err('unauthorized', 'wrong signer key');
        }
        // Rebind: bunker clients regenerate ephemeral keys on reconnect.
        token.clientPub = clientPub;
        token.bound = true;
        token.perms = typeof perms === 'string' ? perms : '';
        token.clientName = parseClientName(metadata);
        token.lastActive = now();
        await saveSessions();
        return 'ack';
      }

      case 'ping': {
        const s = requireSession(sessions, clientPub);
        touch(s);
        await saveSessions();
        return 'pong';
      }

      case 'get_public_key': {
        const s = requireSession(sessions, clientPub);
        touch(s);
        await saveSessions();
        return derivePubkeyHex(priv);
      }

      case 'get_relays': {
        const s = requireSession(sessions, clientPub);
        touch(s);
        await saveSessions();
        const map = {};
        for (const r of s.relays) map[r] = { read: true, write: true };
        return JSON.stringify(map);
      }

      case 'switch_relays': {
        const s = requireSession(sessions, clientPub);
        touch(s);
        await saveSessions();
        // Global allowlist (settings); client may use it to reconnect.
        return JSON.stringify(settings.relays);
      }

      case 'sign_event': {
        const s = requireSession(sessions, clientPub);
        touch(s);
        const raw = params[0];
        if (typeof raw !== 'string' || raw.length > 65536) throw err('invalid_request');
        let event;
        try {
          event = JSON.parse(raw);
        } catch {
          throw err('invalid_request');
        }
        if (!event || typeof event !== 'object' || !Number.isInteger(event.kind)) {
          throw err('invalid_request');
        }
        const decision = await requestApproval({
          kind: 'nip46-sign',
          clientName: s.clientName || '',
          clientPub: s.clientPub,
          event,
        });
        if (decision !== 'allow') throw err('unauthorized', 'signature denied');
        await saveSessions();
        const signed = finalizeEvent(priv, event);
        return JSON.stringify(signed);
      }

      case 'nip44_encrypt': {
        const s = requireSession(sessions, clientPub);
        touch(s);
        await saveSessions();
        const [peer, text] = params;
        if (typeof peer !== 'string' || typeof text !== 'string') throw err('invalid_request');
        return nip44Encrypt(priv, peer, text);
      }

      case 'nip44_decrypt': {
        const s = requireSession(sessions, clientPub);
        touch(s);
        await saveSessions();
        const [peer, payload] = params;
        if (typeof peer !== 'string' || typeof payload !== 'string') throw err('invalid_request');
        return nip44Decrypt(priv, peer, payload);
      }

      case 'nip04_encrypt': {
        const s = requireSession(sessions, clientPub);
        touch(s);
        await saveSessions();
        const [peer, text] = params;
        if (typeof peer !== 'string' || typeof text !== 'string') throw err('invalid_request');
        return nip04Encrypt(priv, peer, text);
      }

      case 'nip04_decrypt': {
        const s = requireSession(sessions, clientPub);
        touch(s);
        await saveSessions();
        const [peer, payload] = params;
        if (typeof peer !== 'string' || typeof payload !== 'string') throw err('invalid_request');
        return nip04Decrypt(priv, peer, payload);
      }

      default:
        throw err('unknown_method', 'unsupported method: ' + method);
    }
  }

  function requireSession(sessions, clientPub) {
    const s = sessionForClient(sessions, clientPub);
    if (!s) throw err('unauthorized', 'no active session for this client');
    return s;
  }

  function decodeSignerParam(raw) {
    const trimmed = String(raw).trim().toLowerCase();
    if (/^[0-9a-f]{64}$/.test(trimmed)) return trimmed;
    try {
      const bytes = decodeBech32Bytes(trimmed, 'npub');
      return bytesToHex(bytes);
    } catch {
      /* not bech32 */
    }
    return null;
  }

  function parseClientName(metadata) {
    if (typeof metadata !== 'string' || !metadata) return '';
    try {
      const obj = JSON.parse(metadata);
      return typeof obj?.name === 'string' ? obj.name.slice(0, 64) : '';
    } catch {
      return '';
    }
  }

  async function respond(clientPub, settings, id, result, error) {
    const sessions = await loadSessions();
    const s = sessionForClient(sessions, clientPub);
    const relays = s ? s.relays : settings.relays;
    const priv = await signerPrivHex();
    const payload = JSON.stringify({ id, result: result ?? '', error: error ?? '' });
    const ciphertext = nip44Encrypt(priv, clientPub, payload);
    const event = finalizeEvent(priv, {
      kind: REQUEST_KIND,
      tags: [['p', clientPub]],
      content: ciphertext,
    });
    await transport.publish(relays, event);
  }

  return {
    async start() {
      if (started) return;
      started = true;
      await refreshSubscriptions();
    },

    /** Alarm hook: prune expired invitations. */
    async tick() {
      const sessions = await loadSessions();
      const cutoff = now() - INVITE_TTL_MS;
      const before = sessions.length;
      const kept = sessions.filter((s) => s.bound || s.created > cutoff);
      if (kept.length !== before) {
        sessionsCache = kept;
        await saveSessions();
        await refreshSubscriptions();
      }
    },

    /** New bunker:// invitation over the settings relays. */
    async createInvite() {
      const sessions = await loadSessions();
      const boundCount = sessions.filter((s) => s.bound).length;
      if (boundCount >= MAX_SESSIONS) throw err('session_limit');
      const settings = await defaultSettings(storage);
      if (settings.relays.length === 0) throw err('no_relays');
      const secret = randomHex(16);
      const token = {
        secret,
        relays: [...settings.relays],
        clientPub: null,
        clientName: '',
        perms: '',
        created: now(),
        lastActive: null,
        bound: false,
      };
      sessions.push(token);
      sessionsCache = sessions;
      await saveSessions();
      await refreshSubscriptions();
      const uri = buildBunkerUri(await signerPub(), token.relays, secret);
      return { uri, secret, relays: token.relays, expires: token.created + INVITE_TTL_MS };
    },

    /** Revoke a connection by secret prefix (popup id). */
    async revoke(secretPrefix) {
      const sessions = await loadSessions();
      const idx = sessions.findIndex((s) => s.secret.startsWith(secretPrefix));
      if (idx < 0) throw err('invalid_request');
      sessions.splice(idx, 1);
      sessionsCache = sessions;
      await saveSessions();
      await refreshSubscriptions();
      return true;
    },

    /** Popup listing. */
    async listSessions() {
      const sessions = await loadSessions();
      return sessions
        .map((s) => ({
          id: s.secret.slice(0, 8),
          clientName: s.clientName || '',
          clientPub: s.clientPub,
          clientNpub: s.clientPub ? encodeNpub(s.clientPub) : null,
          relays: s.relays,
          perms: s.perms,
          bound: !!s.bound,
          created: s.created,
          lastActive: s.lastActive,
        }))
        .sort((a, b) => (b.lastActive ?? b.created) - (a.lastActive ?? a.created));
    },

    async getRelaySettings() {
      const settings = await defaultSettings(storage);
      return { relays: [...settings.relays] };
    },

    async setRelaySettings(relays) {
      const cleaned = normalizeRelayList(relays);
      const settings = await defaultSettings(storage);
      settings.relays = cleaned;
      await storage.set(SETTINGS_STORE, settings);
      await refreshSubscriptions();
      return { relays: cleaned };
    },

    /** Relay map for the NIP-07 getRelays surface. */
    async relaysMap() {
      const settings = await defaultSettings(storage);
      const map = {};
      for (const r of settings.relays) map[r] = { read: true, write: true };
      return map;
    },

    async stop() {
      for (const h of subHandles) h.close();
      subHandles = [];
      started = false;
    },
  };
}
