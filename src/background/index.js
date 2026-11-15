// Background (event page / service worker): the only place that touches keys.
// Handles NIP-07 RPCs from content scripts, origin permissions, approval
// dialogs, identity storage AND the NIP-46 remote signer (bunker) sessions
// over relays. UI/error language follows the browser settings via i18n.
import {
  derivePubkeyHex,
  encodeNpub,
  finalizeEvent,
  parseSecretInput,
  randomIdentity,
} from '../lib/keys.js';
import {
  nip04Decrypt,
  nip04Encrypt,
  nip44Decrypt,
  nip44Encrypt,
} from '../lib/signing.js';
import { RelayPool } from '../lib/relay-pool.js';
import { createSignerCore, SETTINGS_STORE, SESSIONS_STORE } from '../signer/core.js';

const api = globalThis.browser ?? globalThis.chrome;

// Localized message lookup; falls back to the key itself when missing.
function t(key, subs) {
  return api.i18n?.getMessage?.(key, subs) || key;
}

const STORE = {
  KEY: 'grunq_signer:key', // { privHex, created }
  IDENTITY: 'grunq_signer:identity', // { pubkey, created }
  PERMISSIONS: 'grunq_signer:permissions', // { [origin]: { nip07: true, ts } }
  SESSIONS: SESSIONS_STORE, // [ { secret, relays, clientPub, ... } ]
  SETTINGS: SETTINGS_STORE, // { relays: [...], idleMinutes }
};

function err(code) {
  const map = {
    no_key: 'errorNoKey',
    denied: 'errorDenied',
    invalid_input: 'errorInvalidInput',
    no_permission: 'errorNoPermission',
    internal: 'errorInternal',
  };
  return { code, message: t(map[code] ?? 'errorInternal') };
}

// Encrypt/decrypt counterparts must be 32-byte hex pubkeys; a friendlier
// rejection here beats raw crypto-library errors surfacing as "internal".
const is64Hex = (s) => typeof s === 'string' && /^[0-9a-f]{64}$/.test(s);

async function getStore(key, fallback = undefined) {
  const res = await api.storage.local.get(key);
  return res[key] ?? fallback;
}

function setStore(key, value) {
  return api.storage.local.set({ [key]: value });
}

async function removeStore(key) {
  return api.storage.local.remove(key);
}

async function hasIdentity() {
  return (await getStore(STORE.KEY)) != null;
}

// ---------- approval windows ----------

/** @type {Map<string, {resolve: Function, req: any, winId?: number}>} */
const pendingApprovals = new Map();

function requestApproval(req) {
  return new Promise((resolve) => {
    const requestId = crypto.randomUUID();
    const url =
      api.runtime.getURL('approval/approval.html') +
      '#' +
      encodeURIComponent(requestId);
    api.windows
      .create({ url, type: 'popup', width: 440, height: 640 })
      .then((win) => {
        pendingApprovals.set(requestId, { resolve, req, winId: win.id });
      })
      .catch(() => resolve('deny'));
  });
}

function finishApproval(requestId, decision) {
  const p = pendingApprovals.get(requestId);
  if (!p) return false;
  pendingApprovals.delete(requestId);
  if (p.winId != null) api.windows.remove(p.winId).catch(() => {});
  p.resolve(decision);
  return true;
}

api.windows?.onRemoved?.addListener?.((winId) => {
  for (const [id, p] of pendingApprovals) {
    if (p.winId === winId) {
      pendingApprovals.delete(id);
      p.resolve('deny');
    }
  }
});

// ---------- permissions ----------

async function isAllowed(origin) {
  const perms = (await getStore(STORE.PERMISSIONS)) ?? {};
  return !!perms[origin]?.nip07;
}

async function requireOriginPermission(origin) {
  if (await isAllowed(origin)) return true;
  const decision = await requestApproval({ kind: 'nip07-access', origin });
  if (decision === 'always') {
    const perms = (await getStore(STORE.PERMISSIONS)) ?? {};
    perms[origin] = { nip07: true, ts: Date.now() };
    await setStore(STORE.PERMISSIONS, perms);
    return true;
  }
  if (decision === 'allow') return true;
  throw err('denied');
}

// Kind-scoped NIP-07 sign memory: chat signers (the Grunq viewer posts
// kind 1311 per message) would otherwise reopen an approval window for
// every single message. 'always' in the sign dialog persists the kind
// for this origin; other kinds keep asking.
async function canSignKind(origin, kind) {
  const perms = (await getStore(STORE.PERMISSIONS)) ?? {};
  const kinds = perms[origin]?.sign_kinds;
  return Array.isArray(kinds) && kinds.includes(Number(kind));
}

async function rememberSignKind(origin, kind) {
  const perms = (await getStore(STORE.PERMISSIONS)) ?? {};
  const entry = perms[origin] ?? {};
  const kinds = Array.isArray(entry.sign_kinds) ? entry.sign_kinds : [];
  if (!kinds.includes(Number(kind))) kinds.push(Number(kind));
  perms[origin] = { ...entry, sign_kinds: kinds };
  await setStore(STORE.PERMISSIONS, perms);
}

// ---------- NIP-46 signer (bunker) ----------

const signerCore = createSignerCore({
  storage: {
    get: (key) => getStore(key),
    set: (key, value) => setStore(key, value),
  },
  transport: new RelayPool(),
  requestApproval,
  signerPrivHex: async () => (await getStore(STORE.KEY))?.privHex,
  log: (...args) => console.log('[nip46]', ...args),
});

let signerBooted = false;

async function bootSigner() {
  if (signerBooted) return;
  if (!(await hasIdentity())) return;
  signerBooted = true;
  await signerCore.start().catch((e) => {
    console.log('[nip46] start failed', e);
    signerBooted = false;
  });
}

// Event pages start fresh on browser start and (re)install; the top-level
// call covers every other wake-up. Reconnect-on-wake is the whole strategy:
// on start we reload the session registry and re-subscribe (since = now-5min
// catches requests that arrived while the page was asleep).
api.runtime.onStartup?.addListener?.(() => bootSigner());
api.runtime.onInstalled?.addListener?.(() => bootSigner());
bootSigner();

// Keepalive alarm: wakes the event page so sessions get reconnected and
// expired pairing invitations get pruned. One minute is the smallest period
// both Firefox and Chromium accept reliably.
const KEEPALIVE_ALARM = 'grunq-signer-keepalive';
try {
  api.alarms?.create?.(KEEPALIVE_ALARM, { periodInMinutes: 1 });
  api.alarms?.onAlarm?.addListener?.((alarm) => {
    if (alarm?.name === KEEPALIVE_ALARM && signerBooted) {
      signerCore.tick().catch((e) => console.log('[nip46] tick failed', e));
      bootSigner();
    }
  });
} catch {
  /* alarms unavailable (tests) - reconnect-on-wake still covers us */
}

// ---------- NIP-07 RPC handling ----------

function senderOrigin(sender) {
  if (sender?.url) {
    try {
      return new URL(sender.url).origin;
    } catch {
      /* fall through */
    }
  }
  return sender?.origin;
}

async function handleRpc(msg, sender) {
  const origin = senderOrigin(sender);
  if (!origin || !/^https?:$/.test(new URL(origin).protocol)) {
    throw err('no_permission');
  }
  const { method, params = {} } = msg;
  if (!(await hasIdentity())) throw err('no_key');

  switch (method) {
    case 'getPublicKey': {
      await requireOriginPermission(origin);
      const { privHex } = await getStore(STORE.KEY);
      // NIP-07: resolve with the hex pubkey string directly.
      return derivePubkeyHex(privHex);
    }

    case 'getRelays': {
      // NIP-07 callers treat {} as "none"; with NIP-46 relays configured we
      // report the allowlist as read+write per the NIP-07 shape.
      return signerCore.relaysMap();
    }

    case 'signEvent': {
      await requireOriginPermission(origin);
      const event = params?.event;
      if (!event || typeof event !== 'object') throw err('invalid_input');
      if (!(await canSignKind(origin, event.kind))) {
        const decision = await requestApproval({ kind: 'sign-event', origin, event });
        if (decision === 'always') {
          await rememberSignKind(origin, event.kind);
        } else if (decision !== 'allow') {
          throw err('denied');
        }
      }
      const { privHex } = await getStore(STORE.KEY);
      // NIP-07: resolve with the signed event object directly.
      return finalizeEvent(privHex, event);
    }

    case 'nip04.encrypt': {
      await requireOriginPermission(origin);
      const { privHex } = await getStore(STORE.KEY);
      const { pubkey, text } = params;
      if (!is64Hex(pubkey) || typeof text !== 'string') throw err('invalid_input');
      // NIP-07: resolve with the ciphertext string directly.
      return await nip04Encrypt(privHex, pubkey, text);
    }

    case 'nip04.decrypt': {
      await requireOriginPermission(origin);
      const { privHex } = await getStore(STORE.KEY);
      const { pubkey, payload } = params;
      if (!is64Hex(pubkey) || typeof payload !== 'string') throw err('invalid_input');
      return await nip04Decrypt(privHex, pubkey, payload);
    }

    case 'nip44.encrypt': {
      await requireOriginPermission(origin);
      const { privHex } = await getStore(STORE.KEY);
      const { pubkey, text } = params;
      if (!is64Hex(pubkey) || typeof text !== 'string') throw err('invalid_input');
      return nip44Encrypt(privHex, pubkey, text);
    }

    case 'nip44.decrypt': {
      await requireOriginPermission(origin);
      const { privHex } = await getStore(STORE.KEY);
      const { pubkey, payload } = params;
      if (!is64Hex(pubkey) || typeof payload !== 'string') throw err('invalid_input');
      return nip44Decrypt(privHex, pubkey, payload);
    }

    default:
      throw { code: 'internal', message: t('errorUnknownMethod', [String(method)]) };
  }
}

// ---------- web pairing (nostrconnect deep-link from pages) ----------

// Only one pairing approval at a time; pages could otherwise spam approval
// windows by repeated postMessages.
let webPairBusy = false;

async function handleWebNostrConnect(msg, sender) {
  const origin = senderOrigin(sender);
  if (!origin || !/^https?:$/.test(new URL(origin).protocol)) {
    throw err('no_permission');
  }
  if (typeof msg.uri !== 'string' || !msg.uri.startsWith('nostrconnect:')) {
    throw err('invalid_input');
  }
  if (!(await hasIdentity())) throw err('no_key');
  if (webPairBusy) throw { code: 'busy', message: t('errorPairBusy') };
  webPairBusy = true;
  try {
    return await signerCore.connectNostrConnect(msg.uri, { origin });
  } catch (e) {
    if (e?.nip46Code) {
      const map = {
        session_limit: 'nip46ErrorSessionLimit',
        no_relays: 'nip46ErrorNoRelays',
        unauthorized: 'nip46ErrorDenied',
        invalid_request: 'errorInvalidInput',
      };
      throw { code: e.nip46Code, message: t(map[e.nip46Code] ?? 'errorInternal') };
    }
    throw e;
  } finally {
    webPairBusy = false;
  }
}

// ---------- popup messages ----------

async function handlePopup(msg) {
  switch (msg.action) {
    case 'state': {
      const key = await getStore(STORE.KEY);
      const perms = (await getStore(STORE.PERMISSIONS)) ?? {};
      const [sessions, relays] = await Promise.all([
        key ? signerCore.listSessions().catch(() => []) : Promise.resolve([]),
        signerCore.getRelaySettings().catch(() => ({ relays: [] })),
      ]);
      return {
        hasKey: !!key,
        identity: key
          ? {
              pubkey: derivePubkeyHex(key.privHex),
              npub: encodeNpub(derivePubkeyHex(key.privHex)),
              created: key.created,
            }
          : null,
        approvals: Object.entries(perms)
          .filter(([, v]) => v?.nip07)
          .map(([origin, v]) => ({ origin, ts: v.ts, signKinds: Array.isArray(v?.sign_kinds) ? v.sign_kinds : [] })),
        sessions,
        relays: relays.relays,
      };
    }

    case 'import': {
      const privHex = parseSecretInput(String(msg.input ?? ''));
      await setStore(STORE.KEY, { privHex, created: Date.now() });
      await setStore(STORE.IDENTITY, {
        pubkey: derivePubkeyHex(privHex),
        created: Date.now(),
      });
      await bootSigner();
      return { ok: true };
    }

    case 'generate': {
      const id = randomIdentity();
      await setStore(STORE.KEY, { privHex: id.privHex, created: Date.now() });
      await setStore(STORE.IDENTITY, { pubkey: id.pubkeyHex, created: Date.now() });
      await bootSigner();
      return { ok: true };
    }

    case 'remove': {
      await removeStore(STORE.KEY);
      await removeStore(STORE.IDENTITY);
      if (signerBooted) {
        signerBooted = false;
        await signerCore.stop();
      }
      return { ok: true };
    }

    case 'revoke': {
      const perms = (await getStore(STORE.PERMISSIONS)) ?? {};
      delete perms[String(msg.origin ?? '')];
      await setStore(STORE.PERMISSIONS, perms);
      return { ok: true };
    }

    // ---------- NIP-46 (bunker) ----------

    case 'nip46.invite': {
      await bootSigner();
      return await signerCore.createInvite();
    }

    case 'nip46.sessions': {
      return await signerCore.listSessions();
    }

    case 'nip46.revoke': {
      await signerCore.revoke(String(msg.id ?? ''));
      return { ok: true };
    }

    case 'nip46.relays.get': {
      return await signerCore.getRelaySettings();
    }

    case 'nip46.relays.set': {
      const list = Array.isArray(msg.relays) ? msg.relays : [];
      return await signerCore.setRelaySettings(list);
    }

    default:
      throw err('invalid_input');
  }
}

// ---------- approval-page messages ----------

async function handleApprovalPage(msg) {
  switch (msg.action) {
    case 'info': {
      const p = pendingApprovals.get(String(msg.requestId ?? ''));
      if (!p) return null;
      return {
        kind: p.req.kind,
        origin: p.req.origin,
        event: p.req.event ?? null,
        clientName: p.req.clientName ?? '',
        clientPub: p.req.clientPub ?? null,
        clientNpub: p.req.clientPub ? encodeNpub(p.req.clientPub) : null,
        relays: p.req.relays ?? null,
        scheme: p.req.scheme ?? '',
        peer: p.req.peer ?? '',
        payload: p.req.payload ?? '',
      };
    }
    case 'decide': {
      const done = finishApproval(String(msg.requestId ?? ''), msg.decision);
      return { ok: done };
    }
    default:
      throw err('invalid_input');
  }
}

// ---------- router ----------

api.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  (async () => {
    if (msg?.type === 'nostr-rpc') {
      return await handleRpc(msg, sender);
    }
    if (msg?.type === 'web-nostrconnect') {
      return await handleWebNostrConnect(msg, sender);
    }
    if (msg?.type === 'popup') {
      return await handlePopup(msg);
    }
    if (msg?.type === 'approval-page') {
      return await handleApprovalPage(msg);
    }
    return err('invalid_input');
  })()
    .then(sendResponse)
    .catch((e) => {
      if (e && typeof e === 'object' && e.code) sendResponse({ error: e });
      else sendResponse({ error: { code: 'internal', message: String(e?.message ?? e) } });
    });
  return true; // async response
});
