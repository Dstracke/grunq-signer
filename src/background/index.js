// Background (event page / service worker): the only place that touches keys.
// Handles NIP-07 RPCs from content scripts, origin permissions, approval
// dialogs and identity storage. NIP-46 relay sessions come in M2.
// UI/error language follows the browser settings via the i18n API.
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

const api = globalThis.browser ?? globalThis.chrome;

// Localized message lookup; falls back to the key itself when missing.
function t(key, subs) {
  return api.i18n?.getMessage?.(key, subs) || key;
}

const STORE = {
  KEY: 'grunq_signer:key', // { privHex, created }
  IDENTITY: 'grunq_signer:identity', // { pubkey, created }
  PERMISSIONS: 'grunq_signer:permissions', // { [origin]: { nip07: true, ts } }
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
      // M2: bunker sessions provide relays. NIP-07 callers treat {} as "none".
      return {};
    }

    case 'signEvent': {
      await requireOriginPermission(origin);
      const event = params?.event;
      if (!event || typeof event !== 'object') throw err('invalid_input');
      const decision = await requestApproval({ kind: 'sign-event', origin, event });
      if (decision !== 'allow') throw err('denied');
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

// ---------- popup messages ----------

async function handlePopup(msg) {
  switch (msg.action) {
    case 'state': {
      const key = await getStore(STORE.KEY);
      const perms = (await getStore(STORE.PERMISSIONS)) ?? {};
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
          .map(([origin, v]) => ({ origin, ts: v.ts })),
      };
    }

    case 'import': {
      const privHex = parseSecretInput(String(msg.input ?? ''));
      await setStore(STORE.KEY, { privHex, created: Date.now() });
      await setStore(STORE.IDENTITY, {
        pubkey: derivePubkeyHex(privHex),
        created: Date.now(),
      });
      return { ok: true };
    }

    case 'generate': {
      const id = randomIdentity();
      await setStore(STORE.KEY, { privHex: id.privHex, created: Date.now() });
      await setStore(STORE.IDENTITY, { pubkey: id.pubkeyHex, created: Date.now() });
      return { ok: true };
    }

    case 'remove': {
      await removeStore(STORE.KEY);
      await removeStore(STORE.IDENTITY);
      return { ok: true };
    }

    case 'revoke': {
      const perms = (await getStore(STORE.PERMISSIONS)) ?? {};
      delete perms[String(msg.origin ?? '')];
      await setStore(STORE.PERMISSIONS, perms);
      return { ok: true };
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
      return { kind: p.req.kind, origin: p.req.origin, event: p.req.event ?? null };
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
