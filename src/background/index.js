// Background (event page / service worker): the only place that touches keys.
// Handles NIP-07 RPCs from content scripts, origin permissions, approval
// dialogs, identity storage AND the NIP-46 remote signer (bunker) sessions
// over relays. UI/error language follows the browser settings via i18n.
import { derivePubkeyHex, encodeNpub, finalizeEvent } from '../lib/keys.js';
import {
  nip04Decrypt,
  nip04Encrypt,
  nip44Decrypt,
  nip44Encrypt,
} from '../lib/signing.js';
import { RelayPool } from '../lib/relay-pool.js';
import {
  createSignerCore,
  defaultSettings,
  SESSIONS_STORE,
  SETTINGS_STORE,
} from '../signer/core.js';
import { createKeystore, profileKey, sessionsKey } from '../signer/keystore.js';
import { createProfileService, PROFILE_STORE, planRepublish } from '../signer/profile.js';
import { createProfileChecks } from '../signer/profilechecks.js';
import { createAuditLog } from '../signer/audit.js';
import { createRateLimiter } from '../lib/ratelimit.js';

const api = globalThis.browser ?? globalThis.chrome;

// Localized message lookup; falls back to the key itself when missing.
function t(key, subs) {
  return api.i18n?.getMessage?.(key, subs) || key;
}

const STORE = {
  PERMISSIONS: 'grunq_signer:permissions', // { [origin]: { nip07: true, ts } }
};

function err(code) {
  const map = {
    no_key: 'errorNoKey',
    locked: 'errorLocked',
    wrong_password: 'errorWrongPassword',
    weak_password: 'errorWeakPassword',
    password_mismatch: 'errorPasswordMismatch',
    denied: 'errorDenied',
    rate_limited: 'errorRateLimited',
    invalid_backup: 'errorInvalidBackup',
    invalid_url: 'errorInvalidUrl',
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

// Extension session storage is memory-backed: the decrypted key survives
// event-page sleep but never touches disk and is gone after a browser
// restart. Where the browser lacks it (tests, old engines), a module-level
// map provides the same semantics for the running background instance.
const memorySession = new Map();
const sessionStore = api.storage?.session
  ? {
      get: async (key) => (await api.storage.session.get(key))[key],
      set: (key, value) => api.storage.session.set({ [key]: value }),
      remove: (key) => api.storage.session.remove(key),
    }
  : {
      get: async (key) => memorySession.get(key),
      set: async (key, value) => memorySession.set(key, value),
      remove: async (key) => memorySession.delete(key),
    };

const keystore = createKeystore({
  local: { get: getStore, set: setStore, remove: removeStore },
  session: sessionStore,
  log: (...args) => console.log('[keystore]', ...args),
});

// NIP-46 sessions and the public profile are per identity; relays, settings
// and site approvals stay global. The scoping resolves the active identity on
// every access, so switching identities needs no cache invalidation here (the
// signer core is stopped/reset around a switch).
async function scopedKey(key) {
  if (key === SESSIONS_STORE) return sessionsKey(await keystore.activeId());
  if (key === PROFILE_STORE) return profileKey(await keystore.activeId());
  return key;
}

const scopedStorage = {
  get: async (key) => getStore(await scopedKey(key)),
  set: async (key, value) => setStore(await scopedKey(key), value),
};

async function hasIdentity() {
  return (await keystore.status()).hasKey;
}

// Profile traffic is one-shot: a fresh relay pool per publish/fetch keeps
// sockets (and their reconnect timers) from living between popup actions.
const profileTransport = {
  publish: async (relays, event) => {
    const pool = new RelayPool();
    try {
      return await pool.publish(relays, event);
    } finally {
      pool.close();
    }
  },
  subscribe: (relays, filter, onEvent) => {
    const pool = new RelayPool();
    const handle = pool.subscribe(relays, filter, onEvent);
    return {
      close: () => {
        try {
          handle.close();
        } finally {
          pool.close();
        }
      },
    };
  },
};

const auditLog = createAuditLog({ storage: { get: getStore, set: setStore } });

// Pairing attempts are additionally throttled per page origin (the signer
// core throttles per client pubkey).
const pairingLimiter = createRateLimiter({ limit: 5, windowMs: 10 * 60 * 1000 });

// NIP-07 calls worth showing in the audit log (a chat page polls
// getPublicKey, that would only add noise).
const NIP07_AUDIT = new Set(['signEvent', 'nip04.decrypt', 'nip44.decrypt']);

// Start-up profile repair: once per browser run (at most once an hour), ask
// every relay whether it has our kind 0 and republish the local profile to the
// ones that lost it. Never publishes when nothing was published locally.
const PROFILE_CHECK_STORE = 'grunq_signer:profilecheck';
const PROFILE_CHECK_MIN_MS = 60 * 60 * 1000;
let profileCheckScheduled = false;

const profileChecks = createProfileChecks();

const profileService = createProfileService({
  storage: scopedStorage,
  transport: profileTransport,
  log: (...args) => console.log('[profile]', ...args),
});

function signDraft(draft) {
  return keystore.privateKeyHex().then((privHex) => finalizeEvent(privHex, draft));
}

async function republishProfileIfMissing(options = {}) {
  const status = await keystore.status();
  if (!status.hasKey || (status.encrypted && !status.unlocked)) return [];
  const local = await profileService.load();
  if (!local.publishedAt || !local.fields || Object.keys(local.fields).length === 0) return [];
  const marker = await sessionStore.get(PROFILE_CHECK_STORE);
  if (!options.force && marker?.checkedAt && Date.now() - marker.checkedAt < PROFILE_CHECK_MIN_MS) return [];
  const pubkey = await keystore.pubkeyHex();
  const { relays } = await signerCore.getRelaySettings();
  if (!pubkey || relays.length === 0) return [];
  // One fetch per relay: only the relays that actually lost the profile are
  // republished (a single merged fetch could not tell them apart).
  const perRelay = await Promise.all(
    relays.map(async (relay) => ({
      relay,
      present: !!(await profileService
        .fetchLatest(pubkey, [relay], { graceMs: 500, timeoutMs: 5000 })
        .catch(() => null)),
    })),
  );
  await sessionStore.set(PROFILE_CHECK_STORE, { checkedAt: Date.now() });
  const missing = planRepublish(local, perRelay);
  if (missing.length === 0) return [];
  await profileService.publish(local.fields, missing, signDraft);
  console.log('[profile] re-published on', missing.length, 'relay(s):', missing.join(', '));
  return missing;
}

function scheduleProfileRepublish() {
  if (profileCheckScheduled) return;
  profileCheckScheduled = true;
  republishProfileIfMissing().catch((e) => console.log('[profile] republish failed', e));
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
  storage: scopedStorage,
  transport: new RelayPool(),
  requestApproval,
  signerPrivHex: () => keystore.privateKeyHex(),
  onActivity: () => keystore.touch().catch(() => {}),
  onAudit: (entry) => auditLog.record(entry).catch((e) => console.log('[audit] write failed', e)),
  log: (...args) => console.log('[nip46]', ...args),
});

let signerBooted = false;

// Encrypted identities start locked: subscribing and signing both need the
// key, so the signer waits for the popup unlock (the Grunq node in turn waits
// for the signer — same behaviour as a sleeping signer phone).
async function bootSigner() {
  if (signerBooted) return;
  const status = await keystore.status();
  if (!status.hasKey || !status.unlocked) return;
  signerBooted = true;
  const ok = await signerCore.start().then(() => true).catch((e) => {
    console.log('[nip46] start failed', e);
    signerBooted = false;
    return false;
  });
  if (ok) scheduleProfileRepublish();
}

async function stopSigner() {
  if (!signerBooted) return;
  signerBooted = false;
  await signerCore.stop().catch(() => {});
}

async function securitySettings() {
  const settings = await defaultSettings({ get: getStore });
  return { idleMinutes: settings.idleMinutes, autoLock: settings.autoLock !== false };
}

// Keepalive tick: prune invitations, reconnect, and drop the in-memory key
// after the configured idle time. Signer traffic counts as activity (the
// keystore touches the session on every request), so a running stream never
// locks itself out; a quiet browser does.
async function runKeepalive() {
  const status = await keystore.status();
  if (!status.hasKey) return;
  const settings = await defaultSettings({ get: getStore });
  if (status.encrypted && status.unlocked && settings.autoLock !== false) {
    if (await keystore.autoLockIfIdle(settings.idleMinutes)) {
      console.log('[signer] auto-locked after idle');
      await stopSigner();
      return;
    }
  }
  if (signerBooted) signerCore.tick().catch((e) => console.log('[nip46] tick failed', e));
  await bootSigner();
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
    if (alarm?.name === KEEPALIVE_ALARM) {
      runKeepalive().catch((e) => console.log('[signer] keepalive failed', e));
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
  const method = String(msg?.method ?? '');
  const kind = Number.isInteger(msg?.params?.event?.kind) ? msg.params.event.kind : null;
  if (!NIP07_AUDIT.has(method)) return await dispatchRpc(msg, sender);
  try {
    const result = await dispatchRpc(msg, sender);
    await auditLog.record({ scope: 'nip07', method, ok: true, origin: origin ?? '', kind });
    return result;
  } catch (e) {
    await auditLog.record({
      scope: 'nip07',
      method,
      ok: false,
      code: e?.code ?? 'internal',
      origin: origin ?? '',
      kind,
    });
    throw e;
  }
}

async function dispatchRpc(msg, sender) {
  const origin = senderOrigin(sender);
  if (!origin || !/^https?:$/.test(new URL(origin).protocol)) {
    throw err('no_permission');
  }
  const { method, params = {} } = msg;
  const status = await keystore.status();
  if (!status.hasKey) throw err('no_key');
  // Encrypted identities must be unlocked before a site may do anything;
  // the popup shows the unlock field, the site gets a friendly error.
  if (status.encrypted && !status.unlocked) throw err('locked');

  switch (method) {
    case 'getPublicKey': {
      await requireOriginPermission(origin);
      const privHex = await keystore.privateKeyHex();
      await keystore.touch();
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
      const privHex = await keystore.privateKeyHex();
      await keystore.touch();
      // NIP-07: resolve with the signed event object directly.
      return finalizeEvent(privHex, event);
    }

    case 'nip04.encrypt': {
      await requireOriginPermission(origin);
      const privHex = await keystore.privateKeyHex();
      await keystore.touch();
      const { pubkey, text } = params;
      if (!is64Hex(pubkey) || typeof text !== 'string') throw err('invalid_input');
      // NIP-07: resolve with the ciphertext string directly.
      return await nip04Encrypt(privHex, pubkey, text);
    }

    case 'nip04.decrypt': {
      await requireOriginPermission(origin);
      const privHex = await keystore.privateKeyHex();
      await keystore.touch();
      const { pubkey, payload } = params;
      if (!is64Hex(pubkey) || typeof payload !== 'string') throw err('invalid_input');
      return await nip04Decrypt(privHex, pubkey, payload);
    }

    case 'nip44.encrypt': {
      await requireOriginPermission(origin);
      const privHex = await keystore.privateKeyHex();
      await keystore.touch();
      const { pubkey, text } = params;
      if (!is64Hex(pubkey) || typeof text !== 'string') throw err('invalid_input');
      return nip44Encrypt(privHex, pubkey, text);
    }

    case 'nip44.decrypt': {
      await requireOriginPermission(origin);
      const privHex = await keystore.privateKeyHex();
      await keystore.touch();
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
  const status = await keystore.status();
  if (!status.hasKey) throw err('no_key');
  if (status.encrypted && !status.unlocked) throw err('locked');
  if (webPairBusy) throw { code: 'busy', message: t('errorPairBusy') };
  if (pairingLimiter.isBlocked(origin)) {
    throw { code: 'rate_limited', message: t('errorRateLimited') };
  }
  webPairBusy = true;
  try {
    const res = await signerCore.connectNostrConnect(msg.uri, { origin });
    pairingLimiter.reset(origin);
    return res;
  } catch (e) {
    if (e?.nip46Code !== 'rate_limited') pairingLimiter.fail(origin);
    if (e?.nip46Code) {
      const map = {
        session_limit: 'nip46ErrorSessionLimit',
        no_relays: 'nip46ErrorNoRelays',
        unauthorized: 'nip46ErrorDenied',
        rate_limited: 'errorRateLimited',
    invalid_backup: 'errorInvalidBackup',
    invalid_url: 'errorInvalidUrl',
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

// Signer-core errors carry NIP-46 codes; translate the ones a popup can hit.
function popupError(e) {
  if (e?.code && e?.nip46Code === e.code) {
    const map = {
      locked: 'errorLocked',
      rate_limited: 'errorRateLimited',
    invalid_backup: 'errorInvalidBackup',
    invalid_url: 'errorInvalidUrl',
      session_limit: 'nip46ErrorSessionLimit',
      no_relays: 'nip46ErrorNoRelays',
      unauthorized: 'nip46ErrorDenied',
      invalid_request: 'errorInvalidInput',
    };
    throw { code: e.code, message: t(map[e.code] ?? 'errorInternal') };
  }
  throw e;
}

async function handlePopup(msg) {
  switch (msg.action) {
    case 'state': {
      const status = await keystore.status();
      const pubkey = status.hasKey ? await keystore.pubkeyHex() : null;
      const perms = (await getStore(STORE.PERMISSIONS)) ?? {};
      const [sessions, relays, security] = await Promise.all([
        status.hasKey ? signerCore.listSessions().catch(() => []) : Promise.resolve([]),
        signerCore.getRelaySettings().catch(() => ({ relays: [] })),
        securitySettings(),
      ]);
      return {
        hasKey: status.hasKey,
        encrypted: status.encrypted,
        unlocked: status.unlocked,
        identityCount: status.count,
        identity: pubkey
          ? { pubkey, npub: encodeNpub(pubkey), created: status.created, label: status.label }
          : null,
        approvals: Object.entries(perms)
          .filter(([, v]) => v?.nip07)
          .map(([origin, v]) => ({ origin, ts: v.ts, signKinds: Array.isArray(v?.sign_kinds) ? v.sign_kinds : [] })),
        sessions,
        relays: relays.relays,
        security,
      };
    }

    // Plain nsec/hex key, or an ncryptsec backup that needs its passphrase.
    // Imports/creates a NEW identity and makes it active.
    case 'import': {
      const input = String(msg.input ?? '').trim();
      // Restart the signer so subscriptions follow the new identity.
      await stopSigner();
      signerCore.reset();
      const label = typeof msg.label === 'string' ? msg.label : '';
      const res = /^ncryptsec1/i.test(input)
        ? await keystore.importNcryptsec(input, String(msg.passphrase ?? ''), label)
        : await keystore.importSecret(input, label);
      await bootSigner();
      return res;
    }

    case 'generate': {
      await stopSigner();
      signerCore.reset();
      const res = await keystore.generate(typeof msg.label === 'string' ? msg.label : '');
      await bootSigner();
      return res;
    }

    // ---------- multiple identities ----------

    case 'identity.list': {
      return await keystore.list();
    }

    case 'identity.switch': {
      await stopSigner();
      signerCore.reset();
      const status = await keystore.switchTo(String(msg.id ?? ''));
      await bootSigner();
      return status;
    }

    case 'identity.rename': {
      return await keystore.rename(String(msg.id ?? ''), String(msg.label ?? ''));
    }

    // ---------- encrypted identity backup ----------

    case 'backup.export': {
      const status = await keystore.status();
      if (!status.hasKey) throw err('no_key');
      const identities = await keystore.list();
      const profiles = {};
      for (const item of identities) {
        const rec = await getStore(profileKey(item.id));
        if (rec?.fields && Object.keys(rec.fields).length > 0) profiles[item.pubkey] = rec;
      }
      return await keystore.exportBackup(
        String(msg.password ?? ''),
        String(msg.repeat ?? ''),
        { profiles },
      );
    }

    case 'backup.import': {
      // Importing into an empty store is fine, no key needed.
      await stopSigner();
      signerCore.reset();
      const res = await keystore.importBackup(String(msg.text ?? ''), String(msg.password ?? ''), {
        replace: msg.replace === true,
      });
      // Profiles travel with the backup (keyed by pubkey); only fill gaps so a
      // locally edited profile is never overwritten by an older backup.
      let profilesRestored = 0;
      for (const item of await keystore.list()) {
        const saved = res.profiles?.[item.pubkey];
        if (!saved || typeof saved.fields !== 'object') continue;
        const key = profileKey(item.id);
        const existing = await getStore(key);
        if (existing?.fields && Object.keys(existing.fields).length > 0) continue;
        await setStore(key, {
          fields: saved.fields,
          eventId: null,
          publishedAt: Number.isFinite(saved.publishedAt) ? saved.publishedAt : null,
          updatedAt: Date.now(),
        });
        profilesRestored += 1;
      }
      await bootSigner();
      return { ...res, profilesRestored };
    }

    case 'identity.remove': {
      await stopSigner();
      signerCore.reset();
      const status = await keystore.removeIdentity(String(msg.id ?? ''));
      await bootSigner();
      return status;
    }

    // Identity export for migration to a phone/program: the popup asks for
    // the nsec only after its explicit two-step warning, so the secret never
    // sits in the UI until the user asked. The npub comes from `state`.
    case 'export': {
      if (msg.what !== 'nsec') throw err('invalid_input');
      return await keystore.exportNsec(msg.confirm === true);
    }

    /** Stored ncryptsec backup (for keeping it on paper/another device). */
    case 'export-backup': {
      const res = await keystore.exportNcryptsec();
      if (!res) throw err('invalid_input');
      return res;
    }

    // ---------- public profile (kind 0) ----------

    case 'profile.get': {
      const profile = await profileService.load();
      const pubkey = await keystore.pubkeyHex();
      return { ...profile, pubkey, npub: pubkey ? encodeNpub(pubkey) : null };
    }

    // Reading the profile needs no key, so this works while locked too.
    case 'profile.fetch': {
      const pubkey = await keystore.pubkeyHex();
      if (!pubkey) throw err('no_key');
      const { relays } = await signerCore.getRelaySettings();
      const fields = await profileService.fetchLatest(pubkey, relays, { graceMs: 700, timeoutMs: 7000 });
      if (!fields) throw { code: 'not_found', message: t('profileNotFound') };
      return { fields };
    }

    case 'profile.publish': {
      const status = await keystore.status();
      if (status.encrypted && !status.unlocked) throw err('locked');
      const { relays } = await signerCore.getRelaySettings();
      if (relays.length === 0) throw err('invalid_input');
      try {
        const res = await profileService.publish(msg.fields ?? {}, relays, signDraft);
        await keystore.touch();
        return { ...res, relays };
      } catch (e) {
        if (e?.code === 'empty_profile') throw { code: 'empty_profile', message: t('profileEmpty') };
        if (e?.code === 'invalid_url') {
          throw { code: 'invalid_url', message: t('errorInvalidUrl', [(e.fields ?? []).join(', ')]) };
        }
        if (e?.code) throw e;
        throw { code: 'publish_failed', message: t('profilePublishFailed', [String(e?.message ?? e)]) };
      }
    }

    // ---------- settings page (options) ----------

    // Options-page pairing: same flow as the page bridge, but the URI is
    // pasted or arrives as ?nostrconnect= deep link instead of postMessage.
    case 'nostrconnect.pair': {
      const status = await keystore.status();
      if (!status.hasKey) throw err('no_key');
      if (status.encrypted && !status.unlocked) throw err('locked');
      if (typeof msg.uri !== 'string' || !msg.uri.trim().startsWith('nostrconnect:')) {
        throw err('invalid_input');
      }
      const key = 'options';
      if (pairingLimiter.isBlocked(key)) throw err('rate_limited');
      try {
        const res = await signerCore.connectNostrConnect(msg.uri.trim(), {
          origin: t('pairSourceOptions'),
        });
        pairingLimiter.reset(key);
        return res;
      } catch (e) {
        if (e?.nip46Code !== 'rate_limited') pairingLimiter.fail(key);
        popupError(e);
      }
    }

    case 'audit.list': {
      return await auditLog.list({
        clientPub: typeof msg.clientPub === 'string' && msg.clientPub ? msg.clientPub : undefined,
        origin: typeof msg.origin === 'string' && msg.origin ? msg.origin : undefined,
        perSession: Number.isInteger(msg.limit) ? msg.limit : undefined,
      });
    }

    case 'audit.clear': {
      return await auditLog.clear();
    }

    // Remove one remembered sign kind from a site (the origin keeps its
    // approval; only that kind asks again).
    case 'revoke-kind': {
      const origin = String(msg.origin ?? '');
      const kind = Number(msg.kind);
      const perms = (await getStore(STORE.PERMISSIONS)) ?? {};
      if (!perms[origin]) throw err('invalid_input');
      const kinds = Array.isArray(perms[origin].sign_kinds)
        ? perms[origin].sign_kinds.filter((k) => Number(k) !== kind)
        : [];
      perms[origin] = { ...perms[origin], sign_kinds: kinds };
      await setStore(STORE.PERMISSIONS, perms);
      return { ok: true, signKinds: kinds };
    }

    // On-demand verification of the human-readable profile fields.
    case 'profile.check-lud16': {
      return await profileChecks.checkLud16(String(msg.address ?? ''));
    }

    case 'profile.check-nip05': {
      const pubkey = await keystore.pubkeyHex();
      if (!pubkey) throw err('no_key');
      return await profileChecks.checkNip05(
        String(msg.address ?? ''),
        pubkey,
        { force: msg.force === true },
      );
    }

    // Manual repair pull ("check relays") for the options page.
    case 'profile.check': {
      const missing = await republishProfileIfMissing({ force: true });
      return { missing };
    }

    case 'profile.delete': {
      const status = await keystore.status();
      if (status.encrypted && !status.unlocked) throw err('locked');
      const pubkey = await keystore.pubkeyHex();
      if (!pubkey) throw err('no_key');
      const { relays } = await signerCore.getRelaySettings();
      const res = await profileService.remove(pubkey, relays, signDraft);
      await keystore.touch();
      return res;
    }

    // ---------- lock / passphrase ----------

    case 'unlock': {
      const res = await keystore.unlock(String(msg.password ?? ''));
      await bootSigner();
      return res;
    }

    case 'lock': {
      await keystore.lock();
      await stopSigner();
      return { ok: true };
    }

    case 'protect':
    case 'change-passphrase': {
      const res = await keystore.protect(String(msg.password ?? ''), String(msg.repeat ?? ''));
      return res;
    }

    case 'unprotect': {
      await keystore.unprotect();
      return { ok: true };
    }

    case 'security.set': {
      const settings = await defaultSettings({ get: getStore });
      const idle = Number(msg.idleMinutes);
      settings.idleMinutes = Number.isFinite(idle) ? Math.min(240, Math.max(1, Math.round(idle))) : 30;
      settings.autoLock = msg.autoLock !== false;
      await setStore(SETTINGS_STORE, settings);
      return await securitySettings();
    }

    case 'remove': {
      await stopSigner();
      signerCore.reset();
      const status = await keystore.remove();
      await bootSigner();
      return status;
    }

    case 'revoke': {
      const perms = (await getStore(STORE.PERMISSIONS)) ?? {};
      delete perms[String(msg.origin ?? '')];
      await setStore(STORE.PERMISSIONS, perms);
      return { ok: true };
    }

    // ---------- NIP-46 (bunker) ----------

    case 'nip46.invite': {
      try {
        await bootSigner();
        return await signerCore.createInvite();
      } catch (e) {
        popupError(e);
      }
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
        duplicateName: p.req.duplicateName === true,
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
