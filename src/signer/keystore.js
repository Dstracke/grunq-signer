// Key store: one or more identities, each with a label, its own public key and
// either a plaintext secret (Stufe 1) or a NIP-49 `ncryptsec`. Exactly one
// identity is active; NIP-07, the NIP-46 signer and the profile follow it.
//
// Decrypted keys only live in extension session storage (memory), keyed per
// identity, and are gone after a browser restart. The passphrase is never
// stored.
//
// Storage (v2):
//   grunq_signer:identities   { version: 2, active, items: [ { id, label,
//                               pubkey, created, secret: { privHex } |
//                               { ncryptsec } } ] }
//   grunq_signer:unlock       session: { [id]: { privHex, unlockedAt } }
//   grunq_signer:sessions:<id>  NIP-46 sessions (per identity)
//   grunq_signer:profile:<id>   public profile (per identity)
//
// Legacy single-identity records (grunq_signer:key, :identity, :session,
// :sessions, :profile) are migrated on first use.
import {
  derivePubkeyHex,
  encodeNpub,
  encodeNsec,
  parseSecretInput,
  randomIdentity,
} from '../lib/keys.js';
import {
  DEFAULT_LOG_N,
  SECURITY_INSECURE,
  decrypt as nip49Decrypt,
  encrypt as nip49Encrypt,
} from '../lib/nip49.js';

export const IDENTITIES_STORE = 'grunq_signer:identities';
export const UNLOCK_STORE = 'grunq_signer:unlock'; // session storage, memory only
export const SESSIONS_PREFIX = 'grunq_signer:sessions:';
export const PROFILE_PREFIX = 'grunq_signer:profile:';

export const MIN_PASSWORD_LENGTH = 8;

const LEGACY = {
  key: 'grunq_signer:key',
  identity: 'grunq_signer:identity',
  session: 'grunq_signer:session',
  sessions: 'grunq_signer:sessions',
  profile: 'grunq_signer:profile',
};

export const sessionsKey = (id) => `${SESSIONS_PREFIX}${id}`;
export const profileKey = (id) => `${PROFILE_PREFIX}${id}`;

function fail(code, message) {
  const e = new Error(message ?? code);
  e.code = code;
  // NIP-46 responses carry error strings like "error:locked".
  e.nip46Code = code;
  return e;
}

export function createKeystore(env) {
  const {
    local, // { get, set, remove } persistent storage
    session, // { get, set, remove } memory-backed extension session storage
    now = () => Date.now(),
    logN = DEFAULT_LOG_N,
    newId = () => globalThis.crypto?.randomUUID?.() ?? Math.random().toString(36).slice(2),
    log = () => {},
  } = env;

  let ready = null;

  async function readDb() {
    return (await local.get(IDENTITIES_STORE)) ?? { version: 2, active: null, items: [] };
  }

  async function writeDb(db) {
    await local.set(IDENTITIES_STORE, db);
    return db;
  }

  // One-time migration of the pre-multi-identity storage layout.
  async function migrate() {
    const existing = await local.get(IDENTITIES_STORE);
    if (existing) return existing;
    const db = { version: 2, active: null, items: [] };
    const legacy = await local.get(LEGACY.key);
    if (legacy) {
      const id = newId();
      const secret = legacy.privHex
        ? { privHex: legacy.privHex }
        : { ncryptsec: legacy.ncryptsec };
      const privHex = legacy.privHex ?? null;
      db.items.push({
        id,
        label: '',
        pubkey: privHex ? derivePubkeyHex(privHex) : (await local.get(LEGACY.identity))?.pubkey ?? null,
        created: legacy.created ?? now(),
        secret,
      });
      db.active = id;
      const sessions = await local.get(LEGACY.sessions);
      if (sessions) await local.set(sessionsKey(id), sessions);
      const profile = await local.get(LEGACY.profile);
      if (profile) await local.set(profileKey(id), profile);
      const unlock = await session.get(LEGACY.session);
      if (unlock?.privHex) {
        await unlockSet(id, unlock.privHex, unlock.unlockedAt);
      }
      await local.remove(LEGACY.sessions);
      await local.remove(LEGACY.profile);
      await local.remove(LEGACY.key);
      await local.remove(LEGACY.identity);
      await session.remove(LEGACY.session);
      log('migrated legacy identity', id);
    }
    return writeDb(db);
  }

  function ensureReady() {
    if (!ready) ready = migrate();
    return ready;
  }

  async function db() {
    await ensureReady();
    return readDb();
  }

  function activeItem(database) {
    return database.items.find((i) => i.id === database.active) ?? null;
  }

  function publicItem(item, unlocks) {
    const encrypted = typeof item.secret.ncryptsec === 'string';
    return {
      id: item.id,
      label: item.label || '',
      pubkey: item.pubkey,
      npub: item.pubkey ? encodeNpub(item.pubkey) : null,
      created: item.created,
      encrypted,
      unlocked: !encrypted || !!unlocks[item.id]?.privHex,
    };
  }

  async function unlockMap() {
    return (await session.get(UNLOCK_STORE)) ?? {};
  }

  async function unlockSet(id, privHex, unlockedAt) {
    const map = await unlockMap();
    map[id] = { privHex, unlockedAt: unlockedAt ?? now() };
    await session.set(UNLOCK_STORE, map);
  }

  async function unlockClear(id) {
    const map = await unlockMap();
    if (!map[id]) return false;
    delete map[id];
    await session.set(UNLOCK_STORE, map);
    return true;
  }

  function checkPassword(password, repeat) {
    if (typeof password !== 'string' || password.length < MIN_PASSWORD_LENGTH) {
      throw fail('weak_password');
    }
    if (repeat !== undefined && password !== repeat) {
      throw fail('password_mismatch');
    }
  }

  function newItem(secret, pubkey, label) {
    return {
      id: newId(),
      label: typeof label === 'string' ? label.trim().slice(0, 40) : '',
      pubkey,
      created: now(),
      secret,
    };
  }

  async function privateKeyOf(item) {
    if (!item) throw fail('no_key');
    if (item.secret.privHex) return item.secret.privHex;
    const unlocks = await unlockMap();
    if (unlocks[item.id]?.privHex) return unlocks[item.id].privHex;
    throw fail('locked');
  }

  const api = {
    /** { hasKey, count, encrypted, unlocked, created, label } of the active identity. */
    async status() {
      const database = await db();
      const item = activeItem(database);
      if (!item) {
        return { hasKey: false, count: database.items.length, encrypted: false, unlocked: false, created: null, label: '' };
      }
      const unlocks = await unlockMap();
      const encrypted = typeof item.secret.ncryptsec === 'string';
      return {
        hasKey: true,
        count: database.items.length,
        encrypted,
        unlocked: !encrypted || !!unlocks[item.id]?.privHex,
        created: item.created ?? null,
        label: item.label || '',
      };
    },

    async activeId() {
      return (await db()).active;
    },

    /** All identities (no secrets), for the settings page. */
    async list() {
      const database = await db();
      const unlocks = await unlockMap();
      return database.items.map((item) => ({
        ...publicItem(item, unlocks),
        active: item.id === database.active,
      }));
    },

    /** Public key of the active identity, readable while locked. */
    async pubkeyHex() {
      return activeItem(await db())?.pubkey ?? null;
    },

    async npub() {
      const pub = await api.pubkeyHex();
      return pub ? encodeNpub(pub) : null;
    },

    /** Signing key of the active identity; throws "locked" when needed. */
    async privateKeyHex() {
      return privateKeyOf(activeItem(await db()));
    },

    /** Activity marker for auto-lock (active identity only). */
    async touch() {
      const item = activeItem(await db());
      if (!item || !item.secret.ncryptsec) return false;
      const unlocks = await unlockMap();
      if (!unlocks[item.id]?.privHex) return false;
      unlocks[item.id].unlockedAt = now();
      await session.set(UNLOCK_STORE, unlocks);
      return true;
    },

    /** Import nsec/hex as a new active identity. */
    async importSecret(input, label) {
      const privHex = parseSecretInput(String(input ?? ''));
      const database = await db();
      const item = newItem({ privHex }, derivePubkeyHex(privHex), label);
      database.items.push(item);
      database.active = item.id;
      await writeDb(database);
      return publicItem(item, await unlockMap());
    },

    /** Import an ncryptsec backup (passphrase required) as a new active identity. */
    async importNcryptsec(input, password, label) {
      const raw = String(input ?? '').trim().toLowerCase();
      if (!/^ncryptsec1[02-9ac-hj-np-z]+$/.test(raw)) throw fail('invalid_input');
      const out = nip49Decrypt(raw, password); // throws wrong_password
      const database = await db();
      const item = newItem({ ncryptsec: raw }, derivePubkeyHex(out.privHex), label);
      database.items.push(item);
      database.active = item.id;
      await writeDb(database);
      await unlockSet(item.id, out.privHex);
      return publicItem(item, await unlockMap());
    },

    /** Create a fresh identity and make it active. */
    async generate(label) {
      const id = randomIdentity();
      const database = await db();
      const item = newItem({ privHex: id.privHex }, id.pubkeyHex, label);
      database.items.push(item);
      database.active = item.id;
      await writeDb(database);
      return publicItem(item, await unlockMap());
    },

    /** Switch the active identity (caller restarts the signer). */
    async switchTo(id) {
      const database = await db();
      if (!database.items.some((i) => i.id === id)) throw fail('invalid_input');
      database.active = id;
      await writeDb(database);
      return api.status();
    },

    async rename(id, label) {
      const database = await db();
      const item = database.items.find((i) => i.id === id);
      if (!item) throw fail('invalid_input');
      item.label = String(label ?? '').trim().slice(0, 40);
      await writeDb(database);
      return publicItem(item, await unlockMap());
    },

    /** Unlock the active identity with its passphrase. */
    async unlock(password) {
      const item = activeItem(await db());
      if (!item) throw fail('no_key');
      if (item.secret.privHex) return { encrypted: false, npub: encodeNpub(item.pubkey) };
      let out;
      try {
        out = nip49Decrypt(item.secret.ncryptsec, password);
      } catch (e) {
        if (e?.code === 'wrong_password') throw fail('wrong_password');
        throw e;
      }
      if (item.pubkey !== derivePubkeyHex(out.privHex)) throw fail('wrong_password');
      await unlockSet(item.id, out.privHex);
      return { encrypted: true, npub: encodeNpub(item.pubkey) };
    },

    /** Drop the in-memory key of the active identity. */
    async lock() {
      const item = activeItem(await db());
      if (!item) return true;
      await unlockClear(item.id);
      return true;
    },

    /**
     * Auto-lock: drop in-memory keys that idled too long. Returns true when
     * the active identity was locked (the caller stops the signer).
     */
    async autoLockIfIdle(minutes) {
      const database = await db();
      const item = activeItem(database);
      const map = await unlockMap();
      const idleMs = Math.max(1, Number(minutes) || 30) * 60 * 1000;
      const cutoff = now() - idleMs;
      let activeLocked = false;
      let changed = false;
      for (const id of Object.keys(map)) {
        const entry = map[id];
        if (!entry?.privHex) continue;
        // Only identities whose stored secret is encrypted may be locked.
        const owner = database.items.find((i) => i.id === id);
        if (!owner || !owner.secret.ncryptsec) continue;
        if ((entry.unlockedAt ?? 0) >= cutoff) continue;
        delete map[id];
        changed = true;
        if (item?.id === id) activeLocked = true;
      }
      if (changed) await session.set(UNLOCK_STORE, map);
      return activeLocked;
    },

    /**
     * Encrypt the active identity at rest (first time) or re-key it (change).
     * Returns the ncryptsec string so the popup can show it as a backup.
     */
    async protect(password, repeat) {
      checkPassword(password, repeat);
      const database = await db();
      const item = activeItem(database);
      const privHex = await privateKeyOf(item); // throws locked
      const ncryptsec = nip49Encrypt(privHex, password, {
        logN,
        // The key was stored/imported unencrypted at some point, so NIP-49
        // asks us to mark it as handled insecurely (also on re-keying).
        securityByte: SECURITY_INSECURE,
      });
      item.secret = { ncryptsec };
      await writeDb(database);
      await unlockSet(item.id, privHex);
      return { ncryptsec };
    },

    /** Remove the passphrase protection of the active identity. */
    async unprotect() {
      const database = await db();
      const item = activeItem(database);
      const privHex = await privateKeyOf(item);
      item.secret = { privHex };
      await writeDb(database);
      await unlockClear(item.id);
      return true;
    },

    /** Nsec export of the active identity; only when unlocked + confirmed. */
    async exportNsec(confirmed) {
      if (confirmed !== true) throw fail('denied');
      return { nsec: encodeNsec(await api.privateKeyHex()) };
    },

    /** Stored ncryptsec of the active identity (backup), or null. */
    async exportNcryptsec() {
      const item = activeItem(await db());
      if (!item?.secret.ncryptsec) return null;
      return { ncryptsec: item.secret.ncryptsec };
    },

    /** Remove the active identity; falls back to the most recent remaining one. */
    async remove(id) {
      return api.removeIdentity(id ?? (await db()).active);
    },

    async removeIdentity(id) {
      const database = await db();
      const idx = database.items.findIndex((i) => i.id === id);
      if (idx < 0) throw fail('invalid_input');
      database.items.splice(idx, 1);
      await unlockClear(id);
      if (database.active === id) {
        const next = [...database.items].sort((a, b) => (b.created ?? 0) - (a.created ?? 0))[0];
        database.active = next?.id ?? null;
      }
      await writeDb(database);
      return api.status();
    },
  };

  return api;
}
