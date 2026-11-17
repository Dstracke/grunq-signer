// Key store: plaintext (Stufe 1, browser standard) or NIP-49-encrypted
// (ncryptsec) with the decrypted key kept in extension session storage only.
//
// Session storage survives event-page/sleep cycles but not a browser restart,
// so an encrypted identity has to be unlocked once per browser run. The
// passphrase itself is never stored — unlock re-derives the key from the
// ncryptsec on disk.
//
// Environment is injected (local/session storage + clock) so node tests can
// drive the whole lock/unlock/auto-lock cycle without a browser.
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

export const KEY_STORE = 'grunq_signer:key'; // { privHex, created } | { ncryptsec, created }
export const IDENTITY_STORE = 'grunq_signer:identity'; // { pubkey, created }
export const SESSION_STORE = 'grunq_signer:session'; // memory only: { privHex, unlockedAt }

export const MIN_PASSWORD_LENGTH = 8;

function fail(code, message) {
  const e = new Error(message ?? code);
  e.code = code;
  // NIP-46 responses carry error strings like "error:locked".
  e.nip46Code = code;
  return e;
}

export function createKeystore(env) {
  const { local, session, now = () => Date.now(), logN = DEFAULT_LOG_N } = env;

  async function keyRecord() {
    return (await local.get(KEY_STORE)) ?? null;
  }

  async function writeIdentity(privHex) {
    await local.set(IDENTITY_STORE, { pubkey: derivePubkeyHex(privHex), created: now() });
  }

  async function openSession(privHex) {
    await session.set(SESSION_STORE, { privHex, unlockedAt: now() });
  }

  function checkPassword(password, repeat) {
    if (typeof password !== 'string' || password.length < MIN_PASSWORD_LENGTH) {
      throw fail('weak_password');
    }
    if (repeat !== undefined && password !== repeat) {
      throw fail('password_mismatch');
    }
  }

  return {
    /** { hasKey, encrypted, unlocked, created } — safe to show while locked. */
    async status() {
      const rec = await keyRecord();
      if (!rec) return { hasKey: false, encrypted: false, unlocked: false, created: null };
      const encrypted = typeof rec.ncryptsec === 'string';
      if (!encrypted) return { hasKey: true, encrypted: false, unlocked: true, created: rec.created ?? null };
      const s = await session.get(SESSION_STORE);
      return { hasKey: true, encrypted: true, unlocked: !!s?.privHex, created: rec.created ?? null };
    },

    /** Public key, available even while locked (identity record, not the key). */
    async pubkeyHex() {
      const rec = await keyRecord();
      if (!rec) return null;
      if (rec.privHex) return derivePubkeyHex(rec.privHex);
      const identity = await local.get(IDENTITY_STORE);
      if (identity?.pubkey) return identity.pubkey;
      const s = await session.get(SESSION_STORE);
      return s?.privHex ? derivePubkeyHex(s.privHex) : null;
    },

    async npub() {
      const pub = await this.pubkeyHex();
      return pub ? encodeNpub(pub) : null;
    },

    /** The signing key; throws code "locked" for an encrypted, locked store. */
    async privateKeyHex() {
      const rec = await keyRecord();
      if (!rec) throw fail('no_key');
      if (rec.privHex) return rec.privHex;
      const s = await session.get(SESSION_STORE);
      if (s?.privHex) return s.privHex;
      throw fail('locked');
    },

    /** Activity marker for auto-lock; only encrypted stores carry a session. */
    async touch() {
      const rec = await keyRecord();
      if (!rec || !rec.ncryptsec) return false;
      const s = await session.get(SESSION_STORE);
      if (!s?.privHex) return false;
      await session.set(SESSION_STORE, { ...s, unlockedAt: now() });
      return true;
    },

    async importSecret(input) {
      const privHex = parseSecretInput(String(input ?? ''));
      await local.set(KEY_STORE, { privHex, created: now() });
      await writeIdentity(privHex);
      await session.remove(SESSION_STORE);
      return { pubkey: derivePubkeyHex(privHex) };
    },

    async importNcryptsec(input, password) {
      const raw = String(input ?? '').trim().toLowerCase();
      if (!/^ncryptsec1[02-9ac-hj-np-z]+$/.test(raw)) throw fail('invalid_input');
      const out = nip49Decrypt(raw, password); // throws wrong_password
      await local.set(KEY_STORE, { ncryptsec: raw, created: now() });
      await writeIdentity(out.privHex);
      await openSession(out.privHex);
      return { pubkey: derivePubkeyHex(out.privHex) };
    },

    async generate() {
      const id = randomIdentity();
      await local.set(KEY_STORE, { privHex: id.privHex, created: now() });
      await writeIdentity(id.privHex);
      await session.remove(SESSION_STORE);
      return { pubkey: id.pubkeyHex };
    },

    /** Unlock an encrypted identity; sets the in-memory session key. */
    async unlock(password) {
      const rec = await keyRecord();
      if (!rec) throw fail('no_key');
      if (rec.privHex) return { encrypted: false, npub: encodeNpub(derivePubkeyHex(rec.privHex)) };
      if (!rec.ncryptsec) throw fail('no_key');
      let out;
      try {
        out = nip49Decrypt(rec.ncryptsec, password);
      } catch (e) {
        if (e?.code === 'wrong_password') throw fail('wrong_password');
        throw e;
      }
      await openSession(out.privHex);
      // Refresh the identity record in case it was lost (e.g. storage repair).
      await writeIdentity(out.privHex);
      return { encrypted: true, npub: encodeNpub(derivePubkeyHex(out.privHex)) };
    },

    async lock() {
      await session.remove(SESSION_STORE);
      return true;
    },

    /** Drop the in-memory key after `minutes` without activity. */
    async autoLockIfIdle(minutes) {
      const rec = await keyRecord();
      if (!rec || !rec.ncryptsec) return false;
      const s = await session.get(SESSION_STORE);
      if (!s?.privHex) return false;
      const idleMs = Math.max(1, Number(minutes) || 30) * 60 * 1000;
      if (now() - (s.unlockedAt ?? 0) < idleMs) return false;
      await session.remove(SESSION_STORE);
      return true;
    },

    /**
     * Encrypt at rest with a passphrase (first time) or re-key (change).
     * Returns the ncryptsec string so the popup can show it as a backup.
     */
    async protect(password, repeat) {
      checkPassword(password, repeat);
      const privHex = await this.privateKeyHex(); // throws locked when encrypted+locked
      const ncryptsec = nip49Encrypt(privHex, password, {
        logN,
        // The key was stored/imported unencrypted at some point, so NIP-49
        // asks us to mark it as handled insecurely (also on re-keying).
        securityByte: SECURITY_INSECURE,
      });
      const rec = await keyRecord();
      await local.set(KEY_STORE, { ncryptsec, created: rec?.created ?? now() });
      await openSession(privHex);
      return { ncryptsec };
    },

    /** Remove the passphrase protection (keeps the identity). */
    async unprotect() {
      const privHex = await this.privateKeyHex();
      const rec = await keyRecord();
      await local.set(KEY_STORE, { privHex, created: rec?.created ?? now() });
      await session.remove(SESSION_STORE);
      return true;
    },

    /** Nsec export for migration; only when unlocked and explicitly confirmed. */
    async exportNsec(confirmed) {
      if (confirmed !== true) throw fail('denied');
      const privHex = await this.privateKeyHex();
      return { nsec: encodeNsec(privHex) };
    },

    /** The stored ncryptsec (backup), or null for a plaintext store. */
    async exportNcryptsec() {
      const rec = await keyRecord();
      if (!rec?.ncryptsec) return null;
      return { ncryptsec: rec.ncryptsec };
    },

    async remove() {
      await local.remove(KEY_STORE);
      await local.remove(IDENTITY_STORE);
      await session.remove(SESSION_STORE);
      return true;
    },
  };
}
