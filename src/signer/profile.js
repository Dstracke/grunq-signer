// Public profile (NIP-01 kind 0) for the extension identity: edit, publish to
// the allow-listed relays, read the latest version back and delete via NIP-09.
//
// Only public fields are handled - the profile is the one thing this
// extension intentionally publishes. No keys, chats or settings are synced.
export const PROFILE_STORE = 'grunq_signer:profile';

// Field -> maximum length (NIP-24 keys the Grunq node and the extension agree on).
export const PROFILE_FIELDS = {
  name: 64,
  display_name: 64,
  about: 2000,
  picture: 2048,
  banner: 2048,
  website: 2048,
  nip05: 254,
  lud16: 254,
};

// Fields that must be http(s) URLs; anything else is rejected, not stored.
export const PROFILE_URL_FIELDS = ['picture', 'banner', 'website'];

export function isValidHttpUrl(value) {
  if (typeof value !== 'string' || !value.trim()) return false;
  try {
    const url = new URL(value.trim());
    return url.protocol === 'http:' || url.protocol === 'https:';
  } catch {
    return false;
  }
}

/** Field keys with an invalid URL (for the editor/background to reject). */
export function profileFieldErrors(input) {
  const errors = [];
  if (!input || typeof input !== 'object') return errors;
  for (const key of PROFILE_URL_FIELDS) {
    const raw = input[key];
    if (typeof raw === 'string' && raw.trim() && !isValidHttpUrl(raw)) errors.push(key);
  }
  return errors;
}

export function sanitizeProfile(input) {
  const out = {};
  if (!input || typeof input !== 'object') return out;
  for (const [key, max] of Object.entries(PROFILE_FIELDS)) {
    const raw = input[key];
    if (typeof raw !== 'string') continue;
    const value = raw.trim();
    if (!value) continue;
    if (PROFILE_URL_FIELDS.includes(key) && !isValidHttpUrl(value)) continue;
    out[key] = value.slice(0, max);
  }
  // NIP-24 boolean flag: only store it when explicitly true.
  if (input.bot === true) out.bot = true;
  return out;
}

function fail(code, message) {
  const e = new Error(message ?? code);
  e.code = code;
  return e;
}

/**
 * Which relays still need the profile? Used by the start-up repair pull: a
 * relay that answered with a profile is left alone, every relay without one
 * gets the local profile republished. Never touches relays when the local
 * side has nothing published yet.
 */
export function planRepublish(local, perRelay) {
  if (!local || !local.publishedAt) return [];
  const fields = local.fields ?? {};
  if (Object.keys(fields).length === 0) return [];
  if (!Array.isArray(perRelay)) return [];
  return perRelay.filter((r) => r && r.relay && !r.present).map((r) => r.relay);
}

export function createProfileService(env) {
  const {
    storage, // { get(key), set(key, value) }
    transport, // { publish(relays, event), subscribe(relays, filter, onEvent) }
    now = () => Date.now(),
    log = () => {},
  } = env;

  async function read() {
    return (await storage.get(PROFILE_STORE)) ?? null;
  }

  async function write(patch) {
    const rec = (await read()) ?? {};
    const next = { ...rec, ...patch };
    await storage.set(PROFILE_STORE, next);
    return next;
  }

  return {
    /** Local state: { fields, eventId, publishedAt, updatedAt }. */
    async load() {
      const rec = await read();
      return {
        fields: rec?.fields ?? {},
        eventId: rec?.eventId ?? null,
        publishedAt: rec?.publishedAt ?? null,
        updatedAt: rec?.updatedAt ?? null,
      };
    },

    /**
     * Sign and publish the profile (kind 0) to `relays`. The fields are saved
     * locally first, so a relay failure never loses the user's edits.
     */
    async publish(fields, relays, sign) {
      const invalid = profileFieldErrors(fields);
      if (invalid.length > 0) {
        const e = fail('invalid_url');
        e.fields = invalid;
        throw e;
      }
      const clean = sanitizeProfile(fields);
      if (Object.keys(clean).length === 0) throw fail('empty_profile');
      if (!Array.isArray(relays) || relays.length === 0) throw fail('no_relays');
      await write({ fields: clean, updatedAt: now() });
      const draft = {
        kind: 0,
        created_at: Math.floor(now() / 1000),
        tags: [],
        content: JSON.stringify(clean),
      };
      const event = await sign(draft);
      await transport.publish(relays, event);
      await write({ eventId: event.id, publishedAt: now() });
      log('profile published', event.id, relays.length);
      return { fields: clean, eventId: event.id, publishedAt: now() };
    },

    /**
     * Read the newest kind 0 of `pubkey` from the relays. Resolves to the
     * sanitized fields, or null when nothing arrives within the grace period.
     * No key material is needed, so this also works while locked.
     */
    async fetchLatest(pubkey, relays, options = {}) {
      if (typeof pubkey !== 'string' || !pubkey) return null;
      if (!Array.isArray(relays) || relays.length === 0) return null;
      const graceMs = options.graceMs ?? 600;
      const timeoutMs = options.timeoutMs ?? 6000;
      return new Promise((resolve) => {
        let handle = null;
        let best = null;
        let grace = null;
        let done = false;
        const finish = (value) => {
          if (done) return;
          done = true;
          if (grace) clearTimeout(grace);
          clearTimeout(timer);
          try {
            handle?.close();
          } catch {
            /* already closed */
          }
          resolve(value);
        };
        const timer = setTimeout(() => finish(best ? parse(best) : null), timeoutMs);
        function parse(event) {
          try {
            return sanitizeProfile(JSON.parse(event.content));
          } catch {
            return null;
          }
        }
        handle = transport.subscribe(
          relays,
          { kinds: [0], authors: [pubkey], limit: 1 },
          (event) => {
            if (!event || event.kind !== 0 || event.pubkey !== pubkey) return;
            if (!best || event.created_at > best.created_at) best = event;
            if (!grace) grace = setTimeout(() => finish(best ? parse(best) : null), graceMs);
          },
        );
      });
    },

    /** NIP-09 deletion of the published profile (e + a tag), then clear local. */
    async remove(pubkey, relays, sign) {
      const rec = await read();
      if (!rec?.eventId && !rec?.publishedAt) throw fail('no_profile');
      const tags = [];
      if (rec.eventId) tags.push(['e', rec.eventId]);
      if (pubkey) tags.push(['a', `0:${pubkey}:`]);
      const event = await sign({
        kind: 5,
        created_at: Math.floor(now() / 1000),
        tags,
        content: '',
      });
      if (Array.isArray(relays) && relays.length > 0) {
        await transport.publish(relays, event);
      }
      await storage.set(PROFILE_STORE, { fields: {}, eventId: null, publishedAt: null, updatedAt: now() });
      return { eventId: event.id };
    },

    /** Draft event for tests/inspection (no signing, no publishing). */
    buildDraft(fields) {
      const clean = sanitizeProfile(fields);
      return {
        kind: 0,
        created_at: Math.floor(now() / 1000),
        tags: [],
        content: JSON.stringify(clean),
      };
    },
  };
}
