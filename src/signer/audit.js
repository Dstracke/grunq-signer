// Audit log: the last requests the extension answered, so the user can see
// what a connected client (or a site) actually did. Kept in storage.local,
// bounded, newest first. Records contain no plaintext and no keys - method,
// kind, client/origin and the outcome only.
export const AUDIT_STORE = 'grunq_signer:audit';

export const AUDIT_LIMIT = 300; // total entries on disk
export const AUDIT_PER_SESSION = 50; // entries shown per client

export function createAuditLog(env) {
  const { storage, now = () => Date.now(), limit = AUDIT_LIMIT } = env;

  async function read() {
    const list = await storage.get(AUDIT_STORE);
    return Array.isArray(list) ? list : [];
  }

  return {
    /**
     * Append one entry. `entry` is normally
     * { scope: 'nip46'|'nip07', method, ok, code?, kind?, clientPub?,
     *   clientName?, origin? }.
     */
    async record(entry) {
      if (!entry || typeof entry.method !== 'string') return null;
      const list = await read();
      const rec = {
        ts: entry.ts ?? now(),
        scope: entry.scope === 'nip07' ? 'nip07' : 'nip46',
        method: entry.method.slice(0, 40),
        ok: entry.ok !== false,
        code: entry.code ? String(entry.code).slice(0, 40) : '',
        kind: Number.isInteger(entry.kind) ? entry.kind : null,
        clientPub: typeof entry.clientPub === 'string' ? entry.clientPub : '',
        clientName: typeof entry.clientName === 'string' ? entry.clientName.slice(0, 64) : '',
        origin: typeof entry.origin === 'string' ? entry.origin.slice(0, 200) : '',
      };
      list.push(rec);
      // Drop the oldest entries beyond the cap (append-only list, no reordering
      // needed; the UI sorts newest first).
      const trimmed = list.length > limit ? list.slice(list.length - limit) : list;
      await storage.set(AUDIT_STORE, trimmed);
      return rec;
    },

    /**
     * Newest-first entries. `clientPub` narrows to one NIP-46 client,
     * `origin` to one site; `perSession` caps the result (default 50).
     */
    async list(options = {}) {
      const list = await read();
      let out = list;
      if (options.clientPub) out = out.filter((e) => e.clientPub === options.clientPub);
      if (options.origin) out = out.filter((e) => e.origin === options.origin);
      out = out.slice().reverse();
      const cap = options.perSession ?? (options.clientPub ? AUDIT_PER_SESSION : undefined);
      return cap ? out.slice(0, cap) : out;
    },

    async clear() {
      await storage.set(AUDIT_STORE, []);
      return true;
    },
  };
}
