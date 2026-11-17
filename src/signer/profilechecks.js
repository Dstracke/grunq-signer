// On-demand verification of the two human-readable profile fields:
//   - lud16 ("name@wallet"): resolve the LNURL-pay endpoint and report what
//     the wallet says (amount range, description, zap support).
//   - nip05 ("name@domain"): fetch /.well-known/nostr.json and compare the
//     published key with our own public key (lowercase hex only, per NIP-05).
//
// Both only run when the user presses "check", never in the background. The
// network helpers in lib/net.js restrict requests to https and public hosts.
import { fetchJson } from '../lib/net.js';

const ADDRESS_RE = /^[^@\s]+@[^@\s]+\.[^@\s]+$/;
const HEX64_RE = /^[0-9a-f]{64}$/;

export function parseAddress(raw) {
  const value = String(raw ?? '').trim();
  if (!ADDRESS_RE.test(value)) return null;
  const at = value.lastIndexOf('@');
  const name = value.slice(0, at).trim();
  const domain = value.slice(at + 1).trim().toLowerCase();
  if (!name || !domain) return null;
  return { name, domain };
}

function metadataDescription(metadata) {
  // LNURL metadata is a JSON array string: [["text/plain","..."], ...]
  try {
    const entries = JSON.parse(String(metadata ?? '[]'));
    const plain = entries.find((e) => Array.isArray(e) && e[0] === 'text/plain');
    return typeof plain?.[1] === 'string' ? plain[1].slice(0, 200) : '';
  } catch {
    return '';
  }
}

function sats(msat) {
  const value = Number(msat);
  if (!Number.isFinite(value) || value <= 0) return 0;
  return Math.round(value / 1000);
}

export function createProfileChecks(env = {}) {
  const {
    fetchImpl = (...args) => fetch(...args),
    now = () => Date.now(),
    timeoutMs = 10_000,
    maxBytes = 64 * 1024,
    nip05TtlMs = 10 * 60 * 1000,
  } = env;

  /** @type {Map<string, {at:number, result:object}>} */
  const nip05Cache = new Map();

  async function getJson(url, options = {}) {
    return fetchJson(url, {
      fetchImpl,
      timeoutMs: options.timeoutMs ?? timeoutMs,
      maxBytes: options.maxBytes ?? maxBytes,
    });
  }

  return {
    /** Resolve a lightning address; never throws. */
    async checkLud16(raw) {
      const parsed = parseAddress(raw);
      if (!parsed) return { ok: false, code: 'invalid_address' };
      const url = `https://${parsed.domain}/.well-known/lnurlp/${encodeURIComponent(parsed.name)}`;
      let data;
      try {
        data = await getJson(url);
      } catch (e) {
        return { ok: false, code: e?.code ?? 'network' };
      }
      if (!data || data.tag !== 'payRequest') return { ok: false, code: 'not_lnurl' };
      if (typeof data.callback !== 'string') return { ok: false, code: 'not_lnurl' };
      return {
        ok: true,
        domain: parsed.domain,
        name: parsed.name,
        minSats: sats(data.minSendable),
        maxSats: sats(data.maxSendable),
        description: metadataDescription(data.metadata),
        allowsNostr: data.allowsNostr === true,
      };
    },

    /**
     * Check a NIP-05 address against a public key. Results (including
     * failures) are cached for a few minutes; `force` bypasses the cache.
     */
    async checkNip05(raw, pubkey, options = {}) {
      const parsed = parseAddress(raw);
      const key = String(pubkey ?? '').toLowerCase();
      if (!parsed) return { ok: false, code: 'invalid_address' };
      if (!HEX64_RE.test(key)) return { ok: false, code: 'invalid_pubkey' };

      const cacheKey = `${parsed.name}@${parsed.domain}|${key}`;
      const cached = nip05Cache.get(cacheKey);
      if (!options.force && cached && now() - cached.at < nip05TtlMs) return cached.result;

      const url = `https://${parsed.domain}/.well-known/nostr.json?name=${encodeURIComponent(parsed.name)}`;
      let result;
      try {
        const data = await getJson(url, { timeoutMs: 8000, maxBytes: 32 * 1024 });
        const published = data?.names?.[parsed.name];
        if (typeof published !== 'string') result = { ok: true, verified: false, reason: 'not_found' };
        else if (published.startsWith('npub1')) result = { ok: true, verified: false, reason: 'npub' };
        else if (published.toLowerCase() !== key) result = { ok: true, verified: false, reason: 'mismatch' };
        else result = { ok: true, verified: true, domain: parsed.domain };
      } catch (e) {
        result = { ok: false, code: e?.code ?? 'network' };
      }
      nip05Cache.set(cacheKey, { at: now(), result });
      return result;
    },

    clearCache() {
      nip05Cache.clear();
    },
  };
}
