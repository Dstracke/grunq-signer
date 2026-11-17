// Network helpers for the on-demand profile checks (NIP-05, lud16).
//
// These requests are user-initiated (a "check" button) and only ever go to the
// domain the user typed. The guards below keep them from being abused as a
// localhost/intranet probe: only https, no redirects, private hostnames are
// rejected, responses are size- and time-limited. (A browser cannot resolve
// DNS itself, so a public name that points at a private IP is out of reach for
// this check — the request is still the user's own click.)

const PRIVATE_V4 = [
  [/^10\./, '10/8'],
  [/^127\./, '127/8'],
  [/^0\./, '0/8'],
  [/^169\.254\./, '169.254/16'],
  [/^172\.(1[6-9]|2\d|3[01])\./, '172.16/12'],
  [/^192\.168\./, '192.168/16'],
  [/^192\.0\.2\./, '192.0.2/24'],
  [/^198\.51\.100\./, '198.51.100/24'],
  [/^203\.0\.113\./, '203.0.113/24'],
  [/^100\.(6[4-9]|[7-9]\d|1[0-1]\d|12[0-7])\./, '100.64/10'],
  [/^198\.1[89]\./, '198.18/15'],
];

export function isBlockedHost(hostname) {
  const host = String(hostname ?? '').trim().toLowerCase().replace(/^\[|\]$/g, '');
  if (!host) return true;
  if (host === 'localhost' || host.endsWith('.localhost')) return true;
  if (host.endsWith('.local') || host.endsWith('.internal') || host.endsWith('.home.arpa')) return true;
  // IPv6 special ranges
  if (host === '::1' || host === '::') return true;
  if (/^f[cd][0-9a-f]{2}:/.test(host)) return true; // ULA fc00::/7
  if (/^fe[89ab][0-9a-f]:/.test(host)) return true; // link-local fe80::/10
  const mapped = host.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/);
  if (mapped) return isBlockedHost(mapped[1]);
  // IPv4 literals in private ranges (anything that looks like an IPv4)
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host)) {
    const parts = host.split('.').map(Number);
    if (parts.some((p) => p < 0 || p > 255)) return true;
    if (parts[0] >= 224) return true; // multicast/reserved
    if (PRIVATE_V4.some(([re]) => re.test(host))) return true;
    return false;
  }
  // Single-label hostnames (intranet names)
  if (!host.includes('.')) return true;
  return false;
}

/** https URL or null; never http, never credentials, never private hosts. */
export function requireHttpsUrl(raw) {
  let url;
  try {
    url = new URL(String(raw ?? '').trim());
  } catch {
    return null;
  }
  if (url.protocol !== 'https:') return null;
  if (url.username || url.password) return null;
  if (isBlockedHost(url.hostname)) return null;
  return url;
}

/**
 * Fetch JSON with a hard timeout and response-size cap. Never follows
 * redirects. Throws errors with codes: blocked, network, too_large, invalid.
 */
export async function fetchJson(rawUrl, options = {}) {
  const url = requireHttpsUrl(rawUrl);
  if (!url) {
    const e = new Error('blocked or non-https URL');
    e.code = 'blocked';
    throw e;
  }
  const {
    timeoutMs = 10_000,
    maxBytes = 64 * 1024,
    fetchImpl = (...args) => fetch(...args),
  } = options;

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetchImpl(url.toString(), {
      method: 'GET',
      redirect: 'error',
      credentials: 'omit',
      referrerPolicy: 'no-referrer',
      headers: { accept: 'application/json' },
      signal: controller.signal,
    });
    if (!res || !res.ok) {
      const e = new Error(`http ${res?.status ?? 'error'}`);
      e.code = 'network';
      throw e;
    }
    const declared = Number(res.headers?.get?.('content-length') ?? 0);
    if (declared > maxBytes) {
      const e = new Error('response too large');
      e.code = 'too_large';
      throw e;
    }
    const text = await res.text();
    if (text.length > maxBytes) {
      const e = new Error('response too large');
      e.code = 'too_large';
      throw e;
    }
    try {
      return JSON.parse(text);
    } catch {
      const e = new Error('response is not JSON');
      e.code = 'invalid';
      throw e;
    }
  } catch (err) {
    if (err?.name === 'AbortError') {
      const e = new Error('timeout');
      e.code = 'network';
      throw e;
    }
    throw err;
  } finally {
    clearTimeout(timer);
  }
}
