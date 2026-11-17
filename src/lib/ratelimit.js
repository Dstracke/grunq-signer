// Small sliding-window rate limiter for pairing/connection attempts.
// In-memory only (per background instance): the goal is to stop a page or a
// relay client from spamming approval windows, not to persist abuse data.
export function createRateLimiter(options = {}) {
  const {
    limit = 5,
    windowMs = 10 * 60 * 1000,
    now = () => Date.now(),
  } = options;

  /** @type {Map<string, number[]>} */
  const hits = new Map();

  function fresh(key) {
    const cutoff = now() - windowMs;
    const list = (hits.get(key) ?? []).filter((ts) => ts > cutoff);
    if (list.length) hits.set(key, list);
    else hits.delete(key);
    return list;
  }

  return {
    /** True while `key` reached the limit inside the window. */
    isBlocked(key) {
      return fresh(key).length >= limit;
    },

    /** Count one failed attempt; returns true when the key is now blocked. */
    fail(key) {
      const list = fresh(key);
      list.push(now());
      hits.set(key, list);
      return list.length >= limit;
    },

    reset(key) {
      hits.delete(key);
    },

    clear() {
      hits.clear();
    },

    /** Seconds until the oldest counted attempt leaves the window. */
    retryAfterSeconds(key) {
      const list = fresh(key);
      if (list.length < limit) return 0;
      return Math.max(1, Math.ceil((list[0] + windowMs - now()) / 1000));
    },
  };
}
