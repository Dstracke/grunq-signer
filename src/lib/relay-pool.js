// Minimal Nostr relay client over plain WebSocket (the transport both the
// background and the node tests use). Speaks the NIP-01 JSON protocol:
// ["REQ", sub, filter] / ["EVENT", event] / ["CLOSE", sub]; handles
// ["EVENT", sub, event], ["OK", id, ...] and ["NOTICE", msg].
//
// Reconnects per relay with a small backoff so a dead relay never takes
// the pool down. Relays are ws:// or wss:// URLs (https:// is upgraded).
const WS_RE = /^(wss?|https?):\/\//i;

export function normalizeRelayUrl(raw) {
  let url = String(raw ?? '').trim();
  if (!url) return null;
  if (!WS_RE.test(url)) return null;
  if (/^https:\/\//i.test(url)) url = 'wss://' + url.slice(8);
  else if (/^http:\/\//i.test(url)) url = 'ws://' + url.slice(7);
  try {
    const parsed = new URL(url);
    if (parsed.protocol !== 'ws:' && parsed.protocol !== 'wss:') return null;
    // drop default ports to dedupe wss://x and wss://x:443
    if ((parsed.protocol === 'wss:' && parsed.port === '443') ||
        (parsed.protocol === 'ws:' && parsed.port === '80')) {
      parsed.port = '';
    }
    parsed.hash = '';
    return parsed.toString().replace(/\/$/, '');
  } catch {
    return null;
  }
}

export function normalizeRelayList(list) {
  if (!Array.isArray(list)) return [];
  const seen = new Set();
  const out = [];
  for (const item of list) {
    const url = normalizeRelayUrl(item);
    if (url && !seen.has(url)) {
      seen.add(url);
      out.push(url);
    }
  }
  return out;
}

class RelayConn {
  constructor(url, handlers) {
    this.url = url;
    this.handlers = handlers; // { onEvent(event), onOpen() }
    this.ws = null;
    this.backoff = 1000;
    this.closed = false;
    // Messages handed over while the socket is CONNECTING or mid-reconnect;
    // flush() delivers them on open. Without this queue a publish issued
    // right after a reconnect (e.g. nostrconnect pairing) would bounce.
    this.outbox = [];
    this.connect();
  }

  connect() {
    if (this.closed) return;
    try {
      const ws = new WebSocket(this.url);
      this.ws = ws;
      ws.onopen = () => {
        this.backoff = 1000;
        this.flush();
        this.handlers.onOpen?.(this);
      };
      ws.onmessage = (ev) => {
        if (typeof ev.data !== 'string') return;
        let msg;
        try {
          msg = JSON.parse(ev.data);
        } catch {
          return;
        }
        this.handlers.onMessage?.(this, msg);
      };
      ws.onclose = () => {
        this.ws = null;
        if (!this.closed) this.scheduleReconnect();
      };
      ws.onerror = () => {
        try { ws.close(); } catch { /* ignore */ }
      };
    } catch {
      this.scheduleReconnect();
    }
  }

  flush() {
    while (this.outbox.length && this.ws && this.ws.readyState === WebSocket.OPEN) {
      const msg = this.outbox.shift();
      try {
        this.ws.send(JSON.stringify(msg));
      } catch {
        break;
      }
    }
  }

  scheduleReconnect() {
    if (this.closed) return;
    const delay = this.backoff;
    this.backoff = Math.min(this.backoff * 2, 30000);
    setTimeout(() => this.connect(), delay);
  }

  send(msg) {
    if (this.closed) return false;
    if (this.ws && this.ws.readyState === WebSocket.OPEN) {
      try {
        this.ws.send(JSON.stringify(msg));
        return true;
      } catch {
        /* fall through to the queue */
      }
    }
    // CONNECTING or reconnecting: queue; flush() delivers on open.
    if (this.outbox.length >= 16) this.outbox.shift();
    this.outbox.push(msg);
    return true;
  }

  close() {
    this.closed = true;
    if (this.ws) {
      try { this.ws.close(); } catch { /* ignore */ }
      this.ws = null;
    }
  }
}

export class RelayPool {
  constructor() {
    /** @type {Map<string, RelayConn>} */
    this.conns = new Map();
    /** @type {Map<string, {filter: object, onEvent: Function, seen: Set<string>}>} */
    this.subs = new Map();
    this.subSeq = 0;
    this.publishTimeoutMs = 8000;
  }

  conn(url) {
    let conn = this.conns.get(url);
    if (!conn) {
      conn = new RelayConn(url, {
        onOpen: (c) => {
          // re-issue active subscriptions on (re)connect
          for (const [subId, sub] of this.subs) {
            const req = ['REQ', subId, sub.filter];
            // sub relays are tracked per-subscription below
            if (sub.relays?.includes(c.url)) c.send(req);
          }
        },
        onMessage: (c, msg) => this.onMessage(c, msg),
      });
      this.conns.set(url, conn);
    }
    return conn;
  }

  onMessage(conn, msg) {
    if (!Array.isArray(msg) || msg.length < 2) return;
    const [type] = msg;
    if (type === 'OK') {
      conn.okHandler?.(conn, msg);
      return;
    }
    if (type === 'EVENT') {
      const [, subId, event] = msg;
      const sub = this.subs.get(subId);
      if (!sub || !event || typeof event !== 'object') return;
      if (sub.seen.has(event.id)) return;
      sub.seen.add(event.id);
      // keep the dedupe set bounded
      if (sub.seen.size > 500) sub.seen.clear();
      sub.onEvent(event);
    }
    // OK/NOTICE/CLOSE need no action here; publish() tracks OK itself.
  }

  subscribe(relays, filter, onEvent) {
    const urls = normalizeRelayList(relays);
    this.subSeq += 1;
    const subId = 'grunq-' + this.subSeq;
    const sub = { filter, onEvent, seen: new Set(), relays: urls };
    this.subs.set(subId, sub);
    for (const url of urls) {
      const conn = this.conn(url);
      if (!conn.send(['REQ', subId, filter])) {
        // onOpen re-subscribes once the socket is up
      }
    }
    return {
      close: () => {
        for (const url of urls) {
          const conn = this.conns.get(url);
          if (conn) conn.send(['CLOSE', subId]);
        }
        this.subs.delete(subId);
      },
    };
  }

  /** Publish to all relays; resolves once any relay accepts (OK true). */
  publish(relays, event, timeoutMs = this.publishTimeoutMs) {
    const urls = normalizeRelayList(relays);
    if (urls.length === 0) return Promise.reject(new Error('no relays configured'));
    return new Promise((resolve, reject) => {
      let pending = urls.length;
      let done = false;
      const timer = setTimeout(() => {
        if (!done) {
          done = true;
          reject(new Error('no relay accepted the event'));
        }
      }, timeoutMs);
      for (const url of urls) {
        const conn = this.conn(url);
        const sent = conn.send(['EVENT', event]);
        if (!sent) {
          // Socket not open yet: this publish may miss; count it as failed.
          pending -= 1;
          if (pending <= 0 && !done) {
            done = true;
            clearTimeout(timer);
            reject(new Error('relay sockets not connected'));
          }
          continue;
        }
        const onOk = (c, msg) => {
          if (!Array.isArray(msg) || msg[0] !== 'OK' || msg[1] !== event.id) return;
          c.okHandler = null;
          if (done) return;
          if (msg[2] === true) {
            done = true;
            clearTimeout(timer);
            resolve();
          } else {
            pending -= 1;
            if (pending <= 0 && !done) {
              done = true;
              clearTimeout(timer);
              reject(new Error('all relays rejected: ' + (msg[3] ?? '')));
            }
          }
        };
        conn.okHandler = onOk;
      }
    });
  }

  close() {
    for (const conn of this.conns.values()) conn.close();
    this.conns.clear();
    this.subs.clear();
  }
}
