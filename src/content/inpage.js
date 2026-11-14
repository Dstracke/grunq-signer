// In-page NIP-07 shim (MAIN world). Forwards calls via window.postMessage to the
// bridge (isolated world), which relays to the background. All permission checks
// happen in the background - the page can never be trusted. This context has no
// extension APIs, so the few strings here stay English.
(() => {
  if (window.__grunqSignerInjected) return;
  window.__grunqSignerInjected = true;

  let seq = 0;
  /** @type {Map<string, {resolve: Function, reject: Function}>} */
  const pending = new Map();

  window.addEventListener('message', (ev) => {
    if (ev.source !== window) return;
    const d = ev.data;
    if (!d || d.source !== 'grunq-signer' || d.dir !== 'bg->page') return;
    const p = pending.get(d.id);
    if (!p) return;
    pending.delete(d.id);
    if (d.ok) p.resolve(d.data);
    else p.reject(Object.assign(new Error(d.err?.message || 'Unknown error'), { code: d.err?.code }));
  });

  function call(method, params) {
    return new Promise((resolve, reject) => {
      const id = 'gq' + ++seq + '.' + Date.now().toString(36);
      pending.set(id, { resolve, reject });
      window.postMessage({ source: 'grunq-signer', dir: 'page->bg', id, method, params }, '*');
      setTimeout(() => {
        if (pending.has(id)) {
          pending.delete(id);
          reject(Object.assign(new Error('Timed out waiting for the signer extension'), { code: 'timeout' }));
        }
      }, 60000);
    });
  }

  const nostr = Object.freeze({
    getPublicKey: () => call('getPublicKey'),
    getRelays: () => call('getRelays'),
    signEvent: (event) => call('signEvent', { event }),
    nip04: Object.freeze({
      encrypt: (pubkey, text) => call('nip04.encrypt', { pubkey, text }),
      decrypt: (pubkey, payload) => call('nip04.decrypt', { pubkey, payload }),
    }),
    nip44: Object.freeze({
      encrypt: (pubkey, text) => call('nip44.encrypt', { pubkey, text }),
      decrypt: (pubkey, payload) => call('nip44.decrypt', { pubkey, payload }),
    }),
  });

  // Non-writable so the page cannot swap the object out from under callers.
  try {
    Object.defineProperty(window, 'nostr', { value: nostr, configurable: false, writable: false });
  } catch {
    window.nostr = nostr;
  }
})();
