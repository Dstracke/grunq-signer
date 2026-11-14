// Bridge (isolated world): relays window.postMessage RPCs between the in-page
// shim and the background. Never touches keys itself.
(() => {
  const api = globalThis.browser ?? globalThis.chrome;
  if (!api?.runtime?.id) return;

  const t = (key) => api.i18n?.getMessage?.(key) || 'Internal error';

  window.addEventListener('message', (ev) => {
    if (ev.source !== window) return;
    const d = ev.data;
    if (!d || d.source !== 'grunq-signer' || d.dir !== 'page->bg') return;

    api.runtime
      .sendMessage({ type: 'nostr-rpc', id: d.id, method: d.method, params: d.params })
      .then((res) => {
        const err = res?.error
          ? { code: res.error.code, message: res.error.message }
          : { code: 'internal', message: t('errorInternal') };
        window.postMessage(
          {
            source: 'grunq-signer',
            dir: 'bg->page',
            id: d.id,
            ok: !!(res && !res.error),
            data: res && !res.error ? res : undefined,
            err: res && !res.error ? undefined : err,
          },
          '*',
        );
      })
      .catch((e) => {
        window.postMessage(
          {
            source: 'grunq-signer',
            dir: 'bg->page',
            id: d.id,
            ok: false,
            err: { code: 'extension', message: String(e?.message || e) },
          },
          '*',
        );
      });
  });
})();
