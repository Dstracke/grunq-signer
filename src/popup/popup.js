// Popup: identity management (import/generate/remove) and site approvals.
// All labels come from _locales/<ui-lang>/messages.json (browser setting).
const api = globalThis.browser ?? globalThis.chrome;

const el = (id) => document.getElementById(id);

const t = (key, subs) => api.i18n.getMessage(key, subs) || key;

function initI18n() {
  for (const node of document.querySelectorAll('[data-i18n]')) {
    node.textContent = t(node.dataset.i18n);
  }
  for (const node of document.querySelectorAll('[data-i18n-placeholder]')) {
    node.placeholder = t(node.dataset.i18nPlaceholder);
  }
}

function send(msg) {
  return api.runtime.sendMessage({ type: 'popup', ...msg });
}

function show(node, on) {
  node.hidden = !on;
}

async function refresh() {
  const state = await send({ action: 'state' });
  show(el('view-import'), !state.hasKey);
  show(el('view-identity'), state.hasKey);
  if (state.hasKey) {
    el('npub').textContent = state.identity.npub;
    const pub = state.identity.pubkey;
    el('pubkey-short').textContent = pub.slice(0, 16) + '…' + pub.slice(-12);
    const list = el('approvals');
    list.textContent = '';
    show(el('no-approvals'), state.approvals.length === 0);
    for (const a of state.approvals) {
      const li = document.createElement('li');
      const origin = document.createElement('span');
      origin.className = 'origin';
      origin.textContent = a.origin;
      const btn = document.createElement('button');
      btn.className = 'danger';
      btn.textContent = t('btnRevoke');
      btn.addEventListener('click', async () => {
        await send({ action: 'revoke', origin: a.origin });
        await refresh();
      });
      li.append(origin, btn);
      list.append(li);
    }
  }
}

el('btn-import').addEventListener('click', async () => {
  const errEl = el('import-error');
  errEl.hidden = true;
  try {
    await send({ action: 'import', input: el('key-input').value });
    el('key-input').value = '';
    await refresh();
  } catch (e) {
    errEl.textContent = e?.message?.replace(/^Error: /, '') || String(e);
    show(errEl, true);
  }
});

el('btn-generate').addEventListener('click', async () => {
  const errEl = el('import-error');
  errEl.hidden = true;
  try {
    await send({ action: 'generate' });
    await refresh();
  } catch (e) {
    errEl.textContent = e?.message?.replace(/^Error: /, '') || String(e);
    show(errEl, true);
  }
});

el('btn-copy').addEventListener('click', async () => {
  await navigator.clipboard.writeText(el('npub').textContent);
  el('btn-copy').textContent = t('btnCopied');
  setTimeout(() => (el('btn-copy').textContent = t('btnCopy')), 1500);
});

el('btn-remove').addEventListener('click', async () => {
  if (!confirm(t('confirmRemove'))) return;
  await send({ action: 'remove' });
  await refresh();
});

initI18n();
refresh();
