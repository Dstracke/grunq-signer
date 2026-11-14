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
    // prefill the relays editor once
    if (!el('relays-input').value.trim()) {
      el('relays-input').value = state.relays.join('\n');
    }
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

    // bunker (NIP-46) sessions
    const sessions = el('sessions');
    sessions.textContent = '';
    show(el('no-sessions'), state.sessions.length === 0);
    for (const s of state.sessions) {
      const li = document.createElement('li');
      const label = document.createElement('span');
      label.className = 'origin';
      label.textContent = s.clientName || (s.bound ? shortPub(s.clientPub) : t('sessionWaiting'));
      const btn = document.createElement('button');
      btn.className = 'danger';
      btn.textContent = t('btnRevoke');
      btn.addEventListener('click', async () => {
        await send({ action: 'nip46.revoke', id: s.id });
        await refresh();
      });
      li.append(label, btn);
      sessions.append(li);
    }
  }
}

function shortPub(pub) {
  return typeof pub === 'string' && pub.length >= 16
    ? pub.slice(0, 8) + '…' + pub.slice(-8)
    : String(pub ?? '?');
}

function tOr(message, key) {
  // map raw signer-core error codes to localized strings
  if (message === 'session_limit') return t('nip46ErrorSessionLimit');
  if (message === 'no_relays') return t('nip46ErrorNoRelays');
  return message;
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

el('btn-invite').addEventListener('click', async () => {
  const errEl = el('invite-error');
  errEl.hidden = true;
  try {
    const invite = await send({ action: 'nip46.invite' });
    el('invite-uri').value = invite.uri;
    show(el('invite-box'), true);
  } catch (e) {
    errEl.textContent = tOr(e?.message?.replace(/^Error: /, ''), '');
    show(errEl, true);
  }
});

el('btn-invite-copy').addEventListener('click', async () => {
  await navigator.clipboard.writeText(el('invite-uri').value);
  el('btn-invite-copy').textContent = t('btnCopied');
  setTimeout(() => (el('btn-invite-copy').textContent = t('btnCopyUri')), 1500);
});

el('btn-relays-save').addEventListener('click', async () => {
  const status = el('relays-status');
  try {
    const relays = el('relays-input').value
      .split(/\r?\n/)
      .map((l) => l.trim())
      .filter(Boolean);
    const res = await send({ action: 'nip46.relays.set', relays });
    el('relays-input').value = res.relays.join('\n');
    status.textContent = t('relaysSaved');
    show(status, true);
    setTimeout(() => show(status, false), 2000);
  } catch (e) {
    status.textContent = tOr(e?.message?.replace(/^Error: /, ''), '');
    show(status, true);
  }
});

initI18n();
refresh();
