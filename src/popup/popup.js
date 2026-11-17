// Popup: identity management (import/generate/remove/export) and site approvals.
// All labels come from _locales/<ui-lang>/messages.json (browser setting).
// The identity QR codes are rendered locally with the bundled qrcode-generator
// (MIT, see README); the bech32 strings never leave the popup.
import qrcode from '../vendor/qrcode-generator.cjs';

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

// Collapse the export panel and drop any rendered secret (called whenever the
// identity changes: import, generate, remove).
function resetExport() {
  el('nsec').textContent = '';
  el('qr-nsec').removeAttribute('src');
  el('qr-npub').removeAttribute('src');
  show(el('export-box'), false);
  show(el('nsec-locked'), true);
  show(el('nsec-confirm'), false);
  show(el('nsec-unlocked'), false);
  show(el('qr-empty'), false);
}

// The background answers failures as { error: { code, message } } (messages
// already localized there), so unwrap them into real exceptions — otherwise
// the try/catch blocks below would silently swallow e.g. an invalid key.
async function send(msg) {
  const res = await api.runtime.sendMessage({ type: 'popup', ...msg });
  if (res && typeof res === 'object' && res.error) {
    const e = new Error(res.error.message || res.error.code || 'error');
    e.code = res.error.code;
    throw e;
  }
  return res;
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
      origin.textContent = a.signKinds?.length
        ? `${a.origin} · ${t('permSignKinds', [a.signKinds.join(', ')])}`
        : a.origin;
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
    resetExport();
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
    resetExport();
    await refresh();
  } catch (e) {
    errEl.textContent = e?.message?.replace(/^Error: /, '') || String(e);
    show(errEl, true);
  }
});

el('btn-copy').addEventListener('click', async () => {
  await copyKey(el('npub').textContent, el('btn-copy'), 'btnCopy');
});

// ---------- identity export (npub/nsec QR) ----------

function qrDataUrl(text) {
  try {
    const qr = qrcode(0, 'M'); // typeNumber 0 = pick automatically
    qr.addData(String(text));
    qr.make();
    return qr.createDataURL(6, 2);
  } catch {
    return '';
  }
}

function showQr(imgId, text) {
  const img = el(imgId);
  const url = qrDataUrl(text);
  if (url) {
    img.src = url;
    show(img, true);
  } else {
    img.removeAttribute('src');
    show(img, false);
    show(el('qr-empty'), true);
  }
}

// Wipe every trace of the secret from the popup DOM. The nsec is only
// fetched on demand and dropped as soon as the panel closes.
function lockNsec() {
  el('nsec').textContent = '';
  el('qr-nsec').removeAttribute('src');
  show(el('nsec-confirm'), false);
  show(el('nsec-unlocked'), false);
  show(el('nsec-locked'), true);
}

async function copyKey(text, button, labelKey) {
  await navigator.clipboard.writeText(text);
  button.textContent = t('btnCopied');
  setTimeout(() => (button.textContent = t(labelKey)), 1500);
}

el('btn-qr').addEventListener('click', async () => {
  const box = el('export-box');
  if (!box.hidden) {
    lockNsec();
    show(box, false);
    return;
  }
  lockNsec();
  show(el('qr-empty'), false);
  showQr('qr-npub', el('npub').textContent);
  show(box, true);
});

el('btn-nsec-show').addEventListener('click', () => {
  show(el('nsec-locked'), false);
  show(el('nsec-confirm'), true);
});

el('btn-nsec-cancel').addEventListener('click', lockNsec);

el('btn-nsec-confirm').addEventListener('click', async () => {
  const errEl = el('export-error');
  errEl.hidden = true;
  try {
    const { nsec } = await send({ action: 'export', what: 'nsec', confirm: true });
    el('nsec').textContent = nsec;
    show(el('nsec-locked'), false);
    show(el('nsec-confirm'), false);
    show(el('nsec-unlocked'), true);
    showQr('qr-nsec', nsec);
  } catch (e) {
    errEl.textContent = e?.message?.replace(/^Error: /, '') || String(e);
    show(errEl, true);
    lockNsec();
  }
});

el('btn-nsec-hide').addEventListener('click', lockNsec);

el('btn-nsec-copy').addEventListener('click', async () => {
  const value = el('nsec').textContent;
  if (!value) return;
  await copyKey(value, el('btn-nsec-copy'), 'btnCopyNsec');
});

el('btn-remove').addEventListener('click', async () => {
  if (!confirm(t('confirmRemove'))) return;
  await send({ action: 'remove' });
  resetExport();
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
refresh().catch((e) => console.log('[popup] refresh failed', e));
