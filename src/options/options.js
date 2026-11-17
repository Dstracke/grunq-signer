// Options page: profile, relays, site approvals (with per-kind revoke),
// bunker sessions and the audit log. Everything talks to the background over
// the same popup message channel; no key material is handled here.
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

// The background answers failures as { error: { code, message } }.
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

function shortPub(pub) {
  return typeof pub === 'string' && pub.length >= 16
    ? pub.slice(0, 8) + '…' + pub.slice(-8)
    : String(pub ?? '?');
}

function flash(node, text) {
  node.textContent = text;
  show(node, true);
  setTimeout(() => show(node, false), 2500);
}

function showError(node, e) {
  node.textContent = e?.message?.replace(/^Error: /, '') || String(e);
  show(node, true);
}

// ---------- state ----------

let state = { hasKey: false, approvals: [], sessions: [], relays: [], security: {} };
let auditEntries = [];

async function refresh() {
  state = await send({ action: 'state' });
  show(el('view-missing'), !state.hasKey);
  show(el('card-profile'), state.hasKey);
  el('identity-line').textContent = state.hasKey
    ? `${state.identity?.npub ?? ''}${state.encrypted
        ? ` · ${state.unlocked ? t('secBadgeEncrypted') : t('secBadgeLocked')}`
        : ''}`
    : '';
  renderApprovals();
  renderSessions();
  renderRelays();
  await Promise.all([refreshProfile(), refreshAudit()]);
}

// ---------- profile ----------

let profileData = { fields: {}, eventId: null, publishedAt: null };

async function refreshProfile() {
  try {
    profileData = await send({ action: 'profile.get' });
  } catch {
    profileData = { fields: {}, eventId: null, publishedAt: null };
  }
  const fields = profileData.fields ?? {};
  el('pf-name').value = fields.name ?? '';
  el('pf-display-name').value = fields.display_name ?? '';
  el('pf-about').value = fields.about ?? '';
  el('pf-picture').value = fields.picture ?? '';
  el('pf-nip05').value = fields.nip05 ?? '';
  el('pf-lud16').value = fields.lud16 ?? '';
  const chip = el('profile-state');
  const published = !!profileData.publishedAt;
  chip.textContent = published ? t('profilePublishedChip') : t('profileDraftChip');
  chip.className = 'chip' + (published ? '' : ' empty');
  chip.title = published
    ? new Date(profileData.publishedAt).toLocaleString()
    : '';
}

function readProfileForm() {
  return {
    name: el('pf-name').value,
    display_name: el('pf-display-name').value,
    about: el('pf-about').value,
    picture: el('pf-picture').value,
    nip05: el('pf-nip05').value,
    lud16: el('pf-lud16').value,
  };
}

el('btn-profile-publish').addEventListener('click', async () => {
  show(el('profile-error'), false);
  show(el('profile-status'), false);
  try {
    const res = await send({ action: 'profile.publish', fields: readProfileForm() });
    await refreshProfile();
    flash(el('profile-status'), t('profilePublished', [String(res.relays?.length ?? 0)]));
  } catch (e) {
    showError(el('profile-error'), e);
  }
});

el('btn-profile-fetch').addEventListener('click', async () => {
  show(el('profile-error'), false);
  show(el('profile-status'), false);
  try {
    await send({ action: 'profile.fetch' });
    await refreshProfile();
    flash(el('profile-status'), t('profileFetched'));
  } catch (e) {
    showError(el('profile-error'), e);
  }
});

el('btn-profile-delete').addEventListener('click', async () => {
  show(el('profile-error'), false);
  show(el('profile-status'), false);
  if (!confirm(t('confirmProfileDelete'))) return;
  try {
    await send({ action: 'profile.delete' });
    await refreshProfile();
    flash(el('profile-status'), t('profileDeleted'));
  } catch (e) {
    showError(el('profile-error'), e);
  }
});

// ---------- relays ----------

function renderRelays() {
  el('relays-input').value = (state.relays ?? []).join('\n');
}

el('btn-relays-save').addEventListener('click', async () => {
  show(el('relays-error'), false);
  show(el('relays-status'), false);
  try {
    const relays = el('relays-input').value
      .split(/\r?\n/)
      .map((l) => l.trim())
      .filter(Boolean);
    const res = await send({ action: 'nip46.relays.set', relays });
    el('relays-input').value = res.relays.join('\n');
    state.relays = res.relays;
    flash(el('relays-status'), t('relaysSaved'));
  } catch (e) {
    showError(el('relays-error'), e);
  }
});

// ---------- site approvals ----------

function renderApprovals() {
  const list = el('approvals');
  list.textContent = '';
  show(el('no-approvals'), state.approvals.length === 0);
  for (const a of state.approvals) {
    const li = document.createElement('li');
    const who = document.createElement('span');
    who.className = 'who';
    who.textContent = a.origin;
    li.append(who);

    const kinds = Array.isArray(a.signKinds) ? a.signKinds : [];
    if (kinds.length) {
      const wrap = document.createElement('span');
      wrap.className = 'kinds';
      for (const kind of kinds) {
        const chip = document.createElement('span');
        chip.className = 'kind';
        chip.append(document.createTextNode(`Kind ${kind}`));
        const x = document.createElement('button');
        x.textContent = '×';
        x.title = t('revokeKindTitle', [String(kind)]);
        x.addEventListener('click', async () => {
          try {
            await send({ action: 'revoke-kind', origin: a.origin, kind });
            await refresh();
          } catch (e) {
            showError(el('global-error'), e);
          }
        });
        chip.append(x);
        wrap.append(chip);
      }
      li.append(wrap);
    } else {
      const sub = document.createElement('span');
      sub.className = 'sub';
      sub.textContent = t('permOnRequest');
      li.append(sub);
    }

    const btn = document.createElement('button');
    btn.className = 'danger';
    btn.textContent = t('btnRevokeOrigin');
    btn.addEventListener('click', async () => {
      try {
        await send({ action: 'revoke', origin: a.origin });
        await refresh();
      } catch (e) {
        showError(el('global-error'), e);
      }
    });
    li.append(btn);
    list.append(li);
  }
}

// ---------- bunker sessions ----------

function renderSessions() {
  const list = el('sessions');
  list.textContent = '';
  show(el('no-sessions'), state.sessions.length === 0);
  for (const s of state.sessions) {
    const li = document.createElement('li');
    const who = document.createElement('span');
    who.className = 'who';
    who.textContent = s.clientName || (s.bound ? shortPub(s.clientPub) : t('sessionWaiting'));
    const sub = document.createElement('span');
    sub.className = 'sub mono';
    sub.textContent = s.clientNpub
      ? s.clientNpub.slice(0, 24) + '…'
      : (s.relays ?? []).join(' ');
    li.append(who, sub);
    const btn = document.createElement('button');
    btn.className = 'danger';
    btn.textContent = t('btnRevoke');
    btn.addEventListener('click', async () => {
      try {
        await send({ action: 'nip46.revoke', id: s.id });
        await refresh();
      } catch (e) {
        showError(el('global-error'), e);
      }
    });
    li.append(btn);
    list.append(li);
  }
}

// ---------- audit log ----------

let auditFilter = '';

async function refreshAudit() {
  try {
    const list = await send({
      action: 'audit.list',
      clientPub: auditFilter.startsWith('client:') ? auditFilter.slice(7) : undefined,
      origin: auditFilter.startsWith('origin:') ? auditFilter.slice(7) : undefined,
      limit: 150,
    });
    auditEntries = Array.isArray(list) ? list : [];
  } catch {
    auditEntries = [];
  }
  renderAudit();
}

function auditSource(entry) {
  return entry.scope === 'nip07'
    ? `origin:${entry.origin}`
    : `client:${entry.clientPub}`;
}

function renderAuditFilter() {
  const select = el('audit-filter');
  const current = auditFilter;
  select.textContent = '';
  const all = document.createElement('option');
  all.value = '';
  all.textContent = t('auditAllSources');
  select.append(all);
  const seen = new Map();
  for (const entry of auditEntries) {
    const value = auditSource(entry);
    if (!value.endsWith(':') && !seen.has(value)) {
      seen.set(value, entry.scope === 'nip07'
        ? entry.origin
        : entry.clientName || shortPub(entry.clientPub));
    }
  }
  for (const [value, label] of seen) {
    const opt = document.createElement('option');
    opt.value = value;
    opt.textContent = label;
    select.append(opt);
  }
  if (current) {
    // Keep the active filter selectable even if it vanished from the page of
    // entries (it simply yields an empty table until new activity).
    if (!seen.has(current)) {
      const opt = document.createElement('option');
      opt.value = current;
      opt.textContent = current.replace(/^(client|origin):/, '');
      select.append(opt);
    }
    select.value = current;
  }
}

function renderAudit() {
  const body = el('audit-rows');
  body.textContent = '';
  show(el('audit-empty'), auditEntries.length === 0);
  for (const entry of auditEntries) {
    const tr = document.createElement('tr');
    const time = document.createElement('td');
    time.textContent = new Date(entry.ts).toLocaleString();
    const who = document.createElement('td');
    who.textContent = entry.scope === 'nip07'
      ? entry.origin || '—'
      : entry.clientName || shortPub(entry.clientPub) || '—';
    const method = document.createElement('td');
    method.textContent = entry.kind != null ? `${entry.method} · Kind ${entry.kind}` : entry.method;
    const result = document.createElement('td');
    result.className = entry.ok ? 'ok' : 'bad';
    result.textContent = entry.ok
      ? t('auditOk')
      : `${t('auditDenied')}${entry.code ? ' · ' + entry.code : ''}`;
    tr.append(time, who, method, result);
    body.append(tr);
  }
  renderAuditFilter();
}

el('audit-filter').addEventListener('change', async () => {
  auditFilter = el('audit-filter').value;
  await refreshAudit();
});

el('btn-audit-refresh').addEventListener('click', () => {
  refreshAudit().catch((e) => showError(el('global-error'), e));
});

el('btn-audit-clear').addEventListener('click', async () => {
  if (!confirm(t('confirmAuditClear'))) return;
  try {
    await send({ action: 'audit.clear' });
    await refreshAudit();
  } catch (e) {
    showError(el('global-error'), e);
  }
});

// ---------- boot ----------

initI18n();
refresh().catch((e) => showError(el('global-error'), e));
