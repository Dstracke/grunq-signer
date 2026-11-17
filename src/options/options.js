// Options page: profile, relays, site approvals (with per-kind revoke),
// bunker sessions and the audit log. Everything talks to the background over
// the same popup message channel; no key material is handled here.
import { isValidHttpUrl, profileFieldErrors } from '../signer/profile.js';
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
  for (const node of document.querySelectorAll('[data-i18n-alt]')) {
    node.alt = t(node.dataset.i18nAlt);
  }
  for (const node of document.querySelectorAll('[data-i18n-aria-label]')) {
    node.setAttribute('aria-label', t(node.dataset.i18nAriaLabel));
  }
  for (const node of document.querySelectorAll('[data-i18n-title]')) {
    node.title = t(node.dataset.i18nTitle);
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
  await Promise.all([refreshIdentities(), refreshProfile(), refreshAudit()]);
}

// ---------- identities ----------

let identities = [];

async function refreshIdentities() {
  try {
    identities = await send({ action: 'identity.list' });
  } catch {
    identities = [];
  }
  renderIdentities();
}

function renderIdentities() {
  const list = el('identities');
  list.textContent = '';
  for (const item of identities) {
    const li = document.createElement('li');
    const who = document.createElement('span');
    who.className = 'who';
    who.textContent = item.label || t('identityUnnamed');
    if (item.active) {
      const chip = document.createElement('span');
      chip.className = 'chip';
      chip.textContent = t('identityActive');
      who.append(' ', chip);
    }
    const sub = document.createElement('span');
    sub.className = 'sub mono';
    const parts = [];
    if (item.npub) parts.push(item.npub.slice(0, 20) + '…');
    if (item.encrypted) parts.push(item.unlocked ? t('secBadgeEncrypted') : t('secBadgeLocked'));
    sub.textContent = parts.join(' · ');
    li.append(who, sub);

    if (!item.active) {
      const use = document.createElement('button');
      use.textContent = t('btnActivate');
      use.addEventListener('click', async () => {
        try {
          await send({ action: 'identity.switch', id: item.id });
          await refresh();
        } catch (e) {
          showError(el('global-error'), e);
        }
      });
      li.append(use);
    }

    const remove = document.createElement('button');
    remove.className = 'danger';
    remove.textContent = t('btnRemoveIdentity');
    remove.addEventListener('click', async () => {
      if (!confirm(t('confirmRemoveIdentity', [item.label || t('identityUnnamed')]))) return;
      try {
        await send({ action: 'identity.remove', id: item.id });
        await refresh();
      } catch (e) {
        showError(el('global-error'), e);
      }
    });
    li.append(remove);
    list.append(li);
  }
  show(el('no-identities'), identities.length === 0);
}

el('btn-identity-add').addEventListener('click', () => {
  const form = el('identity-add-form');
  show(form, form.hidden);
  if (!form.hidden) {
    show(el('identity-error'), false);
    el('id-label').focus();
  }
});

el('btn-identity-cancel').addEventListener('click', () => {
  show(el('identity-add-form'), false);
  show(el('identity-error'), false);
});

el('btn-identity-save').addEventListener('click', async () => {
  show(el('identity-error'), false);
  try {
    await send({
      action: 'import',
      input: el('id-secret').value,
      passphrase: el('id-passphrase').value,
      label: el('id-label').value,
    });
    el('id-secret').value = '';
    el('id-passphrase').value = '';
    el('id-label').value = '';
    show(el('identity-add-form'), false);
    await refresh();
  } catch (e) {
    showError(el('identity-error'), e);
  }
});

el('btn-identity-generate').addEventListener('click', async () => {
  show(el('identity-error'), false);
  try {
    await send({ action: 'generate', label: el('id-label').value });
    el('id-label').value = '';
    show(el('identity-add-form'), false);
    await refresh();
  } catch (e) {
    showError(el('identity-error'), e);
  }
});

// ---------- encrypted backup ----------

function backupDownload(file) {
  const blob = new Blob([JSON.stringify(file, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  const stamp = new Date().toISOString().slice(0, 10);
  a.href = url;
  a.download = `grunq-signer-backup-${stamp}.json`;
  document.body.append(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 2000);
}

el('btn-backup-export').addEventListener('click', async () => {
  show(el('backup-error'), false);
  show(el('backup-status'), false);
  try {
    const res = await send({
      action: 'backup.export',
      password: el('backup-password').value,
      repeat: el('backup-password2').value,
    });
    backupDownload(res.file);
    el('backup-password').value = '';
    el('backup-password2').value = '';
    flash(el('backup-status'), t('backupExported', [String(res.count)]));
  } catch (e) {
    showError(el('backup-error'), e);
  }
});

el('btn-backup-import').addEventListener('click', () => {
  show(el('backup-error'), false);
  if (!el('backup-password').value) {
    showError(el('backup-error'), { message: t('backupPassphraseNeeded') });
    return;
  }
  el('backup-file').click();
});

el('backup-file').addEventListener('change', async () => {
  const file = el('backup-file').files?.[0];
  el('backup-file').value = '';
  if (!file) return;
  show(el('backup-error'), false);
  show(el('backup-status'), false);
  try {
    const text = await file.text();
    const res = await send({
      action: 'backup.import',
      text,
      password: el('backup-password').value,
    });
    el('backup-password').value = '';
    el('backup-password2').value = '';
    await refresh();
    flash(el('backup-status'), t('backupImported', [String(res.added), String(res.skipped)]));
  } catch (e) {
    showError(el('backup-error'), e);
  }
});

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
  el('pf-banner').value = fields.banner ?? '';
  el('pf-website').value = fields.website ?? '';
  el('pf-nip05').value = fields.nip05 ?? '';
  el('pf-lud16').value = fields.lud16 ?? '';
  el('pf-bot').checked = fields.bot === true;
  resetChecks();
  renderPreview();
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
    banner: el('pf-banner').value,
    website: el('pf-website').value,
    nip05: el('pf-nip05').value,
    lud16: el('pf-lud16').value,
    bot: el('pf-bot').checked,
  };
}

// ---------- profile preview ----------

let nip05Check = null;
let lud16Check = null;

function resetChecks() {
  nip05Check = null;
  lud16Check = null;
  show(el('nip05-result'), false);
  show(el('lud16-result'), false);
}

function renderPreview() {
  const fields = readProfileForm();
  const display = el('pf-display-name').value.trim();
  const name = el('pf-name').value.trim();
  el('pp-display').textContent = display || name || t('profilePreviewEmpty');
  el('pp-name').textContent = name ? `@${name}` : '';

  const avatar = el('pf-picture').value.trim();
  if (isValidHttpUrl(avatar)) {
    if (el('pp-avatar').getAttribute('src') !== avatar) el('pp-avatar').src = avatar;
    show(el('pp-avatar'), true);
  } else {
    el('pp-avatar').removeAttribute('src');
    show(el('pp-avatar'), false);
  }
  el('pp-avatar').onerror = () => {
    el('pp-avatar').removeAttribute('src');
    show(el('pp-avatar'), false);
  };

  const banner = el('pf-banner').value.trim();
  el('pp-banner').style.backgroundImage = isValidHttpUrl(banner)
    ? `url(${JSON.stringify(banner)})`
    : '';

  const about = el('pf-about').value.trim();
  el('pp-about').textContent = about.length > 200 ? about.slice(0, 200) + '…' : about;

  const website = el('pf-website').value.trim();
  if (isValidHttpUrl(website)) {
    const link = el('pp-website');
    link.href = website;
    try {
      link.textContent = new URL(website).hostname;
    } catch {
      link.textContent = website;
    }
    show(link, true);
  } else {
    show(el('pp-website'), false);
  }

  const nip05 = el('pf-nip05').value.trim();
  const nip05Chip = el('pp-nip05');
  if (nip05Check?.ok && nip05Check.verified) {
    nip05Chip.textContent = `✓ ${nip05}`;
    nip05Chip.className = 'chip ok';
    show(nip05Chip, true);
  } else if (nip05) {
    nip05Chip.textContent = nip05;
    nip05Chip.className = 'chip';
    show(nip05Chip, true);
  } else {
    show(nip05Chip, false);
  }

  const lud16 = el('pf-lud16').value.trim();
  const lud16Chip = el('pp-lud16');
  if (lud16Check?.ok) {
    lud16Chip.textContent = `⚡ ${lud16} · ${lud16Check.minSats}–${lud16Check.maxSats} sats`;
    lud16Chip.className = 'chip ok';
    show(lud16Chip, true);
  } else if (lud16) {
    lud16Chip.textContent = `⚡ ${lud16}`;
    lud16Chip.className = 'chip';
    show(lud16Chip, true);
  } else {
    show(lud16Chip, false);
  }

  show(el('pp-bot'), fields.bot === true);
}

for (const id of [
  'pf-name', 'pf-display-name', 'pf-about', 'pf-picture', 'pf-banner',
  'pf-website', 'pf-nip05', 'pf-lud16', 'pf-bot',
]) {
  el(id).addEventListener('input', () => {
    if (id === 'pf-nip05') nip05Check = null;
    if (id === 'pf-lud16') lud16Check = null;
    renderPreview();
  });
}

// ---------- NIP-05 claim for grunq.com ----------

let claimMailto = '';

el('btn-claim-nip05').addEventListener('click', async () => {
  const box = el('claim-box');
  const status = el('claim-status');
  const text = el('claim-text');
  show(box, true);
  status.className = 'hint check-result';
  const name = (el('pf-name').value || '').trim().toLowerCase();
  if (!/^[a-z0-9][a-z0-9_-]{1,29}$/.test(name)) {
    text.value = '';
    status.textContent = t('claimNameNeeded');
    status.className = 'hint check-result bad';
    return;
  }
  const address = `${name}@grunq.com`;
  status.textContent = t('checkRunning');
  try {
    const check = await send({ action: 'profile.check-nip05', address, force: true });
    if (check.ok && check.verified) {
      el('pf-nip05').value = address;
      renderPreview();
      text.value = '';
      status.textContent = t('claimAlreadyYours', [address]);
      status.className = 'hint check-result ok';
      return;
    }
    if (check.ok && check.reason === 'mismatch') {
      text.value = '';
      status.textContent = t('claimTaken', [address]);
      status.className = 'hint check-result bad';
      return;
    }
    const claim = await send({ action: 'profile.claim-nip05', name });
    claimMailto = claim.mailto;
    text.value = claim.text;
    status.textContent = t('claimReady', [address]);
    status.className = 'hint check-result ok';
  } catch (e) {
    text.value = '';
    status.textContent = e?.message ?? String(e);
    status.className = 'hint check-result bad';
  }
});

el('btn-claim-mail').addEventListener('click', () => {
  if (claimMailto) window.location.href = claimMailto;
});

el('btn-claim-copy').addEventListener('click', async () => {
  if (!el('claim-text').value) return;
  await navigator.clipboard.writeText(el('claim-text').value);
  flash(el('claim-status'), t('claimCopied'));
});

// ---------- on-demand checks ----------

el('btn-check-nip05').addEventListener('click', async () => {
  const address = el('pf-nip05').value.trim();
  const out = el('nip05-result');
  if (!address) {
    show(out, false);
    return;
  }
  out.textContent = t('checkRunning');
  out.className = 'hint check-result';
  show(out, true);
  try {
    const res = await send({ action: 'profile.check-nip05', address });
    nip05Check = res;
    if (res.ok && res.verified) {
      out.textContent = t('checkNip05Verified', [address]);
      out.className = 'hint check-result ok';
    } else if (res.ok) {
      const key =
        res.reason === 'mismatch' ? 'checkNip05Mismatch'
        : res.reason === 'npub' ? 'checkNip05Npub'
        : 'checkNip05NotFound';
      out.textContent = t(key, [address]);
      out.className = 'hint check-result bad';
    } else {
      out.textContent = t('checkFailed', [res.code ?? '?']);
      out.className = 'hint check-result bad';
    }
  } catch (e) {
    out.textContent = e?.message ?? String(e);
    out.className = 'hint check-result bad';
  }
  show(out, true);
  renderPreview();
});

el('btn-check-lud16').addEventListener('click', async () => {
  const address = el('pf-lud16').value.trim();
  const out = el('lud16-result');
  if (!address) {
    show(out, false);
    return;
  }
  out.textContent = t('checkRunning');
  out.className = 'hint check-result';
  show(out, true);
  try {
    const res = await send({ action: 'profile.check-lud16', address });
    lud16Check = res;
    if (res.ok) {
      out.textContent = res.allowsNostr
        ? t('checkLud16Ok', [String(res.minSats), String(res.maxSats)])
        : t('checkLud16NoZap', [String(res.minSats), String(res.maxSats)]);
      out.className = 'hint check-result ok';
    } else {
      out.textContent = t('checkFailed', [res.code ?? '?']);
      out.className = 'hint check-result bad';
    }
  } catch (e) {
    out.textContent = e?.message ?? String(e);
    out.className = 'hint check-result bad';
  }
  show(out, true);
  renderPreview();
});


el('btn-profile-publish').addEventListener('click', async () => {
  show(el('profile-error'), false);
  show(el('profile-status'), false);
  const fields = readProfileForm();
  const bad = profileFieldErrors(fields);
  if (bad.length) {
    showError(el('profile-error'), { message: t('errorInvalidUrl', [bad.join(', ')]) });
    return;
  }
  try {
    const res = await send({ action: 'profile.publish', fields });
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

el('btn-profile-check').addEventListener('click', async () => {
  show(el('profile-error'), false);
  show(el('profile-status'), false);
  try {
    const res = await send({ action: 'profile.check' });
    const count = Array.isArray(res.missing) ? res.missing.length : 0;
    flash(el('profile-status'), count
      ? t('profileCheckRepaired', [String(count)])
      : t('profileCheckOk'));
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

// ---------- pairing (paste or ?nostrconnect= deep link) ----------

function deepLinkUri() {
  const fromSearch = new URLSearchParams(location.search).get('nostrconnect');
  if (fromSearch) return fromSearch;
  const hash = location.hash.replace(/^#/, '');
  if (!hash) return '';
  const params = new URLSearchParams(hash);
  return params.get('nostrconnect') ?? (hash.startsWith('nostrconnect:') ? hash : '');
}

el('btn-pair').addEventListener('click', async () => {
  show(el('pair-error'), false);
  show(el('pair-status'), false);
  const uri = el('pair-uri').value.trim();
  try {
    const res = await send({ action: 'nostrconnect.pair', uri });
    await refresh();
    flash(el('pair-status'), t('pairOk', [res?.npub ?? '']));
  } catch (e) {
    showError(el('pair-error'), e);
  }
});

function prefillPairing() {
  const uri = deepLinkUri();
  if (!uri) return;
  el('pair-uri').value = uri;
  el('card-pair').classList.add('highlight');
  el('card-pair').scrollIntoView({ block: 'center' });
  el('btn-pair').focus();
}

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
  const nameCounts = new Map();
  for (const s of state.sessions) {
    if (!s.bound || !s.clientName) continue;
    nameCounts.set(s.clientName, (nameCounts.get(s.clientName) ?? 0) + 1);
  }
  for (const s of state.sessions) {
    const li = document.createElement('li');
    const who = document.createElement('span');
    who.className = 'who';
    who.textContent = s.clientName || (s.bound ? shortPub(s.clientPub) : t('sessionWaiting'));
    if (s.clientName && nameCounts.get(s.clientName) > 1) {
      const chip = document.createElement('span');
      chip.className = 'chip pending';
      chip.textContent = t('multiDeviceChip');
      chip.title = t('multiDeviceHint');
      who.append(' ', chip);
    }
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
prefillPairing();
