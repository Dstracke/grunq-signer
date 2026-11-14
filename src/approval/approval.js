// Approval dialog: shows what is being requested and forwards the decision.
// The requestId comes from the location hash; the background only accepts it
// while a matching pending request exists (prevents forged decisions).
// Labels come from _locales/<ui-lang>/messages.json (browser setting).
const api = globalThis.browser ?? globalThis.chrome;

const t = (key, subs) => api.i18n.getMessage(key, subs) || key;

const requestId = decodeURIComponent(location.hash.slice(1));

function send(msg) {
  return api.runtime.sendMessage({ type: 'approval-page', ...msg });
}

function initI18n() {
  for (const node of document.querySelectorAll('[data-i18n]')) {
    node.textContent = t(node.dataset.i18n);
  }
}

function eventPreview(ev, origin, metaKey = 'eventMeta') {
  const head = document.createElement('div');
  head.className = 'event-meta';
  head.textContent = t(metaKey, [
    origin,
    String(ev.kind ?? '?'),
    new Date((ev.created_at ?? 0) * 1000).toLocaleString(undefined, {
      dateStyle: 'medium',
      timeStyle: 'medium',
    }),
    String(Array.isArray(ev.tags) ? ev.tags.length : 0),
  ]);
  const content = document.createElement('div');
  content.className = 'event-content';
  content.textContent = String(ev.content ?? '').length > 400
    ? String(ev.content).slice(0, 400) + ' …'
    : String(ev.content ?? '');
  return [head, content];
}

async function init() {
  const info = await send({ action: 'info', requestId });
  const content = document.getElementById('content');
  if (!info) {
    document.getElementById('title').textContent = t('titleStale');
    content.textContent = t('staleText');
    return;
  }
  document.getElementById('title').textContent =
    info.kind === 'nip07-access' ? t('titleAccess')
    : info.kind === 'sign-event' ? t('titleSign')
    : info.kind === 'nip46-sign' ? t('titleNip46Sign')
    : t('titleLoading');
  content.textContent = '';

  if (info.kind === 'nip07-access') {
    content.textContent = t('accessIntro', [info.origin]);
    document.getElementById('btn-always').hidden = false;
  } else if (info.kind === 'sign-event') {
    content.textContent = t('signIntro', [info.origin]) + '\n\n';
    content.append(...eventPreview(info.event ?? {}, info.origin));
    document.getElementById('btn-allow').textContent = t('btnSign');
    document.getElementById('btn-always').hidden = true;
  } else if (info.kind === 'nip46-sign') {
    const clientLabel = info.clientName || shortPub(info.clientPub);
    content.textContent = t('nip46SignIntro', [clientLabel]) + '\n\n';
    content.append(...eventPreview(info.event ?? {}, clientLabel, 'eventMetaNip46'));
    document.getElementById('btn-allow').textContent = t('btnSign');
    document.getElementById('btn-always').hidden = true;
  } else {
    content.textContent = JSON.stringify(info, null, 2);
  }
  document.getElementById('actions').hidden = false;
}

function shortPub(pub) {
  return typeof pub === 'string' && pub.length >= 16
    ? pub.slice(0, 8) + '…' + pub.slice(-8)
    : String(pub ?? '?');
}

function decide(decision) {
  send({ action: 'decide', requestId, decision }).then(() => {
    document.getElementById('actions').hidden = true;
    document.getElementById('status').textContent = t('decisionSaved');
    // The background closes the window itself; leave a moment as fallback.
    setTimeout(() => window.close(), 250);
  });
}

document.getElementById('btn-allow').addEventListener('click', () => decide('allow'));
document.getElementById('btn-always').addEventListener('click', () => decide('always'));
document.getElementById('btn-deny').addEventListener('click', () => decide('deny'));

initI18n();
init();
