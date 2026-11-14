// Developer test page for the NIP-07 surface (see test/page.html).
const out = document.getElementById('out');
const peerInput = document.getElementById('peer');

function log(...items) {
  out.classList.remove('muted');
  out.textContent += items.map((i) => (typeof i === 'object' ? JSON.stringify(i, null, 2) : String(i))).join(' ') + '\n';
}

function n() {
  if (!window.nostr) {
    log('window.nostr not found - is the extension loaded and did the content scripts (document_start) run?');
    return null;
  }
  return window.nostr;
}

function roundtripPeer() {
  // default: use our own pubkey as encryption counterpart
  const peer = peerInput.value.trim();
  if (!/^[0-9a-f]{64}$/.test(peer)) {
    throw new Error('peer must be a 64-char hex pubkey - press "getPublicKey" to fill it in');
  }
  return peer;
}

document.getElementById('b-pk').addEventListener('click', async () => {
  try {
    const pk = await n().getPublicKey();
    log('pubkey:', pk);
    peerInput.value = pk;
  } catch (e) { log('getPublicKey ERROR:', e.message, e.code ? `(code ${e.code})` : ''); }
});

document.getElementById('b-relays').addEventListener('click', async () => {
  try { log('relays:', await n().getRelays()); }
  catch (e) { log('getRelays ERROR:', e.message, e.code ? `(code ${e.code})` : ''); }
});

document.getElementById('b-sign').addEventListener('click', async () => {
  try {
    const ev = await n().signEvent({
      kind: 1,
      created_at: Math.floor(Date.now() / 1000),
      tags: [['t', 'grunq-signer-test']],
      content: 'Test signature from the Grunq Signer test page (' + new Date().toISOString() + ')',
    });
    log('signed event:', { id: ev.id, pubkey: ev.pubkey.slice(0, 16) + '…', kind: ev.kind, sig: ev.sig.slice(0, 32) + '…' });
  } catch (e) { log('signEvent ERROR:', e.message, e.code ? `(code ${e.code})` : ''); }
});

document.getElementById('b-nip04').addEventListener('click', async () => {
  try {
    const peer = roundtripPeer();
    const msg = 'nip04 test message';
    const payload = await n().nip04.encrypt(peer, msg);
    log('nip04.encrypt →', payload.slice(0, 60) + '…');
    const plain = await n().nip04.decrypt(peer, payload);
    log('nip04.decrypt →', plain === msg ? 'OK (roundtrip)' : 'MISMATCH: ' + plain);
  } catch (e) { log('nip04 ERROR:', e.message, e.code ? `(code ${e.code})` : ''); }
});

document.getElementById('b-nip44').addEventListener('click', async () => {
  try {
    const peer = roundtripPeer();
    const msg = 'nip44 test message';
    const payload = await n().nip44.encrypt(peer, msg);
    log('nip44.encrypt →', payload.slice(0, 60) + '…');
    const plain = await n().nip44.decrypt(peer, payload);
    log('nip44.decrypt →', plain === msg ? 'OK (roundtrip)' : 'MISMATCH: ' + plain);
  } catch (e) { log('nip44 ERROR:', e.message, e.code ? `(code ${e.code})` : ''); }
});
