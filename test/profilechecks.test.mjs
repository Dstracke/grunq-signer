// Tests for the on-demand profile checks (lud16 + NIP-05) and their network
// guards. fetch is injected, so nothing leaves the machine.
import assert from 'node:assert/strict';
import test from 'node:test';
import { isBlockedHost, requireHttpsUrl, fetchJson } from '../src/lib/net.js';
import { createProfileChecks, parseAddress } from '../src/signer/profilechecks.js';

function jsonResponse(body, { status = 200, headers = {} } = {}) {
  return {
    ok: status >= 200 && status < 300,
    status,
    headers: { get: (name) => headers[name.toLowerCase()] ?? null },
    text: async () => (typeof body === 'string' ? body : JSON.stringify(body)),
  };
}

function fakeFetch(handler) {
  const calls = [];
  const impl = async (url, init) => {
    calls.push({ url, init });
    return handler(url, init);
  };
  impl.calls = calls;
  return impl;
}

test('net: private hosts are blocked, public https is allowed', () => {
  for (const host of [
    'localhost', '127.0.0.1', '10.1.2.3', '192.168.0.5', '172.16.0.1', '172.31.255.1',
    '169.254.1.1', '100.64.0.1', '0.0.0.0', '224.0.0.1', '::1', 'fd00::1', 'fe80::1',
    'router', 'printer.local', 'x.internal', 'app.home.arpa', '[::1]',
  ]) {
    assert.equal(isBlockedHost(host), true, host);
  }
  for (const host of ['example.org', 'relay.grunq.com', '172.32.0.1', '8.8.8.8', 'a.b.example']) {
    assert.equal(isBlockedHost(host), false, host);
  }
});

test('net: requireHttpsUrl only accepts plain public https URLs', () => {
  assert.equal(requireHttpsUrl('https://example.org/.well-known/nostr.json').hostname, 'example.org');
  assert.equal(requireHttpsUrl('http://example.org/x'), null, 'no http');
  assert.equal(requireHttpsUrl('https://user:pw@example.org/x'), null, 'no credentials');
  assert.equal(requireHttpsUrl('https://localhost/x'), null);
  assert.equal(requireHttpsUrl('javascript:alert(1)'), null);
  assert.equal(requireHttpsUrl(''), null);
});

test('net: fetchJson enforces https, size and JSON', async () => {
  const ok = fakeFetch(() => jsonResponse({ hello: 'world' }));
  assert.deepEqual(await fetchJson('https://example.org/x', { fetchImpl: ok }), { hello: 'world' });

  const blocked = fakeFetch(() => jsonResponse({}));
  await assert.rejects(fetchJson('http://example.org/x', { fetchImpl: blocked }), (e) => e.code === 'blocked');
  assert.equal(blocked.calls.length, 0, 'blocked URLs never hit the network');
  await assert.rejects(fetchJson('https://127.0.0.1/x', { fetchImpl: blocked }), (e) => e.code === 'blocked');

  const big = fakeFetch(() => jsonResponse('x'.repeat(100)));
  await assert.rejects(
    fetchJson('https://example.org/x', { fetchImpl: big, maxBytes: 50 }),
    (e) => e.code === 'too_large',
  );

  const broken = fakeFetch(() => jsonResponse('<html>'));
  await assert.rejects(fetchJson('https://example.org/x', { fetchImpl: broken }), (e) => e.code === 'invalid');

  const missing = fakeFetch(() => jsonResponse({}, { status: 404 }));
  await assert.rejects(fetchJson('https://example.org/x', { fetchImpl: missing }), (e) => e.code === 'network');
});

test('net: fetchJson never follows redirects and sends no credentials', async () => {
  const seen = fakeFetch(() => jsonResponse({ ok: true }));
  await fetchJson('https://example.org/x', { fetchImpl: seen });
  assert.equal(seen.calls[0].init.redirect, 'error');
  assert.equal(seen.calls[0].init.credentials, 'omit');
});

test('checks: parseAddress accepts name@domain only', () => {
  assert.deepEqual(parseAddress('luku@getalby.com'), { name: 'luku', domain: 'getalby.com' });
  assert.deepEqual(parseAddress('  _@grunq.com '), { name: '_', domain: 'grunq.com' });
  assert.equal(parseAddress('luku'), null);
  assert.equal(parseAddress('@grunq.com'), null);
  assert.equal(parseAddress('luku@localhost'), null);
});

test('checks: lud16 resolves amounts and zap support', async () => {
  const fetchImpl = fakeFetch(() => jsonResponse({
    tag: 'payRequest',
    callback: 'https://getalby.com/lnurlp/luku/callback',
    minSendable: 1000,
    maxSendable: 100_000_000,
    metadata: JSON.stringify([['text/plain', 'Zaps for luku'], ['text/identifier', 'luku@getalby.com']]),
    allowsNostr: true,
  }));
  const checks = createProfileChecks({ fetchImpl });
  const res = await checks.checkLud16('luku@getalby.com');
  assert.equal(res.ok, true);
  assert.equal(res.domain, 'getalby.com');
  assert.equal(res.minSats, 1);
  assert.equal(res.maxSats, 100_000);
  assert.equal(res.description, 'Zaps for luku');
  assert.equal(res.allowsNostr, true);
  assert.match(fetchImpl.calls[0].url, /^https:\/\/getalby\.com\/\.well-known\/lnurlp\/luku$/);
});

test('checks: lud16 rejects invalid addresses, blocked hosts and non-LNURL answers', async () => {
  const checks = createProfileChecks({ fetchImpl: fakeFetch(() => jsonResponse({ tag: 'other' })) });
  assert.deepEqual(await checks.checkLud16('nope'), { ok: false, code: 'invalid_address' });
  assert.deepEqual(await checks.checkLud16('a@localhost'), { ok: false, code: 'invalid_address' });
  assert.deepEqual(await checks.checkLud16('a@127.0.0.1'), { ok: false, code: 'blocked' });
  assert.deepEqual(await checks.checkLud16('a@example.org'), { ok: false, code: 'not_lnurl' });
});

test('checks: nip05 verifies the published key against our pubkey', async () => {
  const pubkey = 'a'.repeat(64);
  const fetchImpl = fakeFetch(() => jsonResponse({ names: { luku: pubkey } }));
  const checks = createProfileChecks({ fetchImpl });
  const res = await checks.checkNip05('luku@grunq.com', pubkey);
  assert.deepEqual(res, { ok: true, verified: true, domain: 'grunq.com' });
  assert.match(fetchImpl.calls[0].url, /^https:\/\/grunq\.com\/\.well-known\/nostr\.json\?name=luku$/);
});

test('checks: nip05 reports mismatch, missing name and npub values', async () => {
  const pubkey = 'a'.repeat(64);
  const cases = [
    [{ names: { luku: 'b'.repeat(64) } }, 'mismatch'],
    [{ names: { other: pubkey } }, 'not_found'],
    [{ names: { luku: 'npub1xyz' } }, 'npub'],
    [{}, 'not_found'],
  ];
  for (const [body, reason] of cases) {
    const checks = createProfileChecks({ fetchImpl: fakeFetch(() => jsonResponse(body)) });
    const res = await checks.checkNip05('luku@grunq.com', pubkey);
    assert.equal(res.ok, true);
    assert.equal(res.verified, false);
    assert.equal(res.reason, reason);
  }
  // Uppercase hex in nostr.json is not a valid NIP-05 entry -> mismatch.
  const checks = createProfileChecks({ fetchImpl: fakeFetch(() => jsonResponse({ names: { luku: pubkey.toUpperCase() } })) });
  assert.equal((await checks.checkNip05('luku@grunq.com', pubkey)).verified, true, 'case is normalised');
});

test('checks: nip05 network errors surface as codes (and are cached)', async () => {
  let calls = 0;
  const fetchImpl = fakeFetch(() => {
    calls += 1;
    throw Object.assign(new Error('boom'), { code: 'network' });
  });
  const checks = createProfileChecks({ fetchImpl });
  assert.deepEqual(await checks.checkNip05('luku@grunq.com', 'a'.repeat(64)), { ok: false, code: 'network' });
  assert.deepEqual(await checks.checkNip05('luku@grunq.com', 'a'.repeat(64)), { ok: false, code: 'network' });
  assert.equal(calls, 1, 'failure is cached');
  assert.deepEqual(await checks.checkNip05('nope', 'a'.repeat(64)), { ok: false, code: 'invalid_address' });
});
