// QR export tests: the popup renders npub/nsec as QR codes with the bundled
// qrcode-generator (MIT). Guards against a silent break of the export panel
// (e.g. a payload that no QR version can hold) without a browser.
import assert from 'node:assert/strict';
import test from 'node:test';
import qrcode from '../src/vendor/qrcode-generator.cjs';
import { encodeNpub, encodeNsec, randomIdentity } from '../src/lib/keys.js';

function render(text) {
  const qr = qrcode(0, 'M'); // typeNumber 0 = automatic version
  qr.addData(text);
  qr.make();
  return qr;
}

test('qr: npub and nsec fit into an auto-sized QR code', () => {
  const id = randomIdentity();
  const npub = encodeNpub(id.pubkeyHex);
  const nsec = encodeNsec(id.privHex);
  assert.equal(npub.length, 63);
  assert.equal(nsec.length, 63);
  for (const value of [npub, nsec]) {
    const qr = render(value);
    const count = qr.getModuleCount();
    assert.ok(count >= 21 && count <= 177, `module count ${count}`);
    const url = qr.createDataURL(6, 2);
    assert.match(url, /^data:image\/gif;base64,/);
    assert.ok(url.length > 1000);
  }
});

test('qr: different keys produce different codes', () => {
  const a = randomIdentity();
  const b = randomIdentity();
  assert.notEqual(
    render(encodeNpub(a.pubkeyHex)).createDataURL(4, 2),
    render(encodeNpub(b.pubkeyHex)).createDataURL(4, 2),
  );
});

test('qr: type number 0 picks the smallest version for short payloads', () => {
  // 21 modules = version 1; the shortest useful payload is an npub/nsec, so
  // this documents the library still auto-sizes instead of always maxing out.
  const short = render('grunq');
  assert.ok(short.getModuleCount() <= 33);
});
