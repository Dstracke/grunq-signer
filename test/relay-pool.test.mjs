// RelayPool unit tests: the outbox must hold publishes issued while a
// socket is still connecting (nostrconnect pairing publishes right after
// refreshSubscriptions creates the connection).
import test from 'node:test';
import assert from 'node:assert/strict';

import { RelayPool } from '../src/lib/relay-pool.js';

class FakeWS {
  static instances = [];
  static sent = [];
  static OPEN = 1;
  constructor(url) {
    this.url = url;
    this.readyState = 0; // CONNECTING
    FakeWS.instances.push(this);
  }
  send(data) {
    FakeWS.sent.push({ url: this.url, data });
  }
  close() {
    this.readyState = 3;
    this.onclose?.();
  }
  open() {
    this.readyState = 1;
    this.onopen?.();
  }
  relayMessage(msg) {
    this.onmessage?.({ data: JSON.stringify(msg) });
  }
}

function withFakeWS(fn) {
  const real = globalThis.WebSocket;
  FakeWS.instances = [];
  FakeWS.sent = [];
  globalThis.WebSocket = FakeWS;
  return Promise.resolve(fn()).finally(() => {
    globalThis.WebSocket = real;
  });
}

test('relay-pool: publish queues while the socket is connecting', () => {
  return withFakeWS(async () => {
    const pool = new RelayPool();
    // subscribe first so the conn exists but is still CONNECTING
    pool.subscribe(['ws://r.example'], { kinds: [1] }, () => {});
    const ws = FakeWS.instances[0];
    assert.equal(ws.readyState, 0);

    let settled = false;
    const publish = pool.publish(['ws://r.example'], { id: 'ev1' });
    publish.then(
      () => { settled = true; },
      () => { settled = true; },
    );
    await new Promise((r) => setTimeout(r, 25));
    assert.equal(settled, false, 'publish waits for the socket instead of failing');

    ws.open();
    await new Promise((r) => setTimeout(r, 25));
    const eventMsg = FakeWS.sent.map((s) => JSON.parse(s.data)).find((m) => m[0] === 'EVENT');
    assert.ok(eventMsg, 'queued EVENT was flushed on open');
    assert.equal(eventMsg[1].id, 'ev1');

    ws.relayMessage(['OK', 'ev1', true, '']);
    await publish;
    assert.equal(settled, true);
    pool.close();
  });
});

test('relay-pool: publish still rejects when the relay never opens', () => {
  return withFakeWS(async () => {
    const pool = new RelayPool();
    pool.subscribe(['ws://r.example'], { kinds: [1] }, () => {});
    await assert.rejects(
      () => pool.publish(['ws://r.example'], { id: 'ev2' }, 60),
      /no relay accepted/,
    );
    pool.close();
  });
});
