import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { GIVE_UP_AFTER_MS, Outbox } from '../src/outbox.js';
import { Dispatcher, deliver } from '../src/webhook.js';

/** Receiver that fails the first `failures` deliveries with 503, then accepts. */
async function flakyReceiver(failures: number) {
  const seen: string[] = [];
  let remaining = failures;
  const s = createServer((req, res) => {
    let b = '';
    req.on('data', (c) => (b += c));
    req.on('end', () => {
      seen.push(b);
      if (remaining-- > 0) { res.statusCode = 503; res.end('later'); } else res.end('ok');
    });
  });
  await new Promise<void>((ok) => s.listen(0, ok));
  return { url: `http://127.0.0.1:${(s.address() as { port: number }).port}/hook?secret=x`, seen, close: () => s.close() };
}

test('outbox rows survive across instances (a restart) and are delivered by the dispatcher', async () => {
  const dbPath = join(mkdtempSync(join(tmpdir(), 'pvium-outbox-')), 'prover.db');
  const hook = await flakyReceiver(0);
  try {
    // "Before the restart": a job was proven and stored, delivery never happened.
    const first = new Outbox(dbPath);
    first.insert({ jobId: 'j1', callbackUrl: hook.url, body: JSON.stringify({ jobId: 'j1', status: 'ok' }), identityType: 'email', identityValue: 'a@b.c', wallet: '0x1' });
    first.close();

    // "After the restart": a fresh Outbox on the same file; the dispatcher's first tick delivers it.
    const second = new Outbox(dbPath);
    const d = new Dispatcher(second, 60_000);
    await d.tick();
    assert.equal(hook.seen.length, 1);
    assert.equal(JSON.parse(hook.seen[0]).jobId, 'j1');
    assert.equal(second.get('j1')!.status, 'delivered');
    assert.ok(second.get('j1')!.deliveredAt);
    d.stop();
    second.close();
  } finally {
    hook.close();
  }
});

test('failed deliveries back off and retry until acknowledged', async () => {
  const hook = await flakyReceiver(2);
  const outbox = new Outbox(':memory:');
  try {
    outbox.insert({ jobId: 'j2', callbackUrl: hook.url, body: '{"jobId":"j2"}', identityType: 'email', identityValue: 'a@b.c', wallet: null });
    const d = new Dispatcher(outbox, 60_000);

    await d.tick(); // 503 -> attempt 1, next in 60 s
    let row = outbox.get('j2')!;
    assert.equal(row.status, 'pending');
    assert.equal(row.attempts, 1);
    assert.match(row.lastError!, /503/);
    assert.ok(row.nextAttemptAt > Date.now() + 50_000);

    await d.tick(); // not due yet: nothing happens
    assert.equal(hook.seen.length, 1);

    // pretend time passed: pull the next attempt into the past
    assert.equal(outbox.due(10, row.nextAttemptAt + 1).length, 1);
    for (const j of outbox.due(10, row.nextAttemptAt + 1)) {
      const f = await deliver(j.callbackUrl, j.jobId, j.body);
      if (f) outbox.markAttemptFailed(j.jobId, f.error, f.final); else outbox.markDelivered(j.jobId);
    }
    row = outbox.get('j2')!;
    assert.equal(row.attempts, 2);
    assert.equal(row.status, 'pending');

    for (const j of outbox.due(10, row.nextAttemptAt + 1)) {
      const f = await deliver(j.callbackUrl, j.jobId, j.body);
      if (f) outbox.markAttemptFailed(j.jobId, f.error, f.final); else outbox.markDelivered(j.jobId);
    }
    assert.equal(outbox.get('j2')!.status, 'delivered');
    assert.equal(hook.seen.length, 3);
    assert.deepEqual(outbox.counts(), { pending: 0, delivered: 1, failed: 0 });
  } finally {
    hook.close();
    outbox.close();
  }
});

test('a 4xx from the receiver is final; give-up window is 48 h', async () => {
  const s = createServer((_, res) => { res.statusCode = 400; res.end('no'); });
  await new Promise<void>((ok) => s.listen(0, ok));
  const outbox = new Outbox(':memory:');
  try {
    const url = `http://127.0.0.1:${(s.address() as { port: number }).port}/`;
    outbox.insert({ jobId: 'j3', callbackUrl: url, body: '{}', identityType: 'email', identityValue: 'a@b.c', wallet: null });
    await new Dispatcher(outbox, 60_000).tick();
    assert.equal(outbox.get('j3')!.status, 'failed');
    assert.equal(GIVE_UP_AFTER_MS, 48 * 3_600_000);
  } finally {
    s.close();
    outbox.close();
  }
});
