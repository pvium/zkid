import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import type { Server } from 'node:http';
import { createApp } from '../src/app.js';
import { configFromEnv } from '../src/config.js';

const here = dirname(fileURLToPath(import.meta.url));
const pemFile = join(here, '..', '..', 'circuit', 'test', 'fixtures', 'privy_es256_public.pem');
const cfg = configFromEnv({ ...process.env, PRIVY_JWKS_URL: undefined, PRIVY_PUBLIC_KEY_PEM_FILE: pemFile,
  CIRCUIT_JSON: join(here, '..', 'circuit', 'pvium_identity.json'), VK_PATH: join(here, '..', 'circuit', 'vk'),
  CIRCUIT_VERSION_JSON: join(here, '..', 'circuit', 'version.json'), ALLOW_HTTP_CALLBACKS: 'true', MAX_QUEUE: '0', DB_PATH: ':memory:' });
const SECRET = 's3cret';
const app = createApp(cfg, SECRET);
let server: Server;
let base: string;
await new Promise<void>((ok) => { server = app.listen(0, () => { base = `http://127.0.0.1:${(server.address() as { port: number }).port}`; ok(); }); });
after(async () => { server.close(); await app.locals.close(); });

/** A one-shot local receiver for webhook deliveries. */
async function receiver() {
  const { createServer } = await import('node:http');
  let resolveBody: (b: string) => void;
  const got = new Promise<string>((r) => (resolveBody = r));
  const s = createServer((req, res) => { let b = ''; req.on('data', (c) => (b += c)); req.on('end', () => { res.end('ok'); resolveBody(b); }); });
  await new Promise<void>((ok) => s.listen(0, ok));
  return { url: `http://127.0.0.1:${(s.address() as { port: number }).port}/hook?secret=abc`, got, close: () => s.close() };
}

const post = (body: unknown, auth?: string) =>
  fetch(`${base}/attestations`, { method: 'POST', headers: { 'content-type': 'application/json', ...(auth ? { authorization: auth } : {}) }, body: typeof body === 'string' ? body : JSON.stringify(body) });

test('healthz is open and reports the circuit version', async () => {
  const r = await fetch(`${base}/healthz`);
  assert.equal(r.status, 200);
  const body = (await r.json()) as { circuitVersion: number; vkHash: string };
  assert.equal(body.circuitVersion, 1);
  assert.match(body.vkHash, /^0x[0-9a-f]{64}$/);
});

test('rejects a circuit version this prover does not serve', async () => {
  const r = await post({ identityType: 'email', identityValue: 'a@b.c', jwt: 'x.y.z', wallet: '0x1', version: 2 }, `Bearer ${SECRET}`);
  assert.equal(r.status, 400);
  assert.match(((await r.json()) as { error: string }).error, /unsupported circuit version 2/);
});

test('rejects missing or wrong secret', async () => {
  assert.equal((await post({})).status, 401);
  assert.equal((await post({}, 'Bearer wrong')).status, 401);
  assert.equal((await post({}, 'Bearer s3cre')).status, 401); // length mismatch path
});

test('rejects invalid JSON and invalid bodies with 400', async () => {
  assert.equal((await post('{not json', `Bearer ${SECRET}`)).status, 400);
  const r = await post({ identityType: 'email' }, `Bearer ${SECRET}`);
  assert.equal(r.status, 400);
  assert.match(((await r.json()) as { error: string }).error, /identityValue/);
});

test('rejects an untrusted token with 401', async () => {
  const fake = 'eyJhbGciOiJFUzI1NiJ9.eyJpYXQiOjF9.' + Buffer.alloc(64, 1).toString('base64url');
  const r = await post({ identityType: 'email', identityValue: 'a@b.c', jwt: fake, wallet: '0x1' }, `Bearer ${SECRET}`);
  assert.equal(r.status, 401);
});

test('trusts every key across several JWKS sources; the token picks its own', async () => {
  const { createServer } = await import('node:http');
  const { createPublicKey, readFileSync } = await import('node:crypto').then(async (c) => ({ ...c, readFileSync: (await import('node:fs')).readFileSync }));
  const { authenticate, parseToken, trustedKeys } = await import('../src/token.js');
  const real = createPublicKey(readFileSync(pemFile)).export({ format: 'jwk' });
  const other = createPublicKey(readFileSync(join(here, '..', '..', 'circuit', 'test', 'fixtures', 'test_es256_public.pem'))).export({ format: 'jwk' });
  const serve = (jwk: object, kid: string) => {
    const s = createServer((_, res) => { res.setHeader('content-type', 'application/json'); res.end(JSON.stringify({ keys: [{ ...jwk, kid }] })); });
    return new Promise<{ url: string; close: () => void }>((ok) => s.listen(0, () => ok({ url: `http://127.0.0.1:${(s.address() as { port: number }).port}/jwks.json`, close: () => s.close() })));
  };
  const a = await serve(other, 'sandbox-key');
  const b = await serve(real, 'Lp_q4NY6tg5jSdiD790AIm01JR7GIJ_xmDVZZ6MVAfM');
  try {
    const source = { jwksUrls: [a.url, b.url] };
    assert.equal((await trustedKeys(source)).length, 2);
    const jwt = readFileSync(join(here, '..', '..', 'circuit', 'test', 'fixtures', 'sample_token.jwt'), 'utf8').trim();
    const key = await authenticate(parseToken(jwt), source);
    assert.equal(key.kid, 'Lp_q4NY6tg5jSdiD790AIm01JR7GIJ_xmDVZZ6MVAfM');
    await assert.rejects(() => authenticate(parseToken(jwt), { jwksUrls: [a.url] }));
  } finally {
    a.close(); b.close();
  }
});

test('healthz reports queue stats', async () => {
  const body = (await (await fetch(`${base}/healthz`)).json()) as { inFlight: number; queued: number; maxConcurrency: number };
  assert.equal(body.inFlight, 0);
  assert.equal(body.queued, 0);
  assert.equal(body.maxConcurrency, 1);
});

test('async: answers 202 and delivers the outcome to the callback URL', async () => {
  const hook = await receiver();
  try {
    const r = await post({ identityType: 'email', identityValue: 'a@b.c', jwt: 'x.y.z', wallet: '0x1', callbackUrl: hook.url }, `Bearer ${SECRET}`);
    assert.equal(r.status, 202);
    const { jobId, status } = (await r.json()) as { jobId: string; status: string };
    assert.equal(status, 'queued');
    const delivered = JSON.parse(await hook.got) as { jobId: string; status: string; error?: string; identityValue: string };
    assert.equal(delivered.jobId, jobId);
    assert.equal(delivered.status, 'error'); // 'x.y.z' is not a token; the failure is delivered, not lost
    assert.match(delivered.error!, /token/);
    assert.equal(delivered.identityValue, 'a@b.c');

    // The job is persisted and queryable, marked delivered after the receiver's 2xx.
    const job = await (await fetch(`${base}/jobs/${jobId}`, { headers: { authorization: `Bearer ${SECRET}` } })).json() as { status: string; result: { status: string } };
    assert.equal(job.status, 'delivered');
    assert.equal(job.result.status, 'error');
    assert.equal((await fetch(`${base}/jobs/${jobId}`)).status, 401);
    assert.equal((await fetch(`${base}/jobs/nope`, { headers: { authorization: `Bearer ${SECRET}` } })).status, 404);
  } finally {
    hook.close();
  }
});

test('async: rejects bad callback URLs up front', async () => {
  const bad = await post({ identityType: 'email', identityValue: 'a@b.c', jwt: 'x.y.z', wallet: '0x1', callbackUrl: 'not a url' }, `Bearer ${SECRET}`);
  assert.equal(bad.status, 400);
  const badBody = await post({ identityType: 'email', jwt: 'x.y.z', callbackUrl: 'https://example.com/hook' }, `Bearer ${SECRET}`);
  assert.equal(badBody.status, 400); // identityValue missing: validated before accepting
});

test('rejects oversized bodies with 413', async () => {
  const r = await post({ jwt: 'x'.repeat(70 * 1024) }, `Bearer ${SECRET}`);
  assert.equal(r.status, 413);
});
