import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createServer } from 'node:http';
import { createPublicKey } from 'node:crypto';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { AttestationSigner, CIRCUIT_VERSION, IdentityType, shutdown, verifyIdentity, type Attestation } from '../src/index.js';

const fixtures = join(dirname(fileURLToPath(import.meta.url)), 'fixtures');
const proof = new Uint8Array(readFileSync(join(fixtures, 'email.proof')));
const publicInputs = new Uint8Array(readFileSync(join(fixtures, 'email.public_inputs')));
const pem = readFileSync(join(fixtures, 'privy_es256_public.pem'), 'utf8');
const WALLET = '0xA01b6E60D51eDB3fEB9f86a62b846f4F90070f98';
const attestation: Attestation = { proof, publicInputs, wallet: WALLET };

after(() => shutdown());

test('returns the wallet and issuedAt for a matching identity', async () => {
  const r = await verifyIdentity({ attestation, signer: pem, identityType: 'email', identityValue: 'test-9988@privy.io' });
  assert.deepEqual(r, { valid: true, wallet: WALLET, issuedAt: 1789240094 });
});

test('accepts the enum, base64 transport, and any casing of the identity value', async () => {
  const b64 = { proof: Buffer.from(proof).toString('base64'), publicInputs: Buffer.from(publicInputs).toString('base64'), wallet: WALLET.toLowerCase() };
  const r = await verifyIdentity({ attestation: b64, signer: pem, identityType: IdentityType.Email, identityValue: 'TEST-9988@PRIVY.IO' });
  assert.equal(r.valid, true);
  assert.equal((r as { wallet: string }).wallet, WALLET.toLowerCase());
});

test("signer: 'sandbox' verifies the sample attestation from pinned keys, offline", async () => {
  // The fixture token is signed by the sandbox Privy app; its key is pinned in environments.ts.
  const r = await verifyIdentity({ attestation, signer: 'sandbox', identityType: 'email', identityValue: 'test-9988@privy.io' });
  assert.equal(r.valid, true);
});

test('AttestationSigner enum and a plain JWKS URL string are accepted as signers', async () => {
  const typed = await verifyIdentity({ attestation, signer: AttestationSigner.Sandbox, identityType: 'email', identityValue: 'test-9988@privy.io' });
  assert.equal(typed.valid, true);
  const jwk = createPublicKey(pem).export({ format: 'jwk' });
  const server = createServer((_, res) => { res.setHeader('content-type', 'application/json'); res.end(JSON.stringify({ keys: [{ kty: 'EC', crv: 'P-256', x: jwk.x, y: jwk.y }] })); });
  await new Promise<void>((ok) => server.listen(0, ok));
  try {
    const url = `http://127.0.0.1:${(server.address() as { port: number }).port}/jwks.json`;
    const byUrl = await verifyIdentity({ attestation, signer: url, identityType: 'email', identityValue: 'test-9988@privy.io' });
    assert.equal(byUrl.valid, true);
  } finally {
    server.close();
  }
  const junk = await verifyIdentity({ attestation, signer: 'not-a-signer', identityType: 'email', identityValue: 'test-9988@privy.io' });
  assert.equal(junk.valid, false);
  assert.match((junk as { reason: string }).reason, /unrecognised signer/);
});

test("signer: 'production' rejects a sandbox attestation", async () => {
  const r = await verifyIdentity({ attestation, signer: 'production', identityType: 'email', identityValue: 'test-9988@privy.io' });
  assert.deepEqual(r, { valid: false, reason: 'not signed by a trusted key' });
});

test('environment presets carry the app id, JWKS URL and pinned keys', async () => {
  const { PVIUM_ENVIRONMENTS } = await import('../src/index.js');
  for (const env of Object.values(PVIUM_ENVIRONMENTS)) {
    assert.ok(env.jwksUrl.includes(env.privyAppId));
    assert.ok(env.keys.length >= 1);
    for (const k of env.keys) assert.ok(k.kid && k.x > 0n && k.y > 0n);
  }
});

test('accepts its own circuit version and rejects others by name', async () => {
  const same = await verifyIdentity({ attestation: { ...attestation, circuitVersion: CIRCUIT_VERSION }, signer: pem, identityType: 'email', identityValue: 'test-9988@privy.io' });
  assert.equal(same.valid, true);
  const next = CIRCUIT_VERSION + 1;
  const other = await verifyIdentity({ attestation: { ...attestation, circuitVersion: next }, signer: pem, identityType: 'email', identityValue: 'test-9988@privy.io' });
  assert.deepEqual(other, { valid: false, reason: `attestation is for circuit version ${next}; this SDK verifies version ${CIRCUIT_VERSION}` });
  const build = await verifyIdentity({ attestation: { ...attestation, vkHash: '0x' + 'ab'.repeat(32) }, signer: pem, identityType: 'email', identityValue: 'test-9988@privy.io' });
  assert.equal(build.valid, false);
});

test('rejects a wallet the proof does not bind', async () => {
  const r = await verifyIdentity({
    attestation: { ...attestation, wallet: '0x899BA183F2c55BF9C627D9Af2984fbdED2E64311' },
    signer: pem, identityType: 'email', identityValue: 'test-9988@privy.io',
  });
  assert.deepEqual(r, { valid: false, reason: 'wallet mismatch' });
});

test('rejects the wrong identity value or type', async () => {
  const v = await verifyIdentity({ attestation, signer: pem, identityType: 'email', identityValue: 'other@privy.io' });
  const t = await verifyIdentity({ attestation, signer: pem, identityType: 'github_oauth', identityValue: 'test-9988@privy.io' });
  assert.deepEqual(v, { valid: false, reason: 'identity value mismatch' });
  assert.deepEqual(t, { valid: false, reason: 'identity type mismatch' });
});

test('rejects an untrusted signer without running the verifier', async () => {
  const gx = 0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296n;
  const gy = 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5n;
  const r = await verifyIdentity({ attestation, signer: { x: gx, y: gy }, identityType: 'email', identityValue: 'test-9988@privy.io' });
  assert.deepEqual(r, { valid: false, reason: 'not signed by a trusted key' });
});

test('rejects a tampered proof', async () => {
  const bad = new Uint8Array(proof);
  bad[200] ^= 1;
  const r = await verifyIdentity({ attestation: { ...attestation, proof: bad }, signer: pem, identityType: 'email', identityValue: 'test-9988@privy.io' });
  assert.deepEqual(r, { valid: false, reason: 'invalid proof' });
});

test('accepts a signer served from a JWKS URL', async () => {
  const jwk = createPublicKey(pem).export({ format: 'jwk' });
  const server = createServer((_, res) => {
    res.setHeader('content-type', 'application/json');
    res.end(JSON.stringify({ keys: [{ kty: 'RSA', n: 'x', e: 'AQAB' }, { kty: 'EC', crv: 'P-256', x: jwk.x, y: jwk.y, kid: 'k1' }] }));
  });
  await new Promise<void>((ok) => server.listen(0, ok));
  const port = (server.address() as { port: number }).port;
  try {
    const r = await verifyIdentity({
      attestation, signer: { jwksUrl: `http://127.0.0.1:${port}/jwks.json` }, identityType: 'email', identityValue: 'test-9988@privy.io',
    });
    assert.equal(r.valid, true);
  } finally {
    server.close();
  }
});
