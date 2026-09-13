import { test } from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { AttestationService } from '../src/attestation.js';
import { configFromEnv } from '../src/config.js';
import { InputError } from '../src/errors.js';

const here = dirname(fileURLToPath(import.meta.url));
const fixtures = join(here, '..', '..', 'circuit', 'test', 'fixtures');
const jwt = readFileSync(join(fixtures, 'sample_token.jwt'), 'utf8').trim();
const pemFile = join(fixtures, 'privy_es256_public.pem');
const WALLET = '0xA01b6E60D51eDB3fEB9f86a62b846f4F90070f98';

const cfg = configFromEnv({ ...process.env, PRIVY_JWKS_URL: undefined, PRIVY_PUBLIC_KEY_PEM_FILE: pemFile,
  CIRCUIT_JSON: join(here, '..', 'circuit', 'pvium_identity.json'), VK_PATH: join(here, '..', 'circuit', 'vk'),
  CIRCUIT_VERSION_JSON: join(here, '..', 'circuit', 'version.json') });
const canProve = existsSync(cfg.circuitJson) && existsSync(cfg.vkPath) && (cfg.bbBin.includes('/') ? existsSync(cfg.bbBin) : true);

test('bad requests fail fast without proving', async () => {
  const service = new AttestationService(cfg);
  await assert.rejects(() => service.generate({ identityType: 'email', identityValue: 'x', jwt: 'not.a.jwt.at.all', wallet: WALLET }), InputError);
  await assert.rejects(() => service.generate({ identityType: 'nope' as never, identityValue: 'x', jwt, wallet: WALLET }), InputError);
  await assert.rejects(() => service.generate({ identityType: 'email', identityValue: 'other@privy.io', jwt, wallet: WALLET }), InputError);
});

test('generates an attestation the SDK verifies', { skip: !canProve && 'bb / circuit artifacts not available' }, async (t) => {
  const service = new AttestationService(cfg);
  const started = Date.now();
  const a = await service.generate({ identityType: 'email', identityValue: 'test-9988@privy.io', jwt, wallet: WALLET });
  t.diagnostic(`attestation generated in ${((Date.now() - started) / 1000).toFixed(1)} s`);
  assert.equal(a.issuedAt, 1789240094);
  assert.equal(a.wallet, WALLET);
  assert.equal(a.circuitVersion, 1);
  assert.match(a.vkHash, /^0x[0-9a-f]{64}$/);
  assert.equal(Buffer.from(a.publicInputs, 'base64').length, 11 * 32);

  const { verifyIdentity, shutdown } = await import('@pvium/zk-verifier');
  try {
    const ok = await verifyIdentity({
      attestation: { proof: a.proof, publicInputs: a.publicInputs, wallet: a.wallet! },
      signer: readFileSync(pemFile, 'utf8'), identityType: 'email', identityValue: 'TEST-9988@privy.io',
    });
    assert.deepEqual(ok, { valid: true, wallet: WALLET, issuedAt: 1789240094 });
    const wrong = await verifyIdentity({
      attestation: { proof: a.proof, publicInputs: a.publicInputs, wallet: '0x899BA183F2c55BF9C627D9Af2984fbdED2E64311' },
      signer: readFileSync(pemFile, 'utf8'), identityType: 'email', identityValue: 'test-9988@privy.io',
    });
    assert.equal(wrong.valid, false);
  } finally {
    await shutdown();
  }
});
