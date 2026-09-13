import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { authenticate, normalizeLowS, parseToken } from '../src/token.js';
import { buildWitness, toProverToml } from '../src/witness.js';
import { InputError } from '../src/errors.js';
import type { IdentityTypeName } from '../src/identity.js';

const here = dirname(fileURLToPath(import.meta.url));
const circuitDir = join(here, '..', '..', 'circuit');
const fixtures = join(circuitDir, 'test', 'fixtures');
const jwt = readFileSync(join(fixtures, 'sample_token.jwt'), 'utf8').trim();
const pemFile = join(fixtures, 'privy_es256_public.pem');

/** Reference output from the Python witness generator, for the same request. */
function pythonToml(type: string, value: string, wallet?: string): string {
  const out = join(process.env.TMPDIR ?? '/tmp', `pvium-parity-${process.pid}.toml`);
  const args = ['scripts/gen_prover.py', '--jwt', jwt, '--pubkey', pemFile, '--type', type, '--value', value, '-o', out];
  if (wallet) args.push('--wallet', wallet);
  execFileSync('python3', args, { cwd: circuitDir, stdio: 'pipe' });
  return readFileSync(out, 'utf8');
}

async function tsToml(type: IdentityTypeName, value: string, wallet?: string) {
  const token = parseToken(jwt);
  const signer = await authenticate(token, { pemFile });
  const built = buildWitness({ token, signer, identityType: type, identityValue: value, wallet }, normalizeLowS(token.signature));
  return { toml: toProverToml(built.inputs), iat: built.iat };
}

for (const [type, value, wallet] of [
  ['email', 'test-9988@privy.io', '0xA01b6E60D51eDB3fEB9f86a62b846f4F90070f98'],
  ['github_oauth', 'dephizee', 'EXnVUEeELHiYynvjoQ9YhgxfMSDJC6tJm7VkFQY2b8Wj'],
  ['email', 'test-9988@privy.io', undefined],
  ['wallet', '0x899BA183F2c55BF9C627D9Af2984fbdED2E64311', '0xdA90b3C11F5AA8698F5D9356f29541D46E32840d'],
] as const) {
  test(`witness matches gen_prover.py byte for byte: ${type} ${value} ${wallet ?? '(no wallet)'}`, async () => {
    const { toml, iat } = await tsToml(type, value, wallet);
    assert.equal(toml, pythonToml(type, value, wallet));
    assert.equal(iat, 1789240094);
  });
}

test('rejects an identity or wallet that is not linked, before any proving', async () => {
  const token = parseToken(jwt);
  const signer = await authenticate(token, { pemFile });
  const sig = normalizeLowS(token.signature);
  await assert.rejects(
    async () => buildWitness({ token, signer, identityType: 'email', identityValue: 'other@privy.io' }, sig),
    (e: unknown) => e instanceof InputError && /no linked account/.test(e.message),
  );
  await assert.rejects(
    async () => buildWitness({ token, signer, identityType: 'email', identityValue: 'test-9988@privy.io', wallet: '0xA01b6E60D51eDB3fEB9f86a62b846f4F90070f' }, sig),
    (e: unknown) => e instanceof InputError && /no linked account/.test(e.message),
  );
});

test('rejects a token signed by an untrusted key with 401', async () => {
  const token = parseToken(jwt);
  await assert.rejects(
    () => authenticate(token, { pemFile: join(fixtures, 'test_es256_public.pem') }),
    (e: unknown) => e instanceof InputError && e.status === 401,
  );
});

test('low-s normalisation is idempotent and keeps r', () => {
  const token = parseToken(jwt);
  const once = normalizeLowS(token.signature);
  assert.deepEqual(normalizeLowS(once), once);
  assert.deepEqual(once.subarray(0, 32), token.signature.subarray(0, 32));
  assert.ok(BigInt('0x' + once.subarray(32).toString('hex')) <= 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n / 2n);
});
