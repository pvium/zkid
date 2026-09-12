import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createPublicKey } from 'node:crypto';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  IdentityType,
  decodeClaim,
  identityHash,
  parseP256PublicKeyPem,
  shutdown,
  toPublicInputFields,
  verifyProof,
} from '../src/internal.test-helpers.js';

const fixtures = join(dirname(fileURLToPath(import.meta.url)), 'fixtures');
const proof = new Uint8Array(readFileSync(join(fixtures, 'email.proof')));
const publicInputs = new Uint8Array(readFileSync(join(fixtures, 'email.public_inputs')));
const pem = readFileSync(join(fixtures, 'privy_es256_public.pem'), 'utf8');
const claim = decodeClaim(publicInputs);
const SAMPLE_WALLET = '0xA01b6E60D51eDB3fEB9f86a62b846f4F90070f98';

after(() => shutdown());

test('decodes the claim from raw public inputs and from hex fields alike', () => {
  assert.equal(claim.identityType, IdentityType.Email);
  assert.equal(claim.recipient, '0x0000000000000000000000000000000000000001');
  assert.equal(claim.iat, 1789240094);
  assert.deepEqual(decodeClaim(toPublicInputFields(publicInputs)), claim);
});

test('signer in the claim equals the key parsed from PEM, and PEM parsing matches node:crypto', () => {
  const parsed = parseP256PublicKeyPem(pem);
  const jwk = createPublicKey(pem).export({ format: 'jwk' });
  assert.equal(parsed.x, BigInt('0x' + Buffer.from(jwk.x!, 'base64url').toString('hex')));
  assert.equal(parsed.y, BigInt('0x' + Buffer.from(jwk.y!, 'base64url').toString('hex')));
  assert.deepEqual(claim.signer, parsed);
});

test('identityHash reproduces the circuit output for the sample email', async () => {
  assert.equal(await identityHash(IdentityType.Email, 'test-9988@privy.io'), claim.identityHash);
  assert.equal(await identityHash(IdentityType.Email, 'TEST-9988@Privy.io'), claim.identityHash);
  assert.notEqual(await identityHash(IdentityType.Wallet, 'ABC'), await identityHash(IdentityType.Wallet, 'abc'));
});

test('walletHash binds the sample wallet, case-insensitively for 0x addresses', async () => {
  assert.equal(claim.walletHash, await identityHash(IdentityType.Wallet, SAMPLE_WALLET));
  assert.equal(claim.walletHash, await identityHash(IdentityType.Wallet, SAMPLE_WALLET.toLowerCase()));
  assert.notEqual(await identityHash(IdentityType.Wallet, 'So1anaAddr'), await identityHash(IdentityType.Wallet, 'so1anaaddr'));
});


test('verifyProof accepts the sample proof', async () => {
  assert.equal(await verifyProof({ proof, publicInputs }), true);
});

test('verifyProof rejects a flipped proof byte', async () => {
  const bad = new Uint8Array(proof);
  bad[bad.length - 1] ^= 1;
  assert.equal(await verifyProof({ proof: bad, publicInputs }), false);
});

test('verifyProof rejects a changed public input', async () => {
  const fields = toPublicInputFields(publicInputs);
  fields[1] = '0x' + '2'.padStart(64, '0'); // recipient
  assert.equal(await verifyProof({ proof, publicInputs: fields }), false);
});





