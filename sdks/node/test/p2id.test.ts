import { test } from 'node:test';
import assert from 'node:assert/strict';
import { checksumAddress, identityHash, p2idAddress, p2idAddressForHash, p2idScheme, P2ID_SCHEME, P2ID_SCHEMES } from '../src/p2id.js';
import { IdentityType } from '../src/identity.js';

// From contracts/test: identityHash('email', 'test-9988@privy.io') and the vault fixture.
const EMAIL_COMMITMENT = '0xbcda0f09fa9732b2bfdea38199486b654a84e8e06085d7e364af8137f8d7deaf';
// Reference vector produced with ethers.getCreate2Address(factory, salt, initCodeHash) for p2id.vault.v1.
const FACTORY = '0x1111111111111111111111111111111111111111';
const V1_INIT_CODE_HASH = '0xee9e754a61e88c528c790b17d279033c4750ae71c1e2dd07133e4a2009e6ce5c';
const EXPECTED = '0x59ed1B4a2C6c62621d8dfCf31a9b4c0Ab8cC4D02';

test('identityHash matches the circuit and contract fixtures, by id or by name, case-insensitively', async () => {
  assert.equal(await identityHash('email', 'test-9988@privy.io'), EMAIL_COMMITMENT);
  assert.equal(await identityHash(IdentityType.Email, 'TEST-9988@Privy.IO'), EMAIL_COMMITMENT);
  assert.notEqual(await identityHash('phone', '+15551234567'), await identityHash('phone', '+15551234568'));
});

test('schemes are keyed by domain; v1 is pinned and builds on the v1 identity domain', () => {
  assert.equal(P2ID_SCHEME, 'p2id.vault.v1');
  assert.deepEqual(Object.keys(P2ID_SCHEMES), ['p2id.vault.v1']);
  const v1 = p2idScheme('p2id.vault.v1');
  assert.equal(v1.identityDomain, 'p2id.identity.v1');
  assert.equal(v1.vaultInitCodeHash, V1_INIT_CODE_HASH); // frozen once released: changing the vault means p2id.vault.v2
  assert.deepEqual(p2idScheme(), v1);
  assert.throws(() => p2idScheme('p2id.vault.v9'), /unknown P2ID scheme "p2id.vault.v9" \(known: p2id.vault.v1\)/);
});

test('p2idAddress reproduces CREATE2 exactly as the factory computes it', async () => {
  assert.equal(p2idAddressForHash(EMAIL_COMMITMENT, { factory: FACTORY }), EXPECTED);
  assert.equal(await p2idAddress({ identityType: 'email', identityValue: 'Test-9988@privy.io', factory: FACTORY }), EXPECTED);
  assert.equal(await p2idAddress({ identityType: 'email', identityValue: 'test-9988@privy.io', scheme: 'p2id.vault.v1', factory: FACTORY }), EXPECTED);
  // a different identity or factory moves the address
  assert.notEqual(await p2idAddress({ identityType: 'email', identityValue: 'other@privy.io', factory: FACTORY }), EXPECTED);
  assert.notEqual(p2idAddressForHash(EMAIL_COMMITMENT, { factory: '0x2222222222222222222222222222222222222222' }), EXPECTED);
});

test('the address takes no chain: one factory per environment, and a missing one fails loudly', async () => {
  for (const environment of ['production', 'sandbox'] as const) {
    const recorded = p2idScheme().factories[environment];
    const call = p2idAddress({ identityType: 'email', identityValue: 'test-9988@privy.io', environment });
    if (recorded === null) {
      await assert.rejects(call, new RegExp(`has no ${environment} factory address in this release yet`));
    } else {
      assert.equal(await call, p2idAddressForHash(EMAIL_COMMITMENT, { environment }));
    }
  }
  // production is the default
  if (p2idScheme().factories.production === null) {
    await assert.rejects(p2idAddress({ identityType: 'email', identityValue: 'test-9988@privy.io' }), /no production factory/);
  }
  await assert.rejects(
    p2idAddress({ identityType: 'email', identityValue: 'a@b.c', environment: 'staging' as any, factory: FACTORY }),
    /unknown environment "staging"/,
  );
  assert.throws(() => p2idAddressForHash(EMAIL_COMMITMENT, { factory: '0x1234' as `0x${string}` }), /bad factory address/);
  await assert.rejects(p2idAddress({ identityType: 'email', identityValue: 'a@b.c', scheme: 'p2id.vault.v2', factory: FACTORY }), /unknown P2ID scheme/);
});

test('EIP-55 checksum', () => {
  assert.equal(checksumAddress('0xfb6916095ca1df60bb79ce92ce3ea74c37c5d359'), '0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359');
  assert.equal(checksumAddress('0xA01b6E60D51eDB3fEB9f86a62b846f4F90070f98'), '0xA01b6E60D51eDB3fEB9f86a62b846f4F90070f98');
});
