import { test } from 'node:test';
import assert from 'node:assert/strict';
import { checksumAddress, identityHash, p2idAddress, p2idAddressForHash, P2ID_FACTORY, P2ID_VAULT_INIT_CODE_HASH } from '../src/p2id.js';
import { IdentityType } from '../src/identity.js';

// From contracts/test: identityHash('email', 'test-9988@privy.io') and the vault fixture.
const EMAIL_COMMITMENT = '0xbcda0f09fa9732b2bfdea38199486b654a84e8e06085d7e364af8137f8d7deaf';
// Reference vector produced with ethers.getCreate2Address(factory, salt, initCodeHash).
const FACTORY = '0x1111111111111111111111111111111111111111';
const EXPECTED = '0xdFb0272b2178A35D2ad0693F51b5Dd23659C3235';
const EXPECTED_ICH = '0xedeb17b2cad352aa707895e12dddf28ba5ced700b2feaf31d26c3ee221d84768';

test('identityHash matches the circuit and contract fixtures, by id or by name, case-insensitively', async () => {
  assert.equal(await identityHash('email', 'test-9988@privy.io'), EMAIL_COMMITMENT);
  assert.equal(await identityHash(IdentityType.Email, 'TEST-9988@Privy.IO'), EMAIL_COMMITMENT);
  assert.notEqual(await identityHash('phone', '+15551234567'), await identityHash('phone', '+15551234568'));
});

test('p2idAddress reproduces CREATE2 exactly as the factory computes it', async () => {
  assert.equal(P2ID_VAULT_INIT_CODE_HASH, EXPECTED_ICH);
  assert.equal(p2idAddressForHash(EMAIL_COMMITMENT, FACTORY), EXPECTED);
  assert.equal(await p2idAddress({ identityType: 'email', identityValue: 'Test-9988@privy.io', factory: FACTORY }), EXPECTED);
  // a different identity or factory moves the address
  assert.notEqual(await p2idAddress({ identityType: 'email', identityValue: 'other@privy.io', factory: FACTORY }), EXPECTED);
  assert.notEqual(p2idAddressForHash(EMAIL_COMMITMENT, '0x2222222222222222222222222222222222222222'), EXPECTED);
});

test('the address takes no chain: one factory everywhere, and a missing one fails loudly', async () => {
  // Nothing in the inputs names a chain, so the result cannot differ between chains.
  const a = await p2idAddress({ identityType: 'email', identityValue: 'test-9988@privy.io', factory: FACTORY });
  assert.equal(a, EXPECTED);
  if (P2ID_FACTORY === null) {
    await assert.rejects(p2idAddress({ identityType: 'email', identityValue: 'test-9988@privy.io' }), /no Pvium P2ID factory address yet/);
  } else {
    assert.equal(await p2idAddress({ identityType: 'email', identityValue: 'test-9988@privy.io' }), p2idAddressForHash(EMAIL_COMMITMENT));
  }
  assert.throws(() => p2idAddressForHash(EMAIL_COMMITMENT, '0x1234' as `0x${string}`), /bad factory address/);
});

test('EIP-55 checksum', () => {
  assert.equal(checksumAddress('0xfb6916095ca1df60bb79ce92ce3ea74c37c5d359'), '0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359');
  assert.equal(checksumAddress('0xA01b6E60D51eDB3fEB9f86a62b846f4F90070f98'), '0xA01b6E60D51eDB3fEB9f86a62b846f4F90070f98');
});
