import { test } from 'node:test';
import assert from 'node:assert/strict';
import { checksumAddress, identityHash, p2idAddress, p2idAddressForHash, p2idFactory, P2ID_VAULT_INIT_CODE_HASH } from '../src/p2id.js';
import { IdentityType } from '../src/identity.js';

// From contracts/test: identityHash('email', 'test-9988@privy.io') and the vault fixture.
const EMAIL_COMMITMENT = '0xbcda0f09fa9732b2bfdea38199486b654a84e8e06085d7e364af8137f8d7deaf';
// Reference vector produced with ethers.getCreate2Address(factory, salt, initCodeHash).
const FACTORY = '0x1111111111111111111111111111111111111111';
const EXPECTED = '0xFd760512E8873374527A5386E47417b811C43930';
const EXPECTED_ICH = '0x9bb9f157d3bae1e87106f781b0db9e62c4ad40bbcfc52f02590fffa629cd452f';

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

test('unknown chain ids fail loudly instead of deriving against a wrong factory', () => {
  assert.throws(() => p2idFactory(999999), /no Pvium P2ID factory known for chain 999999/);
  assert.throws(() => p2idAddressForHash(EMAIL_COMMITMENT, '0x1234' as `0x${string}`), /bad factory address/);
});

test('EIP-55 checksum', () => {
  assert.equal(checksumAddress('0xfb6916095ca1df60bb79ce92ce3ea74c37c5d359'), '0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359');
  assert.equal(checksumAddress('0xA01b6E60D51eDB3fEB9f86a62b846f4F90070f98'), '0xA01b6E60D51eDB3fEB9f86a62b846f4F90070f98');
});
