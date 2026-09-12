import { expect } from 'chai';
import { ethers } from 'hardhat';
import { createHash, createPublicKey, verify as ecdsaVerify } from 'crypto';
import { readFileSync } from 'fs';
import { join } from 'path';
import { deployIdentityProof, deployVerifier } from './helpers/deployVerifier';

// Must match circuit/src/main.nr
const HASH_PREFIX = 'p2id.identity.v1';
const IDENTITY_TYPE_EMAIL = 0;

// Public input order emitted by the circuit
const PI = {
  identityType: 0,
  recipient: 1,
  signerXHi: 2,
  signerXLo: 3,
  signerYHi: 4,
  signerYLo: 5,
  iat: 6,
  identityHashHi: 7,
  identityHashLo: 8,
  walletHashHi: 9,
  walletHashLo: 10,
} as const;
const PUBLIC_INPUT_COUNT = 11;
const IDENTITY_TYPE_WALLET = 12;
const SAMPLE_WALLET = '0xA01b6E60D51eDB3fEB9f86a62b846f4F90070f98';

const fixtures = join(__dirname, 'fixtures');

function loadProof(): string {
  return '0x' + readFileSync(join(fixtures, 'email.proof')).toString('hex');
}

function loadPublicInputs(): string[] {
  const raw = readFileSync(join(fixtures, 'email.public_inputs'));
  expect(raw.length % 32).to.equal(0);
  const out: string[] = [];
  for (let i = 0; i < raw.length; i += 32) {
    out.push('0x' + raw.subarray(i, i + 32).toString('hex'));
  }
  return out;
}

/** Reassemble a 32-byte hash from the two 128-bit halves the circuit outputs. */
function joinHalves(hi: string, lo: string): string {
  return ethers.toBeHex((BigInt(hi) << 128n) | BigInt(lo), 32);
}

function sha256(...parts: Buffer[]): string {
  return '0x' + createHash('sha256').update(Buffer.concat(parts)).digest('hex');
}

/** The sample token is a real (expired) Privy identity token; the PEM is Privy's key from its JWKS. */
function sampleToken() {
  const token = readFileSync(join(fixtures, 'sample_token.jwt'), 'utf8').trim();
  const [header, payload, signature] = token.split('.');
  return {
    signingInput: Buffer.from(`${header}.${payload}`),
    signature: Buffer.from(signature, 'base64url'),
    publicKey: createPublicKey(readFileSync(join(fixtures, 'privy_es256_public.pem'))),
  };
}

/** Raw (x, y) of the sample signer key, as a claim contract would be constructed with. */
function sampleSignerKey(): { x: bigint; y: bigint } {
  const jwk = sampleToken().publicKey.export({ format: 'jwk' });
  return {
    x: BigInt('0x' + Buffer.from(jwk.x as string, 'base64url').toString('hex')),
    y: BigInt('0x' + Buffer.from(jwk.y as string, 'base64url').toString('hex')),
  };
}

describe('PviumIdentityVerifier (HonkVerifier)', function () {
  this.timeout(120_000);

  let verifier: any;
  let proof: string;
  let publicInputs: string[];

  before(async () => {
    const deployed = await deployVerifier();
    verifier = deployed.verifier;
    proof = loadProof();
    publicInputs = loadPublicInputs();

    for (const [name, c] of Object.entries(deployed)) {
      const code = await ethers.provider.getCode(await c.getAddress());
      console.log(`      ${name} bytecode: ${(code.length - 2) / 2} bytes (EIP-170 limit 24576)`);
    }
  });

  it('exposes the same number of public inputs the circuit emits', () => {
    expect(publicInputs.length).to.equal(PUBLIC_INPUT_COUNT);
  });

  it('verifies the sample proof', async () => {
    expect(await verifier.verify(proof, publicInputs)).to.equal(true);
    const gas = await verifier.verify.estimateGas(proof, publicInputs);
    console.log(`      verify gas: ${gas.toString()}`);
  });

  it('public inputs decode to the expected identity type, recipient and iat', () => {
    expect(BigInt(publicInputs[PI.identityType])).to.equal(BigInt(IDENTITY_TYPE_EMAIL));
    expect(BigInt(publicInputs[PI.recipient])).to.equal(1n);
    expect(BigInt(publicInputs[PI.iat])).to.equal(1789240094n);
  });

  it('signer public key outputs equal the raw key the token was signed with', () => {
    const { x, y } = sampleSignerKey();
    expect(BigInt(joinHalves(publicInputs[PI.signerXHi], publicInputs[PI.signerXLo]))).to.equal(x);
    expect(BigInt(joinHalves(publicInputs[PI.signerYHi], publicInputs[PI.signerYLo]))).to.equal(y);
  });

  it('the sample token really is signed by that key over sha256(header.payload)', () => {
    // Sanity check on the fixture itself; the circuit performs this same check in-circuit.
    const { signingInput, signature, publicKey } = sampleToken();
    const ok = ecdsaVerify('sha256', signingInput, { key: publicKey, dsaEncoding: 'ieee-p1363' }, signature);
    expect(ok).to.equal(true);
    expect(signature.length).to.equal(64); // r || s
  });

  it('identity_hash equals sha256(prefix || type || lowercase(email))', () => {
    const identityHash = joinHalves(publicInputs[PI.identityHashHi], publicInputs[PI.identityHashLo]);
    const expected = sha256(
      Buffer.from(HASH_PREFIX),
      Buffer.from([IDENTITY_TYPE_EMAIL]),
      Buffer.from('test-9988@privy.io'),
    );
    expect(identityHash).to.equal(expected);
  });

  it('wallet_hash equals sha256(prefix || wallet || lowercase(0x address))', () => {
    const walletHash = joinHalves(publicInputs[PI.walletHashHi], publicInputs[PI.walletHashLo]);
    const expected = sha256(
      Buffer.from(HASH_PREFIX),
      Buffer.from([IDENTITY_TYPE_WALLET]),
      Buffer.from(SAMPLE_WALLET.toLowerCase()),
    );
    expect(walletHash).to.equal(expected);
  });

  it('rejects a proof whose recipient was changed', async () => {
    const tampered = [...publicInputs];
    tampered[PI.recipient] = ethers.toBeHex(2n, 32);
    await expect(verifier.verify(proof, tampered)).to.be.reverted;
  });

  it('rejects a proof whose signer key was changed', async () => {
    const tampered = [...publicInputs];
    tampered[PI.signerXLo] = ethers.toBeHex(BigInt(tampered[PI.signerXLo]) ^ 1n, 32);
    await expect(verifier.verify(proof, tampered)).to.be.reverted;
  });

  it('rejects a proof whose identity hash was changed', async () => {
    const tampered = [...publicInputs];
    tampered[PI.identityHashLo] = ethers.toBeHex(BigInt(tampered[PI.identityHashLo]) ^ 1n, 32);
    await expect(verifier.verify(proof, tampered)).to.be.reverted;
  });

  it('rejects a proof with a flipped byte', async () => {
    const bytes = ethers.getBytes(proof);
    bytes[bytes.length - 1] ^= 0x01;
    await expect(verifier.verify(ethers.hexlify(bytes), publicInputs)).to.be.reverted;
  });

  it('rejects a proof of the wrong length', async () => {
    await expect(verifier.verify(proof + '00', publicInputs)).to.be.revertedWithCustomError(
      verifier,
      'ProofLengthWrongWithLogN',
    );
  });

  it('rejects the wrong number of public inputs', async () => {
    await expect(verifier.verify(proof, publicInputs.slice(0, 10))).to.be.revertedWithCustomError(
      verifier,
      'PublicInputsLengthWrong',
    );
  });
});

describe('PviumIdentity', function () {
  this.timeout(120_000);

  let verifierAddress: string;
  let proof: string;
  let publicInputs: string[];

  before(async () => {
    verifierAddress = await (await deployVerifier()).verifier.getAddress();
    proof = loadProof();
    publicInputs = loadPublicInputs();
  });

  it('stores the registered signer key raw', async () => {
    const { x, y } = sampleSignerKey();
    const gate = await deployIdentityProof(verifierAddress, x, y);
    expect(await gate.signerX()).to.equal(x);
    expect(await gate.signerY()).to.equal(y);
    expect(await gate.verifier()).to.equal(verifierAddress);
  });

  it('refuses to register a point that is not on P-256', async () => {
    const { x, y } = sampleSignerKey();
    await expect(deployIdentityProof(verifierAddress, x, y ^ 1n)).to.be.revertedWithCustomError(
      await ethers.getContractFactory('PviumIdentity'),
      'InvalidPublicKey',
    );
  });

  it('verifyAttestation: registered signer passes and decodes the claim', async () => {
    const { x, y } = sampleSignerKey();
    const gate = await deployIdentityProof(verifierAddress, x, y);
    const claim = await gate.verifyAttestation(proof, publicInputs);
    expect(claim.identityType).to.equal(BigInt(IDENTITY_TYPE_EMAIL));
    expect(claim.recipient).to.equal('0x0000000000000000000000000000000000000001');
    expect(claim.iat).to.equal(1789240094n);
    expect(claim.identityHash).to.equal(
      sha256(Buffer.from(HASH_PREFIX), Buffer.from([IDENTITY_TYPE_EMAIL]), Buffer.from('test-9988@privy.io')),
    );
    expect(claim.walletHash).to.equal(
      sha256(Buffer.from(HASH_PREFIX), Buffer.from([IDENTITY_TYPE_WALLET]), Buffer.from(SAMPLE_WALLET.toLowerCase())),
    );
    console.log(`      verifyAttestation gas: ${(await gate.verifyAttestation.estimateGas(proof, publicInputs)).toString()}`);
  });

  it('rejects a valid proof whose signer is not the registered key', async () => {
    // Register a different valid P-256 point: the generator.
    const gx = 0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296n;
    const gy = 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5n;
    const gate = await deployIdentityProof(verifierAddress, gx, gy);
    await expect(gate.verifyAttestation(proof, publicInputs)).to.be.revertedWithCustomError(gate, 'UnknownSigner');
  });

  it('rejects a tampered proof even with the right signer', async () => {
    const { x, y } = sampleSignerKey();
    const gate = await deployIdentityProof(verifierAddress, x, y);
    const bytes = ethers.getBytes(proof);
    bytes[bytes.length - 1] ^= 0x01;
    await expect(gate.verifyAttestation(ethers.hexlify(bytes), publicInputs)).to.be.reverted;
  });

  it('rejects the wrong number of public inputs', async () => {
    const { x, y } = sampleSignerKey();
    const gate = await deployIdentityProof(verifierAddress, x, y);
    await expect(gate.verifyAttestation(proof, publicInputs.slice(0, 10))).to.be.revertedWithCustomError(
      gate,
      'WrongPublicInputCount',
    );
  });
});

describe('PviumIdentity developer API', function () {
  this.timeout(120_000);

  const EMAIL = 'test-9988@privy.io';
  let gate: any;
  let proof: string;
  let publicInputs: string[];

  before(async () => {
    const verifierAddress = await (await deployVerifier()).verifier.getAddress();
    const { x, y } = sampleSignerKey();
    gate = await deployIdentityProof(verifierAddress, x, y);
    proof = loadProof();
    publicInputs = loadPublicInputs();
  });

  it('verifyIdentity(email, wallet) returns issuedAt', async () => {
    const issuedAt = await gate.verifyIdentity(proof, publicInputs, IDENTITY_TYPE_EMAIL, ethers.toUtf8Bytes(EMAIL), SAMPLE_WALLET);
    expect(issuedAt).to.equal(1789240094n);
    console.log(`      verifyIdentity gas: ${(await gate.verifyIdentity.estimateGas(proof, publicInputs, IDENTITY_TYPE_EMAIL, ethers.toUtf8Bytes(EMAIL), SAMPLE_WALLET)).toString()}`);
  });

  it('identity value and EVM wallet are case-insensitive', async () => {
    const issuedAt = await gate.verifyIdentity(proof, publicInputs, IDENTITY_TYPE_EMAIL, ethers.toUtf8Bytes('TEST-9988@Privy.IO'), SAMPLE_WALLET.toLowerCase());
    expect(issuedAt).to.equal(1789240094n);
  });

  it('verifyIdentityNonEvm accepts the wallet as a string', async () => {
    const issuedAt = await gate.verifyIdentityNonEvm(proof, publicInputs, IDENTITY_TYPE_EMAIL, ethers.toUtf8Bytes(EMAIL), SAMPLE_WALLET);
    expect(issuedAt).to.equal(1789240094n);
    await expect(gate.verifyIdentityNonEvm(proof, publicInputs, IDENTITY_TYPE_EMAIL, ethers.toUtf8Bytes(EMAIL), 'EXnVUEeELHiYynvjoQ9YhgxfMSDJC6tJm7VkFQY2b8Wj'))
      .to.be.revertedWithCustomError(gate, 'WalletMismatch');
  });

  it('verifyIdentityHashes matches the same hashing as the SDK', async () => {
    const identityHash = sha256(Buffer.from(HASH_PREFIX), Buffer.from([IDENTITY_TYPE_EMAIL]), Buffer.from(EMAIL));
    const walletHash = sha256(Buffer.from(HASH_PREFIX), Buffer.from([IDENTITY_TYPE_WALLET]), Buffer.from(SAMPLE_WALLET.toLowerCase()));
    expect(await gate.verifyIdentityHashes(proof, publicInputs, IDENTITY_TYPE_EMAIL, identityHash, walletHash)).to.equal(1789240094n);
  });

  it('rejects a wallet the proof does not bind', async () => {
    await expect(gate.verifyIdentity(proof, publicInputs, IDENTITY_TYPE_EMAIL, ethers.toUtf8Bytes(EMAIL), '0x899BA183F2c55BF9C627D9Af2984fbdED2E64311'))
      .to.be.revertedWithCustomError(gate, 'WalletMismatch');
  });

  it('rejects the wrong identity value or type', async () => {
    await expect(gate.verifyIdentity(proof, publicInputs, IDENTITY_TYPE_EMAIL, ethers.toUtf8Bytes('other@gmail.com'), SAMPLE_WALLET))
      .to.be.revertedWithCustomError(gate, 'IdentityMismatch');
    await expect(gate.verifyIdentity(proof, publicInputs, 5, ethers.toUtf8Bytes(EMAIL), SAMPLE_WALLET))
      .to.be.revertedWithCustomError(gate, 'IdentityTypeMismatch');
  });

  it('rejects a tampered proof after the cheap checks pass', async () => {
    const bytes = ethers.getBytes(proof);
    bytes[300] ^= 0x01;
    await expect(gate.verifyIdentity(ethers.hexlify(bytes), publicInputs, IDENTITY_TYPE_EMAIL, ethers.toUtf8Bytes(EMAIL), SAMPLE_WALLET)).to.be.reverted;
  });
});
