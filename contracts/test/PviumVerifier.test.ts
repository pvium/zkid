import { expect } from 'chai';
import { ethers } from 'hardhat';
import { readFileSync } from 'fs';
import { join } from 'path';
import { deployIdentityProof, deployVerifier } from './helpers/deployVerifier';
import { createPublicKey } from 'crypto';

const NS = ethers.id('p2id.email.v1');
const DAY = 24 * 3600;
const POLICY = ethers.id('kyc:basic;sanctions:ofac;v1');
const fixtures = join(__dirname, 'fixtures');
const EMAIL_COMMITMENT = '0xbcda0f09fa9732b2bfdea38199486b654a84e8e06085d7e364af8137f8d7deaf'; // identityHash('email','test-9988@privy.io')
const LINKED_WALLET = '0xA01b6E60D51eDB3fEB9f86a62b846f4F90070f98';

function proofBytes(name: string): string {
  const proof = readFileSync(join(fixtures, `${name}.proof`));
  const raw = readFileSync(join(fixtures, `${name}.public_inputs`));
  const words: string[] = [];
  for (let i = 0; i < raw.length; i += 32) words.push('0x' + raw.subarray(i, i + 32).toString('hex'));
  return ethers.AbiCoder.defaultAbiCoder().encode(['bytes', 'bytes32[]'], [proof, words]);
}

const NO_CONSTRAINT = { commitment: ethers.ZeroHash, signature: '0x' };
const constraintOf = (commitment: string, signature = '0x') => ({ commitment, signature });

describe('PviumVerifier: real ZK proof + signed constraint commitment', function () {
  this.timeout(180_000);

  let pviumIdentity: any, verifier: any, verifierNoSigner: any, vault: any, token: any, factory: any;
  let payer: any, attester: any, stranger: any, admin: any;

  /** EIP-712 signature over Constraint(bytes32 commitment) in `v`'s domain. */
  async function signConstraint(signer: any, v: any, commitment: string, chainId?: bigint) {
    const domain = { name: 'PviumVerifier', version: '1', chainId: chainId ?? (await ethers.provider.getNetwork()).chainId, verifyingContract: await v.getAddress() };
    return signer.signTypedData(domain, { Constraint: [{ name: 'commitment', type: 'bytes32' }] }, { commitment });
  }

  before(async () => {
    [payer, attester, stranger, admin] = await ethers.getSigners();
    const honk = await (await deployVerifier()).verifier.getAddress();
    const jwk = createPublicKey(readFileSync(join(fixtures, 'privy_es256_public.pem'))).export({ format: 'jwk' });
    const x = BigInt('0x' + Buffer.from(jwk.x!, 'base64url').toString('hex'));
    const y = BigInt('0x' + Buffer.from(jwk.y!, 'base64url').toString('hex'));
    pviumIdentity = await deployIdentityProof(honk, x, y);
    verifier = await ethers.deployContract('PviumVerifier', [await pviumIdentity.getAddress(), attester.address]);
    verifierNoSigner = await ethers.deployContract('PviumVerifier', [await pviumIdentity.getAddress(), ethers.ZeroAddress]);
  });

  beforeEach(async () => {
    token = await ethers.deployContract('MockERC20');
    const policy = await ethers.deployContract('PviumP2IDPolicy', [admin.address, [await verifier.getAddress(), await verifierNoSigner.getAddress()]]);
    factory = await ethers.deployContract('PviumP2IdVaultFactory', [admin.address, NS, await policy.getAddress(), await verifier.getAddress(), 7 * DAY, DAY, 30 * DAY]);
    await factory.deploy(EMAIL_COMMITMENT);
    vault = await ethers.getContractAt('P2IDVault', await factory.vaultFor(EMAIL_COMMITMENT));
  });

  it('getIdentityWallet returns the wallet and iat for a valid proof of the expected identity', async () => {
    const [wallet, iat] = await verifier.getIdentityWallet(EMAIL_COMMITMENT, proofBytes('email'), NO_CONSTRAINT);
    expect(wallet).to.equal(LINKED_WALLET);
    expect(iat).to.equal(1789240094n);
  });

  it('a valid proof for a different identity reverts', async () => {
    await expect(verifier.getIdentityWallet(ethers.id('someone-else'), proofBytes('email'), NO_CONSTRAINT))
      .to.be.revertedWithCustomError(verifier, 'IdentityMismatch');
  });

  it('a tampered proof reverts rather than returning address(0)', async () => {
    const bad = ethers.getBytes(proofBytes('email'));
    bad[400] ^= 1;
    await expect(verifier.getIdentityWallet(EMAIL_COMMITMENT, ethers.hexlify(bad), NO_CONSTRAINT)).to.be.reverted;
  });

  it('claims a vault with a real proof and pays the wallet the proof resolves to', async () => {
    await token.mint(await vault.getAddress(), 250n);
    await expect(vault.refreshProofAndSweep(await verifier.getAddress(), proofBytes('email'), await token.getAddress(), 0))
      .to.emit(vault, 'OwnerRefreshed').withArgs(await verifier.getAddress(), LINKED_WALLET, 1789240094n);
    expect(await token.balanceOf(LINKED_WALLET)).to.equal(250n);
  });

  it('the vault rejects a valid proof for a different identity', async () => {
    await factory.deploy(ethers.id('someone-else'));
    const otherVault = await ethers.getContractAt('P2IDVault', await factory.vaultFor(ethers.id('someone-else')));
    await expect(otherVault.refreshProof(await verifier.getAddress(), proofBytes('email'))).to.be.revertedWithCustomError(verifier, 'IdentityMismatch');
  });

  it('a constrained deposit needs the proof and the registered signer over the commitment', async () => {
    const commitment = await verifier.screeningCommitment(POLICY, EMAIL_COMMITMENT);
    await token.mint(payer.address, 100n);
    await token.connect(payer).approve(await vault.getAddress(), 100n);
    await vault.connect(payer).fund(await token.getAddress(), 100n, commitment, DAY);
    await vault.refreshProofAndSweep(await verifier.getAddress(), proofBytes('email'), await token.getAddress(), 0);
    expect(await token.balanceOf(LINKED_WALLET)).to.equal(0n); // protected

    // attester signs the commitment as EIP-712 typed data in this verifier's domain
    const good = await signConstraint(attester, verifier, commitment);
    const bad = await signConstraint(stranger, verifier, commitment);
    expect(ethers.recoverAddress(await verifier.constraintDigest(commitment), good)).to.equal(attester.address);
    await expect(vault.sweepBucket(await verifier.getAddress(), constraintOf(commitment, bad), await token.getAddress(), proofBytes('email'), 0))
      .to.be.revertedWithCustomError(verifier, 'InvalidConstraintSigner');
    await expect(vault.sweepBucket(await verifier.getAddress(), constraintOf(commitment), await token.getAddress(), proofBytes('email'), 0))
      .to.be.revertedWithCustomError(verifier, 'MalformedSignature');
    await expect(vault.sweepBucket(await verifier.getAddress(), constraintOf(ethers.id('other-commitment'), good), await token.getAddress(), proofBytes('email'), 0))
      .to.be.revertedWithCustomError(verifier, 'InvalidConstraintSigner'); // signature is over a different commitment

    await vault.connect(stranger).sweepBucket(await verifier.getAddress(), constraintOf(commitment, good), await token.getAddress(), proofBytes('email'), 0);
    expect(await token.balanceOf(LINKED_WALLET)).to.equal(100n);
  });

  it('a constraint signature is bound to the chain and the verifier', async () => {
    const commitment = await verifier.screeningCommitment(POLICY, EMAIL_COMMITMENT);
    const otherChain = await signConstraint(attester, verifier, commitment, 8453n);
    await expect(verifier.getIdentityWallet(EMAIL_COMMITMENT, proofBytes('email'), constraintOf(commitment, otherChain)))
      .to.be.revertedWithCustomError(verifier, 'InvalidConstraintSigner');
    const otherVerifier = await ethers.deployContract('PviumVerifier', [await pviumIdentity.getAddress(), attester.address]);
    const forOther = await signConstraint(attester, otherVerifier, commitment);
    await expect(verifier.getIdentityWallet(EMAIL_COMMITMENT, proofBytes('email'), constraintOf(commitment, forOther)))
      .to.be.revertedWithCustomError(verifier, 'InvalidConstraintSigner');
    const personalSign = await attester.signMessage(ethers.getBytes(commitment)); // the old scheme
    await expect(verifier.getIdentityWallet(EMAIL_COMMITMENT, proofBytes('email'), constraintOf(commitment, personalSign)))
      .to.be.revertedWithCustomError(verifier, 'InvalidConstraintSigner');
  });

  it('the constraint signer is immutable: a new attester is a new verifier deployment', async () => {
    expect((verifier as any).setConstraintSigner).to.equal(undefined);
    expect(await verifier.constraintSigner()).to.equal(attester.address);
  });

  it('supportsConstraints reflects whether an attester is set, and a vault refuses constrained deposits otherwise', async () => {
    expect(await verifier.supportsConstraints()).to.equal(true);
    expect(await verifierNoSigner.supportsConstraints()).to.equal(false);
    await token.mint(payer.address, 10n);
    await token.connect(payer).approve(await vault.getAddress(), 10n);
    const commitment = await verifier.screeningCommitment(POLICY, EMAIL_COMMITMENT);
    await expect(vault.connect(payer).fundWith(await verifierNoSigner.getAddress(), await token.getAddress(), 10n, commitment, DAY))
      .to.be.revertedWithCustomError(vault, 'ConstraintsUnsupported');
    await vault.connect(payer).fundWith(await verifierNoSigner.getAddress(), await token.getAddress(), 10n, ethers.ZeroHash, DAY); // unconstrained is fine
  });

  it('a verifier without a constraint signer refuses constrained sweeps but still proves identity', async () => {
    const [wallet] = await verifierNoSigner.getIdentityWallet(EMAIL_COMMITMENT, proofBytes('email'), NO_CONSTRAINT);
    expect(wallet).to.equal(LINKED_WALLET);
    await expect(verifierNoSigner.getIdentityWallet(EMAIL_COMMITMENT, proofBytes('email'), constraintOf(ethers.id('c'))))
      .to.be.revertedWithCustomError(verifierNoSigner, 'ConstraintsUnsupported');
  });
});
