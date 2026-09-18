import { expect } from 'chai';
import { ethers } from 'hardhat';
import { time } from '@nomicfoundation/hardhat-network-helpers';

const NS = ethers.id('p2id.vault.v1');
const ID = ethers.id('identity');
const DAY = 24 * 3600;
const Z = ethers.ZeroHash;

/**
 * Fees and gating come from the factory's policy; the vault bounds what any policy can do.
 * These tests use a policy whose rate, recipient and failure modes can be changed at will.
 */
describe('P2IDVault fees and policy limits', function () {
  let factory: any, policy: any, vault: any, token: any, idv: any, V: string;
  let deployer: any, payer: any, ownerWallet: any, treasury: any, operator: any;

  const proofFor = (wallet: string, iat: number) =>
    ethers.AbiCoder.defaultAbiCoder().encode(['address', 'bytes32', 'uint64'], [wallet, ID, iat]);
  const OK = ethers.hexlify(ethers.toUtf8Bytes('ok'));

  async function fund(amount: bigint, constraint = Z, verifier = V) {
    await token.mint(payer.address, amount);
    await token.connect(payer).approve(await vault.getAddress(), amount);
    const rc = await (await vault.connect(payer).fundWith(verifier, await token.getAddress(), amount, constraint, DAY)).wait();
    const ev = rc!.logs.map((l: any) => { try { return vault.interface.parseLog(l); } catch { return null; } }).find((e: any) => e?.name === 'Funded');
    return Number(ev.args.depositId);
  }

  beforeEach(async () => {
    [deployer, payer, ownerWallet, treasury, operator] = await ethers.getSigners();
    idv = await ethers.deployContract('MockIdentityVerifier');
    V = await idv.getAddress();
    token = await ethers.deployContract('MockERC20');
    policy = await ethers.deployContract('MockFeePolicy');
    await policy.allow(V, true);
    factory = await ethers.deployContract('PviumP2IdVaultFactory', [deployer.address, NS, await policy.getAddress(), V, 7 * DAY, DAY, 30 * DAY]);
    await factory.deploy(ID);
    vault = await ethers.getContractAt('P2IDVault', await factory.vaultFor(ID));
  });

  it('a fee is taken on claim at the rate fixed when the deposit was made, accrues per verifier, and the policy distributes it', async () => {
    await policy.setFee(50, treasury.address); // 0.5%
    const d = await fund(10_000n);
    expect((await vault.deposits(d)).feeBps).to.equal(50n);

    await policy.setFee(100, treasury.address); // raised later: must not re-price the deposit
    await expect(vault.refreshProofAndSweep(V, proofFor(ownerWallet.address, 1000), await token.getAddress(), 0))
      .to.emit(vault, 'Claimed').withArgs(d, ownerWallet.address, 10_000n, 50n)
      .and.to.emit(vault, 'FeeAccrued').withArgs(V, await token.getAddress(), 50n)
      .and.to.emit(vault, 'Swept').withArgs(V, await token.getAddress(), 9_950n, 50n, ownerWallet.address, 1n);
    expect(await token.balanceOf(ownerWallet.address)).to.equal(9_950n);
    expect(await vault.feesOwed(V, await token.getAddress())).to.equal(50n);
    expect(await vault.feesOwedTotal(await token.getAddress())).to.equal(50n);

    // anyone can hand accrued fees to the policy; the policy pulls them and decides where they go
    await expect(vault.connect(payer).withdrawFees(V, await token.getAddress()))
      .to.emit(vault, 'FeesDistributed').withArgs(V, await token.getAddress(), 50n, await policy.getAddress());
    expect(await token.balanceOf(treasury.address)).to.equal(50n);
    expect(await vault.feesOwedTotal(await token.getAddress())).to.equal(0n);
    expect(await token.allowance(await vault.getAddress(), await policy.getAddress())).to.equal(0n);
    expect(await vault.connect(payer).withdrawFees.staticCall(V, await token.getAddress())).to.equal(0n);
  });

  it('no policy can charge more than MAX_FEE_BPS (1%)', async () => {
    expect(await vault.MAX_FEE_BPS()).to.equal(100n);
    await policy.setFee(5_000, treasury.address); // asks for 50%
    const d = await fund(10_000n);
    expect((await vault.deposits(d)).feeBps).to.equal(100n);
    await token.mint(await vault.getAddress(), 1_000n); // bare transfer, quoted at sweep time: capped too
    await vault.refreshProofAndSweep(V, proofFor(ownerWallet.address, 1000), await token.getAddress(), 0);
    expect(await token.balanceOf(ownerWallet.address)).to.equal(10_890n); // 11_000 - 1%
    expect(await vault.feesOwed(V, await token.getAddress())).to.equal(110n);
  });

  it('refunds never pay a fee', async () => {
    await policy.setFee(100, treasury.address);
    const d = await fund(10_000n);
    await time.increase(DAY + 1);
    await vault.connect(payer).refund(d);
    expect(await token.balanceOf(payer.address)).to.equal(10_000n);
    expect(await vault.feesOwedTotal(await token.getAddress())).to.equal(0n);
  });

  it('a failing policy can never block a claim: a failed quote means no fee, and payouts never ask the policy', async () => {
    await policy.setFee(100, treasury.address);
    await policy.setMode(1); // fee queries revert
    const reverted = await fund(1_000n);
    expect((await vault.deposits(reverted)).feeBps).to.equal(0n);
    await policy.setMode(2); // fee queries burn all gas they are given
    const gasBomb = await fund(1_000n);
    expect((await vault.deposits(gasBomb)).feeBps).to.equal(0n);

    await policy.setMode(0);
    const priced = await fund(1_000n); // quoted normally: 1%
    await policy.setMode(3); // distribution is broken too
    await vault.refreshProofAndSweep(V, proofFor(ownerWallet.address, 1000), await token.getAddress(), 0);
    expect(await token.balanceOf(ownerWallet.address)).to.equal(2_990n); // claim unaffected
    expect((await vault.deposits(priced)).feeBps).to.equal(100n);
    expect(await vault.feesOwed(V, await token.getAddress())).to.equal(10n);
  });

  it('the policy splits fees as it chooses, e.g. between a verifier operator and the protocol', async () => {
    await policy.setFee(100, treasury.address);
    await policy.setOperator(V, operator.address, 7_000); // 70% to the verifier's operator
    await fund(100_000n);
    await vault.refreshProofAndSweep(V, proofFor(ownerWallet.address, 1000), await token.getAddress(), 0);
    await vault.withdrawFees(V, await token.getAddress());
    expect(await token.balanceOf(operator.address)).to.equal(700n);
    expect(await token.balanceOf(treasury.address)).to.equal(300n);
  });

  it('distribution cannot take more than is owed, and what it does not take stays accrued', async () => {
    await policy.setFee(100, treasury.address);
    await fund(10_000n);
    await vault.refreshProofAndSweep(V, proofFor(ownerWallet.address, 1000), await token.getAddress(), 0);

    await policy.setMode(3); // distribution reverts: nothing moves
    await expect(vault.withdrawFees(V, await token.getAddress())).to.be.reverted;
    expect(await vault.feesOwed(V, await token.getAddress())).to.equal(100n);
    await policy.setMode(4); // tries to pull more than it was approved for
    await expect(vault.withdrawFees(V, await token.getAddress())).to.be.reverted;
    expect(await vault.feesOwed(V, await token.getAddress())).to.equal(100n);

    await policy.setMode(0);
    await policy.setPullBps(4_000); // takes only 40%
    await expect(vault.withdrawFees(V, await token.getAddress()))
      .to.emit(vault, 'FeesDistributed').withArgs(V, await token.getAddress(), 40n, await policy.getAddress());
    expect(await vault.feesOwed(V, await token.getAddress())).to.equal(60n);
    expect(await token.allowance(await vault.getAddress(), await policy.getAddress())).to.equal(0n); // reset
    expect(await vault.untrackedBalance(await token.getAddress())).to.equal(0n); // the rest is still held apart
  });

  it('under the launch policy no fee accrues, so there is never anything to distribute', async () => {
    const launch = await ethers.deployContract('PviumP2IDPolicy', [deployer.address, [V]]);
    const f = await ethers.deployContract('PviumP2IdVaultFactory', [deployer.address, NS, await launch.getAddress(), V, 7 * DAY, DAY, 30 * DAY]);
    await f.deploy(ID);
    const v = await ethers.getContractAt('P2IDVault', await f.vaultFor(ID));
    await token.mint(payer.address, 1_000n);
    await token.connect(payer).approve(await v.getAddress(), 1_000n);
    await v.connect(payer).fund(await token.getAddress(), 1_000n, Z, DAY);
    await v.refreshProofAndSweep(V, proofFor(ownerWallet.address, 1000), await token.getAddress(), 0);
    expect(await token.balanceOf(ownerWallet.address)).to.equal(1_000n);
    expect(await v.feesOwedTotal(await token.getAddress())).to.equal(0n);
    expect(await v.withdrawFees.staticCall(V, await token.getAddress())).to.equal(0n); // returns before calling the policy
    await expect(launch.distributeFee(V, await token.getAddress(), 1n)).to.be.revertedWithCustomError(launch, 'NoFees');
  });

  it('accrued fees are held apart: never counted as untracked funds, never paid out again', async () => {
    await policy.setFee(100, treasury.address);
    await fund(10_000n);
    await vault.refreshProofAndSweep(V, proofFor(ownerWallet.address, 1000), await token.getAddress(), 0);
    expect(await token.balanceOf(await vault.getAddress())).to.equal(100n); // the fee, still held
    expect(await vault.untrackedBalance(await token.getAddress())).to.equal(0n);
    await vault.sweepUntracked(await token.getAddress());
    expect(await token.balanceOf(ownerWallet.address)).to.equal(9_900n);
    await token.mint(await vault.getAddress(), 500n);
    expect(await vault.untrackedBalance(await token.getAddress())).to.equal(500n);
  });

  it('constrained buckets are charged too, at each deposit\'s own rate', async () => {
    const c = ethers.id('screened');
    await policy.setFee(20, treasury.address);
    const a = await fund(5_000n, c);
    await policy.setFee(80, treasury.address);
    const b = await fund(5_000n, c);
    await expect(vault.sweepBucket(V, { commitment: c, signature: OK }, await token.getAddress(), proofFor(ownerWallet.address, 1000), 0))
      .to.emit(vault, 'Claimed').withArgs(a, ownerWallet.address, 5_000n, 10n)
      .and.to.emit(vault, 'Claimed').withArgs(b, ownerWallet.address, 5_000n, 40n);
    expect(await token.balanceOf(ownerWallet.address)).to.equal(9_950n);
  });

  it('a constrained deposit is refused under a verifier that cannot satisfy constraints', async () => {
    const none = await ethers.deployContract('MockNoConstraintVerifier');
    await policy.allow(await none.getAddress(), true);
    await token.mint(payer.address, 10n);
    await token.connect(payer).approve(await vault.getAddress(), 10n);
    await expect(vault.connect(payer).fundWith(await none.getAddress(), await token.getAddress(), 10n, ethers.id('c'), DAY))
      .to.be.revertedWithCustomError(vault, 'ConstraintsUnsupported').withArgs(await none.getAddress());
    // a contract that is not a verifier at all does not say it supports constraints either
    await policy.allow(await token.getAddress(), true);
    await expect(vault.connect(payer).fundWith(await token.getAddress(), await token.getAddress(), 10n, ethers.id('c'), DAY))
      .to.be.revertedWithCustomError(vault, 'ConstraintsUnsupported');
  });

  it('gating is the one thing a policy controls outright: disallowing freezes claims, refunds still work', async () => {
    const d = await fund(1_000n);
    await vault.refreshProof(V, proofFor(ownerWallet.address, 1000));
    await policy.allow(V, false);
    await expect(vault.sweep(V, await token.getAddress(), 0)).to.be.revertedWithCustomError(vault, 'VerifierNotApproved');
    await time.increase(DAY + 1);
    await vault.connect(payer).refund(d);
    expect(await token.balanceOf(payer.address)).to.equal(1_000n);
  });
});
