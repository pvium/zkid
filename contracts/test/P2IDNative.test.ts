import { expect } from 'chai';
import { ethers } from 'hardhat';
import { time } from '@nomicfoundation/hardhat-network-helpers';

const NS = ethers.id('p2id.vault.v1');
const ID = ethers.id('native-identity');
const DAY = 24 * 3600;
const Z = ethers.ZeroHash;
const NATIVE = ethers.ZeroAddress;
const bnb = (v: string) => ethers.parseEther(v);

/**
 * The native coin is the token address(0) everywhere in the vault: BNB on BNB Chain, ETH on Base,
 * the same bytecode on every chain. (Amounts below are written as BNB; on Base they are ETH.)
 */
describe('P2IDVault native coin (BNB on BNB Chain, ETH on Base)', function () {
  let factory: any, policy: any, vault: any, idv: any, V: string;
  let deployer: any, payer: any, ownerWallet: any, treasury: any;

  const proofFor = (wallet: string, iat: number) =>
    ethers.AbiCoder.defaultAbiCoder().encode(['address', 'bytes32', 'uint64'], [wallet, ID, iat]);
  const OK = ethers.hexlify(ethers.toUtf8Bytes('ok'));
  const balance = (a: string) => ethers.provider.getBalance(a);

  beforeEach(async () => {
    [deployer, payer, ownerWallet, treasury] = await ethers.getSigners();
    idv = await ethers.deployContract('MockIdentityVerifier');
    V = await idv.getAddress();
    policy = await ethers.deployContract('MockFeePolicy');
    await policy.allow(V, true);
    factory = await ethers.deployContract('PviumP2IdVaultFactory', [deployer.address, NS, await policy.getAddress(), V, 7 * DAY, DAY, 30 * DAY]);
  });

  async function deployVault() {
    await factory.deploy(ID);
    vault = await ethers.getContractAt('P2IDVault', await factory.vaultFor(ID));
    return vault;
  }

  it('BNB sent to a P2ID before its vault exists is claimable once it is deployed', async () => {
    const addr = await factory.vaultFor(ID);
    await payer.sendTransaction({ to: addr, value: bnb('1') }); // e.g. a launchpad paying creator fees
    await deployVault();
    expect(await vault.NATIVE()).to.equal(NATIVE);
    expect(await vault.untrackedBalance(NATIVE)).to.equal(bnb('1'));
    const before = await balance(ownerWallet.address);
    await vault.connect(payer).refreshProofAndSweep(V, proofFor(ownerWallet.address, 1000), NATIVE, 0);
    expect((await balance(ownerWallet.address)) - before).to.equal(bnb('1'));
    expect(await balance(await vault.getAddress())).to.equal(0n);
  });

  it('plain BNB sends to a deployed vault are accepted (even with the 2300-gas transfer stipend) and swept', async () => {
    await deployVault();
    await payer.sendTransaction({ to: await vault.getAddress(), value: bnb('0.3') });
    // Solidity's `transfer` forwards only 2300 gas: the vault's receive must still accept it.
    const sender = await ethers.deployContract('MockNativeSender');
    await sender.send(await vault.getAddress(), { value: bnb('0.2') });
    expect(await vault.untrackedBalance(NATIVE)).to.equal(bnb('0.5'));
    await vault.refreshProof(V, proofFor(ownerWallet.address, 1000));
    const before = await balance(ownerWallet.address);
    await vault.connect(payer).sweepUntracked(NATIVE);
    expect((await balance(ownerWallet.address)) - before).to.equal(bnb('0.5'));
  });

  it('fund() is payable for BNB: exact value, recorded funder, refundable in BNB', async () => {
    await deployVault();
    await expect(vault.connect(payer).fund(NATIVE, bnb('1'), Z, DAY, { value: bnb('0.9') }))
      .to.be.revertedWithCustomError(vault, 'NativeValueMismatch');
    await expect(vault.connect(payer).fund(NATIVE, bnb('1'), Z, DAY))
      .to.be.revertedWithCustomError(vault, 'NativeValueMismatch');
    await expect(vault.connect(payer).fund(NATIVE, bnb('1'), Z, DAY, { value: bnb('1') }))
      .to.emit(vault, 'Funded').withArgs(0, payer.address, NATIVE, bnb('1'), V, Z, DAY, 0);
    expect(await vault.trackedTotal(NATIVE)).to.equal(bnb('1'));
    expect(await vault.untrackedBalance(NATIVE)).to.equal(0n);

    await time.increase(DAY + 1);
    const before = await balance(payer.address);
    const rc = await (await vault.connect(payer).refund(0)).wait();
    const gas = rc!.gasUsed * rc!.gasPrice;
    expect((await balance(payer.address)) - before + gas).to.equal(bnb('1'));
    expect(await vault.trackedTotal(NATIVE)).to.equal(0n);
  });

  it('an ERC-20 deposit that also sends BNB is refused, so BNB can never be stranded on it', async () => {
    await deployVault();
    const token = await ethers.deployContract('MockERC20');
    await token.mint(payer.address, 10n);
    await token.connect(payer).approve(await vault.getAddress(), 10n);
    await expect(vault.connect(payer).fund(await token.getAddress(), 10n, Z, DAY, { value: 1n }))
      .to.be.revertedWithCustomError(vault, 'NativeValueMismatch');
  });

  it('BNB deposits are claimed like tokens: default bucket to the owner, constrained bucket through the proof', async () => {
    await deployVault();
    await vault.connect(payer).fund(NATIVE, bnb('0.4'), Z, DAY, { value: bnb('0.4') });
    const c = ethers.id('screened');
    await vault.connect(payer).fund(NATIVE, bnb('0.6'), c, DAY, { value: bnb('0.6') });
    await payer.sendTransaction({ to: await vault.getAddress(), value: bnb('0.1') }); // direct transfer

    const before = await balance(ownerWallet.address);
    await vault.connect(payer).refreshProofAndSweep(V, proofFor(ownerWallet.address, 1000), NATIVE, 0);
    expect((await balance(ownerWallet.address)) - before).to.equal(bnb('0.5')); // default deposit + direct transfer
    expect(await balance(await vault.getAddress())).to.equal(bnb('0.6')); // constrained stays

    await vault.connect(payer).sweepBucket(V, { commitment: c, signature: OK }, NATIVE, proofFor(ownerWallet.address, 1000), 0);
    expect((await balance(ownerWallet.address)) - before).to.equal(bnb('1.1'));
    expect(await balance(await vault.getAddress())).to.equal(0n);
  });

  it('the factory funds in BNB on the payer\'s behalf, deploying the vault on first use', async () => {
    const addr = await factory.vaultFor(ID);
    await expect(factory.connect(payer).fund(ID, NATIVE, bnb('2'), Z, DAY, { value: bnb('1') }))
      .to.be.revertedWithCustomError(await ethers.getContractFactory('P2IDVault'), 'NativeValueMismatch');
    await factory.connect(payer).fund(ID, NATIVE, bnb('2'), Z, DAY, { value: bnb('2') });
    vault = await ethers.getContractAt('P2IDVault', addr);
    expect((await vault.deposits(0)).funder).to.equal(payer.address);
    expect((await vault.deposits(0)).token).to.equal(NATIVE);
    expect(await balance(addr)).to.equal(bnb('2'));
    expect(await balance(await factory.getAddress())).to.equal(0n);

    const token = await ethers.deployContract('MockERC20');
    await expect(factory.connect(payer).fund(ID, await token.getAddress(), 1n, Z, DAY, { value: 1n }))
      .to.be.revertedWithCustomError(factory, 'UnexpectedValue');
  });

  it('fees in BNB accrue at the deposit\'s rate and are sent to the policy to distribute', async () => {
    await policy.setFee(100, treasury.address); // 1%
    await deployVault();
    await vault.connect(payer).fund(NATIVE, bnb('10'), Z, DAY, { value: bnb('10') });
    const before = await balance(ownerWallet.address);
    await vault.connect(payer).refreshProofAndSweep(V, proofFor(ownerWallet.address, 1000), NATIVE, 0);
    expect((await balance(ownerWallet.address)) - before).to.equal(bnb('9.9'));
    expect(await vault.feesOwed(V, NATIVE)).to.equal(bnb('0.1'));
    expect(await vault.untrackedBalance(NATIVE)).to.equal(0n); // held apart

    const t0 = await balance(treasury.address);
    await expect(vault.connect(payer).withdrawFees(V, NATIVE))
      .to.emit(vault, 'FeesDistributed').withArgs(V, NATIVE, bnb('0.1'), await policy.getAddress());
    expect((await balance(treasury.address)) - t0).to.equal(bnb('0.1'));
    expect(await balance(await vault.getAddress())).to.equal(0n);

    // a failing distribution moves nothing
    await vault.connect(payer).fund(NATIVE, bnb('1'), Z, DAY, { value: bnb('1') });
    await vault.connect(payer).sweep(V, NATIVE, 0);
    await policy.setMode(3);
    await expect(vault.withdrawFees(V, NATIVE)).to.be.reverted;
    expect(await vault.feesOwed(V, NATIVE)).to.equal(bnb('0.01'));
  });

  it('an owner wallet that re-enters on receiving BNB cannot double-claim', async () => {
    await deployVault();
    const wallet = await ethers.deployContract('MockReentrantWallet');
    await payer.sendTransaction({ to: await vault.getAddress(), value: bnb('1') });
    await vault.refreshProof(V, proofFor(await wallet.getAddress(), 1000));
    await wallet.arm(await vault.getAddress(), vault.interface.encodeFunctionData('sweepUntracked', [NATIVE]));
    // The re-entry hits the lock, so the wallet's receive reverts and so does the whole payout.
    await expect(vault.sweepUntracked(NATIVE)).to.be.revertedWithCustomError(vault, 'NativeTransferFailed');
    expect(await balance(await vault.getAddress())).to.equal(bnb('1')); // nothing left the vault
    await wallet.arm(ethers.ZeroAddress, '0x'); // once it stops re-entering, it is paid normally
    await vault.sweepUntracked(NATIVE);
    expect(await balance(await wallet.getAddress())).to.equal(bnb('1'));
  });

  it('a wallet that rejects BNB only blocks its own payout; the owner can move to another wallet', async () => {
    await deployVault();
    const rejecting = await ethers.deployContract('MockIdentityVerifier'); // no receive(): rejects BNB
    await payer.sendTransaction({ to: await vault.getAddress(), value: bnb('1') });
    await vault.refreshProof(V, proofFor(await rejecting.getAddress(), 1000));
    await expect(vault.sweepUntracked(NATIVE)).to.be.revertedWithCustomError(vault, 'NativeTransferFailed');
    await vault.refreshProof(V, proofFor(ownerWallet.address, 2000));
    const before = await balance(ownerWallet.address);
    await vault.connect(payer).sweepUntracked(NATIVE);
    expect((await balance(ownerWallet.address)) - before).to.equal(bnb('1'));
  });
});
