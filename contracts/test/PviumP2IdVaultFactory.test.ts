import { expect } from 'chai';
import { ethers } from 'hardhat';
import { time } from '@nomicfoundation/hardhat-network-helpers';
import { readFileSync } from 'fs';
import { join } from 'path';

const NS = ethers.id('p2id.email.v1');
const DAY = 86400;
const ID = ethers.id('identity-a');

describe('PviumP2IdVaultFactory', function () {
  let factory: any, idv: any, token: any;
  let deployer: any, payer: any, ownerWallet: any;

  const proofFor = (wallet: string, iat: number, identityHash = ID) =>
    ethers.AbiCoder.defaultAbiCoder().encode(
      ['address', 'bytes32', 'uint64'],
      [wallet, identityHash, iat],
    );

  /** Offline derivation: keccak256(0xff ‖ factory ‖ identityHash ‖ keccak256(creationCode)). */
  async function deriveOffline(identityHash: string) {
    const creationCode = (await ethers.getContractFactory('P2IDVault'))
      .bytecode;
    return ethers.getCreate2Address(
      await factory.getAddress(),
      identityHash,
      ethers.keccak256(creationCode),
    );
  }

  beforeEach(async () => {
    [deployer, payer, ownerWallet] = await ethers.getSigners();
    idv = await ethers.deployContract('MockIdentityVerifier');
    token = await ethers.deployContract('MockERC20');
    factory = await ethers.deployContract('PviumP2IdVaultFactory', [
      deployer.address,
      NS,
      await idv.getAddress(),
      7 * DAY,
      DAY,
      30 * DAY,
    ]);
  });

  it('the vault address is derivable offline from the factory address and a constant', async () => {
    expect(await factory.initCodeHash()).to.equal(
      ethers.keccak256((await ethers.getContractFactory('P2IDVault')).bytecode),
    );
    const predicted = await factory.vaultFor(ID);
    expect(predicted).to.equal(await deriveOffline(ID));
    expect(await factory.isDeployed(ID)).to.equal(false);
    await expect(factory.deploy(ID))
      .to.emit(factory, 'VaultDeployed')
      .withArgs(ID, predicted);
    expect(await factory.isDeployed(ID)).to.equal(true);
    const vault = await ethers.getContractAt('P2IDVault', predicted);
    expect(await vault.saltCommitment()).to.equal(ID);
    expect(await vault.nsHash()).to.equal(NS);
    expect(await vault.defaultVerifier()).to.equal(await idv.getAddress());
    expect(await factory.approvedVerifiers(await idv.getAddress())).to.equal(
      true,
    );
    expect(await vault.factory()).to.equal(await factory.getAddress());
    expect(await vault.minRefundWindow()).to.equal(DAY);
    expect(await vault.maxRefundWindow()).to.equal(30 * DAY);
  });

  it('the init code hash the Node SDK ships (sdks/node/src/p2id.json) matches this build', async () => {
    const sdk = JSON.parse(readFileSync(join(__dirname, '..', '..', 'sdks', 'node', 'src', 'p2id.json'), 'utf8'));
    expect(await factory.initCodeHash()).to.equal(sdk.vaultInitCodeHash, 'run: node sdks/node/scripts/embed-p2id.mjs --update');
  });

  it('deploy is idempotent and different identities get different addresses', async () => {
    const a = await factory.vaultFor(ID);
    await factory.deploy(ID);
    await expect(factory.deploy(ID)).to.not.emit(factory, 'VaultDeployed');
    expect(await factory.vaultFor(ID)).to.equal(a);
    expect(await factory.vaultFor(ethers.id('identity-b'))).to.not.equal(a);
  });

  it('initialize is factory-only and runs once', async () => {
    const loose = await ethers.deployContract('P2IDVault'); // deployer is an EOA, so it is the "factory"
    await expect(
      loose.connect(payer).initialize(NS, ID, DAY, 30 * DAY),
    ).to.be.revertedWithCustomError(loose, 'NotFactory');
    await loose.initialize(NS, ID, DAY, 30 * DAY);
    await expect(
      loose.initialize(NS, ID, DAY, 30 * DAY),
    ).to.be.revertedWithCustomError(loose, 'AlreadyInitialized');
    await factory.deploy(ID);
    const vault = await ethers.getContractAt(
      'P2IDVault',
      await factory.vaultFor(ID),
    );
    await expect(
      vault.initialize(NS, ID, DAY, 30 * DAY),
    ).to.be.revertedWithCustomError(vault, 'NotFactory');
  });

  it('funds sent before deployment are swept by the owner after deployment', async () => {
    const predicted = await factory.vaultFor(ID);
    await token.mint(predicted, 500n); // e.g. a plain transfer to the derived address
    await factory.deploy(ID);
    const vault = await ethers.getContractAt('P2IDVault', predicted);
    await vault.refreshProofAndSweep(
      await idv.getAddress(),
      proofFor(ownerWallet.address, 1000),
      await token.getAddress(),
      0,
    );
    expect(await token.balanceOf(ownerWallet.address)).to.equal(500n);
  });

  it('fund() deploys on first use, records the payer as funder, and one approval pays any identity', async () => {
    await token.mint(payer.address, 300n);
    await token.connect(payer).approve(await factory.getAddress(), 300n);
    const ID_B = ethers.id('identity-b');
    await factory
      .connect(payer)
      .fund(ID, await token.getAddress(), 100n, ethers.ZeroHash, DAY);
    await factory
      .connect(payer)
      .fund(ID_B, await token.getAddress(), 200n, ethers.ZeroHash, DAY);
    const vaultA = await ethers.getContractAt(
      'P2IDVault',
      await factory.vaultFor(ID),
    );
    const vaultB = await ethers.getContractAt(
      'P2IDVault',
      await factory.vaultFor(ID_B),
    );
    expect(await token.balanceOf(await vaultA.getAddress())).to.equal(100n);
    expect(await token.balanceOf(await vaultB.getAddress())).to.equal(200n);
    expect(await token.balanceOf(await factory.getAddress())).to.equal(0n);
    expect((await vaultA.deposits(0)).funder).to.equal(payer.address);

    // the payer, not the factory, holds the refund right
    await expect(vaultA.refund(0)).to.be.revertedWithCustomError(
      vaultA,
      'NotFunder',
    );
    await time.increase(DAY + 1);
    await vaultA.connect(payer).refund(0);
    expect(await token.balanceOf(payer.address)).to.equal(100n);
  });

  it('only the factory can call fundFor', async () => {
    await factory.deploy(ID);
    const vault = await ethers.getContractAt(
      'P2IDVault',
      await factory.vaultFor(ID),
    );
    await expect(
      vault.fundFor(
        payer.address,
        await idv.getAddress(),
        await token.getAddress(),
        1n,
        ethers.ZeroHash,
        DAY,
      ),
    ).to.be.revertedWithCustomError(vault, 'NotFactory');
  });

  it('the verifier registry is owner-managed; the default is immutable; fundWith picks a verifier', async () => {
    const idv2 = await ethers.deployContract('MockIdentityVerifier');
    const V2 = await idv2.getAddress();
    await expect(
      factory.connect(payer).approveVerifier(V2, true),
    ).to.be.revertedWithCustomError(factory, 'NotOwner');
    await expect(
      factory.approveVerifier(payer.address, true),
    ).to.be.revertedWithCustomError(factory, 'InvalidVerifier');
    await expect(factory.approveVerifier(V2, true))
      .to.emit(factory, 'VerifierApprovalSet')
      .withArgs(V2, true);
    expect(factory.setDefaultVerifier).to.equal(undefined); // no instant setter: only the timelocked proposal
    expect(await factory.defaultVerifier()).to.equal(await idv.getAddress());

    await token.mint(payer.address, 10n);
    await token.connect(payer).approve(await factory.getAddress(), 10n);
    await factory
      .connect(payer)
      .fundWith(ID, V2, await token.getAddress(), 4n, ethers.ZeroHash, DAY); // explicit opt-in
    await factory
      .connect(payer)
      .fund(ID, await token.getAddress(), 6n, ethers.ZeroHash, DAY); // default, unchanged
    const vault = await ethers.getContractAt(
      'P2IDVault',
      await factory.vaultFor(ID),
    );
    expect((await vault.deposits(0)).verifier).to.equal(V2);
    expect((await vault.deposits(1)).verifier).to.equal(await idv.getAddress());

    // two-step ownership
    await factory.transferOwnership(payer.address);
    await expect(
      factory.connect(deployer).acceptOwnership(),
    ).to.be.revertedWithCustomError(factory, 'NotPendingOwner');
    await factory.connect(payer).acceptOwnership();
    expect(await factory.owner()).to.equal(payer.address);
    await expect(
      factory.approveVerifier(V2, false),
    ).to.be.revertedWithCustomError(factory, 'NotOwner');
  });

  it('the default verifier changes only through a visible timelock', async () => {
    const idv2 = await ethers.deployContract('MockIdentityVerifier');
    const V2 = await idv2.getAddress();
    await expect(factory.proposeDefaultVerifier(V2)).to.be.revertedWithCustomError(factory, 'VerifierNotApproved');
    await factory.approveVerifier(V2, true);
    await expect(factory.activateDefaultVerifier()).to.be.revertedWithCustomError(factory, 'NothingProposed');
    await expect(factory.connect(payer).proposeDefaultVerifier(V2)).to.be.revertedWithCustomError(factory, 'NotOwner');

    const tx = await factory.proposeDefaultVerifier(V2);
    const rc = await tx.wait();
    const eta = (await ethers.provider.getBlock(rc!.blockNumber))!.timestamp + 7 * DAY;
    await expect(tx).to.emit(factory, 'DefaultVerifierProposed').withArgs(V2, eta);
    expect(await factory.proposedDefaultVerifier()).to.equal(V2);
    await expect(factory.activateDefaultVerifier()).to.be.revertedWithCustomError(factory, 'TimelockNotElapsed');
    expect(await factory.defaultVerifier()).to.equal(await idv.getAddress()); // unchanged during the delay

    // a revocation during the delay kills the proposal in effect
    await factory.approveVerifier(V2, false);
    await time.increase(7 * DAY + 1);
    await expect(factory.activateDefaultVerifier()).to.be.revertedWithCustomError(factory, 'VerifierNotApproved');
    await factory.approveVerifier(V2, true);
    await expect(factory.activateDefaultVerifier()).to.emit(factory, 'DefaultVerifierActivated').withArgs(V2);
    expect(await factory.defaultVerifier()).to.equal(V2);
    expect(await factory.proposedDefaultEta()).to.equal(0n);

    // cancel path
    await factory.proposeDefaultVerifier(await idv.getAddress());
    await expect(factory.cancelDefaultVerifierProposal()).to.emit(factory, 'DefaultVerifierProposalCancelled');
    await expect(factory.cancelDefaultVerifierProposal()).to.be.revertedWithCustomError(factory, 'NothingProposed');

    // vaults follow the factory: fund() and untracked funds now use V2, old deposits keep V
    const vault = await ethers.getContractAt('P2IDVault', await factory.deploy.staticCall(ID));
    await factory.deploy(ID);
    expect(await vault.defaultVerifier()).to.equal(V2);
  });
});
