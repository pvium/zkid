import { expect } from 'chai';
import { ethers, network } from 'hardhat';
import { time } from '@nomicfoundation/hardhat-network-helpers';

// Audit findings (see AUDIT.md). Finding 1 is fixed and asserted as a regression; findings 2 and 3
// are documented trust and token assumptions, reproduced here so any change to them is noticed.
describe('P2IDVault audit findings', function () {
  const identity = ethers.id('audit-identity');
  const day = 86400;
  const proof = (wallet: string, iat: number) => ethers.AbiCoder.defaultAbiCoder()
    .encode(['address', 'bytes32', 'uint64'], [wallet, identity, iat]);

  async function setup() {
    const [admin, payer, oldWallet, newWallet] = await ethers.getSigners();
    const v1 = await ethers.deployContract('MockIdentityVerifier');
    const v2 = await ethers.deployContract('MockIdentityVerifier');
    const a1 = await v1.getAddress(), a2 = await v2.getAddress();
    const policy = await ethers.deployContract('PviumP2IDPolicy', [admin.address, [a1, a2]]);
    const factory = await ethers.deployContract('PviumP2IdVaultFactory', [
      admin.address, ethers.id('audit'), await policy.getAddress(), a1, day, day, 30 * day,
    ]);
    await factory.deploy(identity);
    const vault = await ethers.getContractAt('P2IDVault', await factory.vaultFor(identity));
    const token = await ethers.deployContract('MockERC20');
    return { admin, payer, oldWallet, newWallet, a1, a2, policy, factory, vault, token };
  }

  it('fixed (finding 1): switching defaults cannot reactivate an older wallet for direct transfers', async () => {
    const { oldWallet, newWallet, a1, a2, factory, vault, token } = await setup();
    // Model two legitimate verifiers accepting proofs from overlapping signing-key sets.
    await vault.refreshProof(a2, proof(oldWallet.address, 1000));
    await vault.refreshProof(a1, proof(oldWallet.address, 1000));
    await vault.refreshProof(a1, proof(newWallet.address, 2000)); // owner moves wallets under the default
    expect(await vault.untrackedProofIat()).to.equal(2000n);
    await expect(vault.refreshProof(a1, proof(oldWallet.address, 1000)))
      .to.be.revertedWithCustomError(vault, 'ProofTooOld');
    await token.mint(await vault.getAddress(), 100n);
    await factory.proposeDefaultVerifier(a2);
    await time.increase(14 * day);
    await factory.activateDefaultVerifier();

    // B still records the old wallet (iat 1000 < 2000): direct transfers are not paid to it,
    // and presenting the old proof again under B does not help either.
    await expect(vault.sweepUntracked(await token.getAddress())).to.be.revertedWithCustomError(vault, 'ProofTooOld');
    await vault.refreshProof(a2, proof(oldWallet.address, 1000));
    await expect(vault.sweepUntracked(await token.getAddress())).to.be.revertedWithCustomError(vault, 'ProofTooOld');
    expect(await vault.sweepable(a2, await token.getAddress())).to.equal(0n);
    await vault.sweep(a2, await token.getAddress(), 0); // B's own deposits (none) only; direct transfers stay
    expect(await token.balanceOf(oldWallet.address)).to.equal(0n);

    // The owner proves under the new default with a fresh token: direct transfers follow.
    await vault.refreshProof(a2, proof(newWallet.address, 3000));
    await vault.sweepUntracked(await token.getAddress());
    expect(await token.balanceOf(newWallet.address)).to.equal(100n);
    expect(await token.balanceOf(oldWallet.address)).to.equal(0n);
  });

  it('a verifier payers merely opted into cannot raise the direct-transfer floor', async () => {
    const { newWallet, a1, a2, vault, token } = await setup();
    await vault.refreshProof(a1, proof(newWallet.address, 2000)); // a1 is the default
    await vault.refreshProof(a2, proof(newWallet.address, 9_999_999_999)); // not the default: ignored for the floor
    expect(await vault.untrackedProofIat()).to.equal(2000n);
    await token.mint(await vault.getAddress(), 5n);
    await vault.sweepUntracked(await token.getAddress());
    expect(await token.balanceOf(newWallet.address)).to.equal(5n);
  });

  it('trust assumption (finding 2): after 14 days\' public notice, governance can route direct transfers through a verifier it chose', async () => {
    const { admin, newWallet, a1, a2, factory, vault, token } = await setup();
    await vault.refreshProof(a1, proof(newWallet.address, 2000));
    await token.mint(await vault.getAddress(), 100n);
    // The mock stands in for a governance-approved malicious verifier, not a forged ZK proof.
    await vault.refreshProof(a2, proof(admin.address, 3000));
    await factory.proposeDefaultVerifier(a2);
    await time.increase(13 * day);
    await expect(factory.activateDefaultVerifier()).to.be.revertedWithCustomError(factory, 'TimelockNotElapsed');
    // during the notice the owner can still sweep; here nobody does, so the change applies
    await time.increase(day);
    await factory.activateDefaultVerifier();
    await vault.sweepUntracked(await token.getAddress());
    expect(await token.balanceOf(admin.address)).to.equal(100n);
  });

  it('during the notice the identity owner can always sweep first', async () => {
    const { admin, newWallet, a1, a2, factory, vault, token } = await setup();
    await vault.refreshProof(a1, proof(newWallet.address, 2000));
    await token.mint(await vault.getAddress(), 100n);
    await vault.refreshProof(a2, proof(admin.address, 3000));
    await factory.proposeDefaultVerifier(a2);
    await vault.sweepUntracked(await token.getAddress()); // owner objects and leaves
    expect(await token.balanceOf(newWallet.address)).to.equal(100n);
  });

  it('fixed (finding 2, freeze): the policy cannot freeze claims through the current default verifier', async () => {
    const { payer, newWallet, a1, policy, vault, token } = await setup();
    await vault.refreshProof(a1, proof(newWallet.address, 2000));
    await token.mint(await vault.getAddress(), 100n);
    await policy.approveVerifier(a1, false); // revoking the default
    // claims through it continue: direct transfers, proofs, and its default bucket
    await vault.refreshProof(a1, proof(newWallet.address, 2500));
    await vault.sweepUntracked(await token.getAddress());
    expect(await token.balanceOf(newWallet.address)).to.equal(100n);
    // but it takes no new deposits while revoked
    await token.mint(payer.address, 10n);
    await token.connect(payer).approve(await vault.getAddress(), 10n);
    await expect(vault.connect(payer).fund(await token.getAddress(), 10n, ethers.ZeroHash, day))
      .to.be.revertedWithCustomError(vault, 'VerifierNotApproved');
  });

  it('token assumption (finding 3): a balance contraction leaves later deposit refunds underfunded', async () => {
    const { payer, oldWallet, token, vault } = await setup();
    const vaultAddress = await vault.getAddress(), tokenAddress = await token.getAddress();
    for (const signer of [payer, oldWallet]) {
      await token.mint(signer.address, 100n);
      await token.connect(signer).approve(vaultAddress, 100n);
      await vault.connect(signer).fund(tokenAddress, 100n, ethers.ZeroHash, day);
    }
    // MockERC20.balanceOf is at slot 3. Model an external negative rebase/balance confiscation.
    const slot = ethers.keccak256(ethers.AbiCoder.defaultAbiCoder()
      .encode(['address', 'uint256'], [vaultAddress, 3]));
    expect(await token.balanceOf(vaultAddress)).to.equal(200n);
    await network.provider.send('hardhat_setStorageAt', [
      tokenAddress, slot, ethers.zeroPadValue(ethers.toBeHex(150), 32),
    ]);
    expect(await token.balanceOf(vaultAddress)).to.equal(150n);
    expect(await vault.trackedTotal(tokenAddress)).to.equal(200n);
    await time.increase(day + 1);
    await vault.connect(payer).refund(0);
    expect(await token.balanceOf(vaultAddress)).to.equal(50n);
    await expect(vault.connect(oldWallet).refund(1))
      .to.be.revertedWithCustomError(vault, 'TokenCallFailed');
    expect((await vault.deposits(1)).consumed).to.equal(false);
  });
});
