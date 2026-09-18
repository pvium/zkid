import { expect } from 'chai';
import { ethers, network } from 'hardhat';
import { createPublicKey } from 'crypto';
import { readFileSync } from 'fs';
import { join } from 'path';
import { deployDeterministic, deployStack, ensureDeterministicDeployer, predictStack, stackStatus, type StackParams } from '../scripts/lib/deterministic';

const DAY = 24 * 3600;
const EMAIL_COMMITMENT = '0xbcda0f09fa9732b2bfdea38199486b654a84e8e06085d7e364af8137f8d7deaf';
// A second valid P-256 point (the generator), standing in for the other key a Privy JWKS lists.
const GX = 0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296n;
const GY = 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5n;

describe('Deterministic deployment: chain-agnostic P2ID addresses', function () {
  this.timeout(120_000);

  async function params(): Promise<StackParams> {
    const jwk = createPublicKey(readFileSync(join(__dirname, 'fixtures', 'privy_es256_public.pem'))).export({ format: 'jwk' });
    return {
      owner: '0x00000000000000000000000000000000000A11CE',
      scheme: 'p2id.vault.v1',
      circuitVersion: 2,
      signerKeys: [
        { x: BigInt('0x' + Buffer.from(jwk.x!, 'base64url').toString('hex')), y: BigInt('0x' + Buffer.from(jwk.y!, 'base64url').toString('hex')) },
        { x: GX, y: GY },
      ],
      attester: '0x0000000000000000000000000000000000000A77',
      defaultChangeDelay: 7 * DAY,
      minRefundWindow: DAY,
      maxRefundWindow: 90 * DAY,
    };
  }

  it('the whole stack, and so every vault, lands at the same address whoever deploys it and on whatever chain', async () => {
    const [a, b] = await ethers.getSigners();
    const snapshot = await network.provider.send('evm_snapshot');
    const predicted = await predictStack(await params()); // offline: nothing deployed yet
    expect(await ethers.provider.getCode(predicted.factory)).to.equal('0x');
    const first = await deployStack(await params(), a);
    expect(first).to.deep.equal(predicted);
    const factory1 = await ethers.getContractAt('PviumP2IdVaultFactory', first.factory);
    const vault1 = await factory1.vaultFor(EMAIL_COMMITMENT);

    // "Another chain": wipe the state, and deploy from a different account with a different nonce.
    await network.provider.send('evm_revert', [snapshot]);
    await b.sendTransaction({ to: b.address, value: 0 }); // nonce differs too
    const second = await deployStack(await params(), b);
    expect(second).to.deep.equal(first);
    const factory2 = await ethers.getContractAt('PviumP2IdVaultFactory', second.factory);
    expect(await factory2.vaultFor(EMAIL_COMMITMENT)).to.equal(vault1);

    // and it is the address the SDK formula gives, from constants only
    const sdk = JSON.parse(readFileSync(join(__dirname, '..', '..', 'sdks', 'node', 'src', 'p2id.json'), 'utf8'));
    expect(ethers.getCreate2Address(second.factory, EMAIL_COMMITMENT, sdk.schemes[sdk.current].vaultInitCodeHash)).to.equal(vault1);

    // deploying again is a no-op that returns the same addresses
    expect(await deployStack(await params(), a)).to.deep.equal(first);

    // wiring
    const verifier = await ethers.getContractAt('PviumVerifier', second.pviumVerifier);
    expect(await verifier.pviumIdentity()).to.equal(second.pviumIdentity);
    expect(await factory2.defaultVerifier()).to.equal(second.pviumVerifier);
    expect(await factory2.policy()).to.equal(second.policy);
    expect(await factory2.owner()).to.equal(ethers.getAddress((await params()).owner));
  });

  it('any different parameter is a different stack: addresses are a commitment to the configuration', async () => {
    const [a] = await ethers.getSigners();
    const base = await deployStack(await params(), a);
    const other = await deployStack({ ...(await params()), attester: '0x0000000000000000000000000000000000000B0B' }, a);
    expect(other.pviumIdentity).to.equal(base.pviumIdentity); // untouched by the attester
    // the JWKS key order is irrelevant: keys are sorted before deployment
    const reversed = await deployStack({ ...(await params()), signerKeys: [...(await params()).signerKeys].reverse() }, a);
    expect(reversed).to.deep.equal(base);
    // a different key set is a different stack (sandbox vs production)
    const oneKey = await deployStack({ ...(await params()), signerKeys: (await params()).signerKeys.slice(0, 1) }, a);
    expect(oneKey.pviumIdentity).to.not.equal(base.pviumIdentity);
    expect(oneKey.factory).to.not.equal(base.factory);
    expect(other.pviumVerifier).to.not.equal(base.pviumVerifier);
    expect(other.factory).to.not.equal(base.factory);
  });

  it('the scheme domain is an input to the addresses: it is the factory namespace and the salt', async () => {
    const [a] = await ethers.getSigners();
    const v1 = await deployStack(await params(), a);
    const v2 = await deployStack({ ...(await params()), scheme: 'p2id.vault.v2' }, a);
    expect(v2.factory).to.not.equal(v1.factory);
    const f1 = await ethers.getContractAt('PviumP2IdVaultFactory', v1.factory);
    const f2 = await ethers.getContractAt('PviumP2IdVaultFactory', v2.factory);
    expect(await f1.nsHash()).to.equal(ethers.id('p2id.vault.v1'));
    expect(await f2.nsHash()).to.equal(ethers.id('p2id.vault.v2'));
    expect(await f1.vaultFor(EMAIL_COMMITMENT)).to.not.equal(await f2.vaultFor(EMAIL_COMMITMENT));
    await expect(deployStack({ ...(await params()), scheme: 'v1' }, a)).to.be.rejectedWith(/bad scheme/);
  });

  it('resumes an interrupted deployment: finished steps are skipped, the rest are deployed', async () => {
    const [a] = await ethers.getSigners();
    const snapshot = await network.provider.send('evm_snapshot');
    // A salt no other test uses, so every address starts out empty.
    const p = { ...(await params()), salt: ethers.id('resume-test') };
    const target = await predictStack(p);

    // An earlier run deployed RelationsLib and then stopped (the state seen on Base Sepolia).
    await ensureDeterministicDeployer();
    const relationsInit = (await (await ethers.getContractFactory('RelationsLib')).getDeployTransaction()).data as string;
    await deployDeterministic(relationsInit, p.salt, a);
    const before = await stackStatus(target);
    expect(before.relationsLib).to.equal(true);
    expect(before.transcriptLib).to.equal(false);
    expect(before.factory).to.equal(false);

    const log: string[] = [];
    const resumed = await deployStack(p, a, (m) => log.push(m));
    expect(resumed).to.deep.equal(target);
    expect(log.find((l) => l.startsWith('relationsLib'))).to.match(/already deployed, skipped/);
    expect(log.filter((l) => l.endsWith('  deployed')).length).to.equal(6);
    expect(Object.values(await stackStatus(target)).every(Boolean)).to.equal(true);

    // and a run over a complete stack sends nothing at all
    const again: string[] = [];
    await deployStack(p, a, (m) => again.push(m));
    expect(again.every((l) => /already deployed, skipped/.test(l))).to.equal(true);
    await network.provider.send('evm_revert', [snapshot]);
  });
});
