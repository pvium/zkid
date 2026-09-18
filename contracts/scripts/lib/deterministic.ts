// Deterministic (CREATE2) deployment of the whole P2ID stack through the canonical deterministic
// deployment proxy, so every contract, and therefore every identity's vault, has the same address
// on every EVM chain. An address then depends only on the bytecode, the constructor arguments and
// the salt, never on who deploys or on a nonce.
import { ethers, network } from 'hardhat';
import type { Signer } from 'ethers';

/** Arachnid's deterministic deployment proxy: present at this address on most EVM chains. */
export const DETERMINISTIC_DEPLOYER =
  '0x4e59b44847b379578588920cA78FbF26c0B4956C';
const DETERMINISTIC_DEPLOYER_RUNTIME =
  '0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe03601600081602082378035828234f58015156039578182fd5b8082525050506014600cf3';

export interface StackParams {
  /** Registry owner of the factory: a multisig that exists at the same address on every chain. */
  owner: string;
  /**
   * Address-scheme domain, e.g. "p2id.vault.v1" (the key in sdks/node/src/p2id.json). Its hash is
   * both the factory's namespace and the deployment salt, so the scheme name is an input to every
   * address rather than only a label.
   */
  scheme: string;
  circuitVersion: number;
  /** Privy signing key, raw P-256 coordinates. */
  signerX: bigint;
  signerY: bigint;
  /** Constraint attester; ZeroAddress disables constraints. */
  attester: string;
  defaultChangeDelay: number;
  minRefundWindow: number;
  maxRefundWindow: number;
  /** Override the deployment salt (default keccak256(scheme)); only to deliberately get a separate stack. */
  salt?: string;
}

export interface StackAddresses {
  relationsLib: string;
  transcriptLib: string;
  zkVerifier: string;
  pviumIdentity: string;
  pviumVerifier: string;
  factory: string;
}

export const CURRENT_SCHEME = 'p2id.vault.v1';

/** Make sure the proxy exists. On a local Hardhat network it is installed; elsewhere it must already be there. */
export async function ensureDeterministicDeployer(): Promise<void> {
  if ((await ethers.provider.getCode(DETERMINISTIC_DEPLOYER)) !== '0x') return;
  if (network.name === 'hardhat' || network.name === 'localhost') {
    await network.provider.send('hardhat_setCode', [
      DETERMINISTIC_DEPLOYER,
      DETERMINISTIC_DEPLOYER_RUNTIME,
    ]);
    return;
  }
  throw new Error(
    `deterministic deployment proxy ${DETERMINISTIC_DEPLOYER} is not deployed on ${network.name}; ` +
      'deploy it first (https://github.com/Arachnid/deterministic-deployment-proxy), otherwise addresses will not match other chains',
  );
}

export function predictAddress(initCode: string, salt: string): string {
  return ethers.getCreate2Address(
    DETERMINISTIC_DEPLOYER,
    salt,
    ethers.keccak256(initCode),
  );
}

/** Deploy `initCode` through the proxy (no-op if already deployed); returns the address. */
export async function deployDeterministic(
  initCode: string,
  salt: string,
  signer: Signer,
): Promise<string> {
  const address = predictAddress(initCode, salt);
  if ((await ethers.provider.getCode(address)) !== '0x') return address;
  const tx = await signer.sendTransaction({
    to: DETERMINISTIC_DEPLOYER,
    data: ethers.concat([salt, initCode]),
  });
  await tx.wait();
  if ((await ethers.provider.getCode(address)) === '0x')
    throw new Error(`deployment to ${address} failed`);
  return address;
}

async function initCodeOf(
  name: string,
  args: unknown[],
  libraries?: Record<string, string>,
): Promise<string> {
  const factory = await ethers.getContractFactory(
    name,
    libraries ? { libraries } : undefined,
  );
  const tx = await factory.getDeployTransaction(...args);
  return tx.data as string;
}

/** Deploy (or find) the whole stack. Same params + same build = same addresses on every chain. */
export async function deployStack(
  p: StackParams,
  signer: Signer,
): Promise<StackAddresses> {
  await ensureDeterministicDeployer();
  if (!/^p2id\.vault\.v[1-9][0-9]*$/.test(p.scheme)) throw new Error(`bad scheme "${p.scheme}" (expected p2id.vault.vN)`);
  const nsHash = ethers.id(p.scheme);
  const salt = p.salt ?? nsHash;
  const relationsLib = await deployDeterministic(
    await initCodeOf('RelationsLib', []),
    salt,
    signer,
  );
  const transcriptLib = await deployDeterministic(
    await initCodeOf('ZKTranscriptLib', []),
    salt,
    signer,
  );
  const zkVerifier = await deployDeterministic(
    await initCodeOf('PviumZKVerifier', [], {
      RelationsLib: relationsLib,
      ZKTranscriptLib: transcriptLib,
    }),
    salt,
    signer,
  );
  const pviumIdentity = await deployDeterministic(
    await initCodeOf('PviumIdentity', [
      zkVerifier,
      p.circuitVersion,
      p.signerX,
      p.signerY,
    ]),
    salt,
    signer,
  );
  const pviumVerifier = await deployDeterministic(
    await initCodeOf('PviumVerifier', [pviumIdentity, p.attester]),
    salt,
    signer,
  );
  const factory = await deployDeterministic(
    await initCodeOf('PviumP2IdVaultFactory', [
      p.owner,
      nsHash,
      pviumVerifier,
      p.defaultChangeDelay,
      p.minRefundWindow,
      p.maxRefundWindow,
    ]),
    salt,
    signer,
  );
  return {
    relationsLib,
    transcriptLib,
    zkVerifier,
    pviumIdentity,
    pviumVerifier,
    factory,
  };
}
