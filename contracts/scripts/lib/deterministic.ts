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
  /**
   * Owner of the factory (timelocked policy / default-verifier changes) and of the launch policy
   * (verifier allowlist): a multisig that exists at the same address on every chain.
   */
  owner: string;
  /**
   * Address-scheme domain, e.g. "p2id.vault.v1" (the key in sdks/node/src/p2id.json). Its hash is
   * both the factory's namespace and the deployment salt, so the scheme name is an input to every
   * address rather than only a label.
   */
  scheme: string;
  circuitVersion: number;
  /**
   * Every key in the Privy app's JWKS, raw P-256 coordinates. Order does not matter: the stack
   * sorts them, so the same set always gives the same addresses.
   */
  signerKeys: { x: bigint; y: bigint }[];
  /** Constraint attester; ZeroAddress disables constraints. */
  attester: string;
  policyChangeDelay: number;
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
  policy: string;
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

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

/**
 * Whether `address` has code, tolerating load-balanced RPCs (e.g. the public Base endpoints) whose
 * backends lag behind each other: "no code" is only believed after several reads agree.
 */
export async function hasCode(address: string, opts: { reads?: number; delayMs?: number } = {}): Promise<boolean> {
  // The in-process Hardhat chain has a single consistent state: one read is exact.
  const reads = network.name === 'hardhat' ? 1 : (opts.reads ?? 3);
  for (let i = 0; i < reads; i++) {
    if ((await ethers.provider.getCode(address)) !== '0x') return true;
    if (i < reads - 1) await sleep(opts.delayMs ?? 1500);
  }
  return false;
}

export type DeployLog = (message: string) => void;

/**
 * Deploy `initCode` through the proxy (no-op if already deployed); returns the address.
 * With `signer === null` nothing is sent: the address is only predicted.
 *
 * Safe to re-run after a partial failure: an existing contract is detected and skipped, and a
 * deployment whose "already there?" read was stale is caught by simulating the call first (the
 * proxy reverts when the address is taken).
 */
export async function deployDeterministic(
  initCode: string,
  salt: string,
  signer: Signer | null,
  opts: { name?: string; log?: DeployLog } = {},
): Promise<string> {
  const address = predictAddress(initCode, salt);
  if (signer === null) return address;
  const name = opts.name ?? address;
  const log = opts.log ?? (() => {});
  if (await hasCode(address, { reads: 1 })) {
    log(`${name.padEnd(14)} ${address}  already deployed, skipped`);
    return address;
  }
  const request = { to: DETERMINISTIC_DEPLOYER, data: ethers.concat([salt, initCode]) };
  try {
    await signer.call(request);
  } catch (err) {
    // The proxy reverts when CREATE2 fails, and the usual reason is that the address is taken:
    // the first read was stale. Look again, patiently, before treating it as a real failure.
    if (await hasCode(address, { reads: 5, delayMs: 2000 })) {
      log(`${name.padEnd(14)} ${address}  already deployed, skipped`);
      return address;
    }
    throw new Error(`deploying ${name} to ${address} would revert: ${(err as Error).message}`);
  }
  const tx = await signer.sendTransaction(request);
  log(`${name.padEnd(14)} ${address}  deploying, tx ${tx.hash}`);
  const receipt = await tx.wait();
  if (!receipt || receipt.status !== 1) throw new Error(`deploying ${name}: transaction ${tx.hash} reverted`);
  // A successful proxy call means the contract exists (the proxy reverts otherwise). Wait until the
  // RPC shows it, so later steps and the final checks read consistent state.
  if (!(await hasCode(address, { reads: 20, delayMs: 3000 }))) {
    throw new Error(`deploying ${name}: ${tx.hash} succeeded but ${address} still shows no code after 60s; re-run to continue`);
  }
  log(`${name.padEnd(14)} ${address}  deployed`);
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

/**
 * The addresses the stack will have, computed offline: no transactions, no network needed. Use it
 * to fill in `factory` in sdks/node/src/p2id.json, or to check a chain before deploying to it.
 */
export function predictStack(p: StackParams): Promise<StackAddresses> {
  return deployStack(p, null);
}

/** Deploy (or find) the whole stack. Same params + same build = same addresses on every chain. */
export async function deployStack(
  p: StackParams,
  signer: Signer | null,
  log?: DeployLog,
): Promise<StackAddresses> {
  if (signer !== null) await ensureDeterministicDeployer();
  if (!/^p2id\.vault\.v[1-9][0-9]*$/.test(p.scheme)) throw new Error(`bad scheme "${p.scheme}" (expected p2id.vault.vN)`);
  const nsHash = ethers.id(p.scheme);
  const salt = p.salt ?? nsHash;
  const relationsLib = await deployDeterministic(
    await initCodeOf('RelationsLib', []),
    salt,
    signer,
    { name: 'relationsLib', log },
  );
  const transcriptLib = await deployDeterministic(
    await initCodeOf('ZKTranscriptLib', []),
    salt,
    signer,
    { name: 'transcriptLib', log },
  );
  const zkVerifier = await deployDeterministic(
    await initCodeOf('PviumZKVerifier', [], {
      RelationsLib: relationsLib,
      ZKTranscriptLib: transcriptLib,
    }),
    salt,
    signer,
    { name: 'zkVerifier', log },
  );
  const keys = sortedKeys(p.signerKeys);
  const pviumIdentity = await deployDeterministic(
    await initCodeOf('PviumIdentity', [
      zkVerifier,
      p.circuitVersion,
      keys.map((k) => k.x),
      keys.map((k) => k.y),
    ]),
    salt,
    signer,
    { name: 'pviumIdentity', log },
  );
  const pviumVerifier = await deployDeterministic(
    await initCodeOf('PviumVerifier', [pviumIdentity, p.attester]),
    salt,
    signer,
    { name: 'pviumVerifier', log },
  );
  const policy = await deployDeterministic(
    await initCodeOf('PviumP2IDPolicy', [p.owner, [pviumVerifier]]),
    salt,
    signer,
    { name: 'policy', log },
  );
  const factory = await deployDeterministic(
    await initCodeOf('PviumP2IdVaultFactory', [
      p.owner,
      nsHash,
      policy,
      pviumVerifier,
      p.policyChangeDelay,
      p.minRefundWindow,
      p.maxRefundWindow,
    ]),
    salt,
    signer,
    { name: 'factory', log },
  );
  return {
    relationsLib,
    transcriptLib,
    zkVerifier,
    pviumIdentity,
    pviumVerifier,
    policy,
    factory,
  };
}

/** For each contract of the stack, whether it already has code on the current network. */
export async function stackStatus(a: StackAddresses): Promise<Record<keyof StackAddresses, boolean>> {
  const out = {} as Record<keyof StackAddresses, boolean>;
  for (const [name, address] of Object.entries(a) as [keyof StackAddresses, string][]) out[name] = await hasCode(address, { reads: 2 });
  return out;
}

/** Canonical order for a key set (by x, then y), so JWKS ordering can never move an address. */
export function sortedKeys(keys: { x: bigint; y: bigint }[]): { x: bigint; y: bigint }[] {
  if (keys.length === 0) throw new Error('at least one Privy signing key is required');
  return [...keys].sort((a, b) => (a.x === b.x ? (a.y < b.y ? -1 : a.y > b.y ? 1 : 0) : a.x < b.x ? -1 : 1));
}

/** Read back a deployed stack and fail loudly if anything is not wired as configured. */
export async function checkStack(p: StackParams, a: StackAddresses, expectedVaultInitCodeHash?: string): Promise<void> {
  const fail = (what: string, got: unknown, want: unknown) => {
    throw new Error(`deployment check failed: ${what} is ${got}, expected ${want}`);
  };
  const same = (x: string, y: string) => x.toLowerCase() === y.toLowerCase();
  for (const [name, address] of Object.entries(a)) {
    if (!(await hasCode(address, { reads: 5, delayMs: 2000 }))) fail(`${name} code at ${address}`, 'empty', 'deployed');
  }
  const identity = await ethers.getContractAt('PviumIdentity', a.pviumIdentity);
  if (!same(await identity.verifier(), a.zkVerifier)) fail('PviumIdentity.verifier', await identity.verifier(), a.zkVerifier);
  if (Number(await identity.circuitVersion()) !== p.circuitVersion) fail('circuitVersion', await identity.circuitVersion(), p.circuitVersion);
  if (Number(await identity.signerKeyCount()) !== p.signerKeys.length) fail('signerKeyCount', await identity.signerKeyCount(), p.signerKeys.length);
  for (const k of p.signerKeys) if (!(await identity.isSignerKey(k.x, k.y))) fail(`signer key ${k.x.toString(16).slice(0, 12)}…`, 'missing', 'accepted');
  const verifier = await ethers.getContractAt('PviumVerifier', a.pviumVerifier);
  if (!same(await verifier.pviumIdentity(), a.pviumIdentity)) fail('PviumVerifier.pviumIdentity', await verifier.pviumIdentity(), a.pviumIdentity);
  if (!same(await verifier.constraintSigner(), p.attester)) fail('constraintSigner', await verifier.constraintSigner(), p.attester);
  const factory = await ethers.getContractAt('PviumP2IdVaultFactory', a.factory);
  if (!same(await factory.owner(), p.owner)) fail('factory.owner', await factory.owner(), p.owner);
  if (!same(await factory.defaultVerifier(), a.pviumVerifier)) fail('factory.defaultVerifier', await factory.defaultVerifier(), a.pviumVerifier);
  if (!same(await factory.policy(), a.policy)) fail('factory.policy', await factory.policy(), a.policy);
  const policy = await ethers.getContractAt('PviumP2IDPolicy', a.policy);
  if (!same(await policy.owner(), p.owner)) fail('policy.owner', await policy.owner(), p.owner);
  if (!(await policy.isVerifierAllowed(a.pviumVerifier))) fail('default verifier allowed by the policy', false, true);
  if ((await factory.nsHash()) !== ethers.id(p.scheme)) fail('factory.nsHash', await factory.nsHash(), ethers.id(p.scheme));
  if (Number(await factory.policyChangeDelay()) !== p.policyChangeDelay) fail('policyChangeDelay', await factory.policyChangeDelay(), p.policyChangeDelay);
  if (expectedVaultInitCodeHash && (await factory.initCodeHash()) !== expectedVaultInitCodeHash) {
    fail('factory.initCodeHash', await factory.initCodeHash(), `${expectedVaultInitCodeHash} (sdks/node/src/p2id.json)`);
  }
}
