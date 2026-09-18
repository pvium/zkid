import { keccak_256 } from '@noble/hashes/sha3';
import { IdentityType, identityHash as hashIdentity, toHex } from './identity.js';
import { resolveIdentityType, type IdentityTypeName } from './identityNames.js';
import { P2ID_SCHEME, P2ID_SCHEMES, type P2IDScheme, type P2IDSchemeName } from './p2idConstants.js';
import type { PviumEnvironmentName } from './environments.js';

export { P2ID_SCHEME, P2ID_SCHEMES };
export type { P2IDScheme, P2IDSchemeName };

/**
 * P2ID address derivation.
 *
 *   identityHash = sha256(identityDomain ‖ byte(typeId) ‖ normalize(value))
 *   p2id         = keccak256(0xff ‖ factory ‖ identityHash ‖ vaultInitCodeHash)[12..]
 *
 * `normalize` ASCII-lowercases every type except phone and wallet, and lowercases `0x…` wallet
 * addresses. A *scheme* (`p2id.vault.vN`) fixes the three constants: the identity domain, the
 * vault creation-code hash and the factory. The factory is deployed through the deterministic
 * deployment proxy, so it is at the same address on every EVM chain: a P2ID address is
 * chain-agnostic, like any wallet address. (The vault contract still has to be deployed on each
 * chain where it is claimed; anyone can do that, and funds sent before then are claimable once
 * it is.)
 *
 * Each Pvium environment is its own stack: `production` (mainnets, the production Privy app) and
 * `sandbox` (testnets, the sandbox Privy app) have different factories, so the same identity has
 * a different address in each. Production is the default.
 *
 * Schemes are history. A change to the vault bytecode moves every address, so it ships as the
 * next scheme and becomes `P2ID_SCHEME`; earlier schemes stay in `P2ID_SCHEMES` so addresses
 * people were already given can be derived, and claimed, forever.
 */

/** Constants of a scheme; defaults to the current one. */
export function p2idScheme(name: P2IDSchemeName | string = P2ID_SCHEME): P2IDScheme {
  const s = (P2ID_SCHEMES as Record<string, P2IDScheme>)[name];
  if (!s) throw new Error(`unknown P2ID scheme "${name}" (known: ${Object.keys(P2ID_SCHEMES).join(', ')})`);
  return s;
}

/** The identity commitment: the CREATE2 salt of the identity's vault and the value proofs bind. */
export function identityHash(
  type: IdentityType | IdentityTypeName,
  value: string,
  scheme: P2IDSchemeName | string = P2ID_SCHEME,
): Promise<`0x${string}`> {
  return hashIdentity(resolveIdentityType(type), value, p2idScheme(scheme).identityDomain);
}

export interface P2IDAddressInput {
  identityType: IdentityType | IdentityTypeName;
  /** The identity as the user linked it, e.g. "you@example.com". Case does not matter. */
  identityValue: string;
  /** Address scheme; defaults to the current one (`P2ID_SCHEME`). Pass an older one to find an address issued under it. */
  scheme?: P2IDSchemeName | string;
  /** Pvium environment; defaults to `production`. Use `sandbox` on testnets. */
  environment?: PviumEnvironmentName;
  /** Derive against another factory than the scheme's (e.g. a test deployment). */
  factory?: `0x${string}`;
}

/** The P2ID address for an identity: where to pay it, on any EVM chain, deployed or not. Checksummed. */
export async function p2idAddress(input: P2IDAddressInput): Promise<`0x${string}`> {
  const salt = await identityHash(input.identityType, input.identityValue, input.scheme);
  return p2idAddressForHash(salt, { scheme: input.scheme, environment: input.environment, factory: input.factory });
}

/** Same, from an identity hash you already have (e.g. from an attestation's claim). */
export function p2idAddressForHash(
  identityHash: `0x${string}`,
  opts: { scheme?: P2IDSchemeName | string; environment?: PviumEnvironmentName; factory?: `0x${string}` } = {},
): `0x${string}` {
  const scheme = p2idScheme(opts.scheme);
  const environment = opts.environment ?? 'production';
  if (environment !== 'production' && environment !== 'sandbox') throw new Error(`unknown environment "${environment}"`);
  const factory = opts.factory ?? scheme.factories[environment];
  if (!factory) {
    throw new Error(`scheme ${opts.scheme ?? P2ID_SCHEME} has no ${environment} factory address in this release yet; pass \`factory\` explicitly`);
  }
  if (!/^0x[0-9a-fA-F]{40}$/.test(factory)) throw new Error(`bad factory address ${factory}`);
  const preimage = new Uint8Array(1 + 20 + 32 + 32);
  preimage[0] = 0xff;
  preimage.set(hexToBytes(factory, 20), 1);
  preimage.set(hexToBytes(identityHash, 32), 21);
  preimage.set(hexToBytes(scheme.vaultInitCodeHash, 32), 53);
  return checksumAddress(toHex(keccak_256(preimage).subarray(12)));
}

/** EIP-55 checksum. */
export function checksumAddress(address: `0x${string}`): `0x${string}` {
  const lower = address.slice(2).toLowerCase();
  const hash = keccak_256(new TextEncoder().encode(lower));
  let out = '0x';
  for (let i = 0; i < 40; i++) {
    const nibble = (hash[i >> 1] >> (i % 2 === 0 ? 4 : 0)) & 0xf;
    out += nibble >= 8 ? lower[i].toUpperCase() : lower[i];
  }
  return out as `0x${string}`;
}

function hexToBytes(hex: string, length: number): Uint8Array {
  const h = hex.startsWith('0x') ? hex.slice(2) : hex;
  if (h.length !== length * 2 || !/^[0-9a-fA-F]*$/.test(h)) throw new Error(`expected ${length}-byte hex, got ${hex}`);
  const out = new Uint8Array(length);
  for (let i = 0; i < length; i++) out[i] = parseInt(h.slice(i * 2, i * 2 + 2), 16);
  return out;
}
