import { keccak_256 } from '@noble/hashes/sha3';
import { IdentityType, identityHash as hashIdentity, toHex } from './identity.js';
import { resolveIdentityType, type IdentityTypeName } from './identityNames.js';
import { P2ID_FACTORIES, P2ID_VAULT_INIT_CODE_HASH } from './p2idConstants.js';

export { P2ID_FACTORIES, P2ID_VAULT_INIT_CODE_HASH };

/**
 * P2ID v1 address derivation.
 *
 *   identityHash = sha256("p2id.identity.v1" ‖ typeId ‖ normalize(value))
 *   vault        = keccak256(0xff ‖ factory ‖ identityHash ‖ keccak256(P2IDVault creationCode))[12..]
 *
 * `normalize` ASCII-lowercases every type except phone and wallet, and lowercases `0x…` wallet
 * addresses. The vault takes no constructor arguments, so the creation-code hash is a constant
 * per release (`P2ID_VAULT_INIT_CODE_HASH`) and the address depends only on the factory and the
 * identity. Funds sent to it before the vault is deployed are claimable once anyone deploys it.
 */

/** The identity commitment: the CREATE2 salt of the identity's vault and the value proofs bind. */
export function identityHash(type: IdentityType | IdentityTypeName, value: string): Promise<`0x${string}`> {
  return hashIdentity(resolveIdentityType(type), value);
}

export interface P2IDAddressInput {
  identityType: IdentityType | IdentityTypeName;
  /** The identity as the user linked it, e.g. "you@example.com". Case does not matter. */
  identityValue: string;
  /** The factory to derive against: an EIP-155 chain id with a known Pvium factory, or an explicit factory address. */
  factory: number | `0x${string}`;
  /** Override the vault creation-code hash (e.g. for a factory built from a different vault release). */
  initCodeHash?: `0x${string}`;
}

/** The P2ID v1 vault address for an identity: where to pay it, deployed or not. Checksummed. */
export async function p2idAddress(input: P2IDAddressInput): Promise<`0x${string}`> {
  const salt = await identityHash(input.identityType, input.identityValue);
  return p2idAddressForHash(salt, input.factory, input.initCodeHash);
}

/** Same, from an identity hash you already have (e.g. from an attestation's claim). */
export function p2idAddressForHash(
  identityHash: `0x${string}`,
  factory: number | `0x${string}`,
  initCodeHash: `0x${string}` = P2ID_VAULT_INIT_CODE_HASH,
): `0x${string}` {
  const factoryAddress = resolveFactory(factory);
  const preimage = new Uint8Array(1 + 20 + 32 + 32);
  preimage[0] = 0xff;
  preimage.set(hexToBytes(factoryAddress, 20), 1);
  preimage.set(hexToBytes(identityHash, 32), 21);
  preimage.set(hexToBytes(initCodeHash, 32), 53);
  return checksumAddress(toHex(keccak_256(preimage).subarray(12)));
}

/** The Pvium factory for a chain, or throws with the list of chains this release knows. */
export function p2idFactory(chainId: number): `0x${string}` {
  const f = P2ID_FACTORIES[chainId];
  if (!f) {
    const known = Object.keys(P2ID_FACTORIES).join(', ') || 'none';
    throw new Error(`no Pvium P2ID factory known for chain ${chainId} in this release (known: ${known}); pass the factory address explicitly`);
  }
  return f;
}

function resolveFactory(factory: number | `0x${string}`): `0x${string}` {
  if (typeof factory === 'number') return p2idFactory(factory);
  if (!/^0x[0-9a-fA-F]{40}$/.test(factory)) throw new Error(`bad factory address ${factory}`);
  return factory;
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
