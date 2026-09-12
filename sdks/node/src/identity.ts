/** Identity type ids. Must match circuit/src/identity.nr. */
export enum IdentityType {
  Email = 0,
  Phone = 1,
  Google = 2,
  Twitter = 3,
  Discord = 4,
  Github = 5,
  Linkedin = 6,
  Apple = 7,
  Telegram = 8,
  Tiktok = 9,
  Instagram = 10,
  Farcaster = 11,
  Wallet = 12,
}

/** Domain-separation prefix baked into the circuit's identity hash. */
export const HASH_PREFIX = 'p2id.identity.v1';

/** Types whose value is ASCII-lowercased before hashing: everything except phone numbers and
 *  wallet addresses (matches CASE_INSENSITIVE in circuit/src/identity.nr). */
export function isCaseInsensitive(type: IdentityType): boolean {
  return type !== IdentityType.Wallet && type !== IdentityType.Phone;
}

/**
 * Apply the circuit's normalisation to an identity value: ASCII-lowercase for case-insensitive
 * types and for EVM (`0x…`) wallet addresses; base58 (Solana) addresses are left untouched.
 */
export function normalizeIdentityValue(type: IdentityType, value: string): string {
  const lower = isCaseInsensitive(type) || (type === IdentityType.Wallet && value.startsWith('0x'));
  return lower ? value.replace(/[A-Z]/g, (c) => c.toLowerCase()) : value;
}

/**
 * `sha256(HASH_PREFIX || type || normalize(value))`, exactly as the circuit computes it.
 * This is the routing salt a payer uses to address an identity, and the value a proof's
 * `identityHash` output is compared against.
 */
export async function identityHash(type: IdentityType, value: string): Promise<`0x${string}`> {
  const enc = new TextEncoder();
  const prefix = enc.encode(HASH_PREFIX);
  const body = enc.encode(normalizeIdentityValue(type, value));
  if (body.length < 1 || body.length > 128) throw new Error('identity value must be 1..128 bytes');
  const preimage = new Uint8Array(prefix.length + 1 + body.length);
  preimage.set(prefix, 0);
  preimage[prefix.length] = type;
  preimage.set(body, prefix.length + 1);
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', preimage));
  return toHex(digest);
}

export function toHex(bytes: Uint8Array): `0x${string}` {
  let s = '';
  for (const b of bytes) s += b.toString(16).padStart(2, '0');
  return `0x${s}`;
}
