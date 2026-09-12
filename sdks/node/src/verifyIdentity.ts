import { IdentityType, identityHash } from './identity.js';
import { resolveIdentityType, type IdentityTypeName } from './identityNames.js';
import { decodeClaim, type P256PublicKey, type PublicInputs } from './publicInputs.js';
import { parseP256PublicKeyPem } from './signer.js';
import { verifyProof } from './verify.js';

/** What Pvium's resolution API returns for an identity: the proof plus the address it binds. */
export interface Attestation {
  /** Proof bytes, or base64 of them. */
  proof: Uint8Array | string;
  /** Public inputs: raw bytes, base64 of them, or the hex fields. */
  publicInputs: PublicInputs | string;
  /** The wallet address the proof binds to the identity, exactly as linked in Privy. */
  wallet: string;
}

/**
 * Where to get the trusted signing key (Privy's verification key for the Pvium app):
 * a SPKI PEM string, or a JWKS URL whose P-256 keys are all accepted (handles rotation).
 */
export type Signer = string | { jwksUrl: string } | P256PublicKey;

export interface VerifyIdentityInput {
  attestation: Attestation;
  signer: Signer;
  identityType: IdentityType | IdentityTypeName;
  identityValue: string;
}

export type VerifyIdentityResult =
  | {
      valid: true;
      /** The wallet address, now proven to be linked to the identity in the same Privy account. */
      wallet: string;
      /** When Privy issued the token the proof was made from (unix seconds). Freshness is your policy. */
      issuedAt: number;
    }
  | { valid: false; reason: string };

/**
 * Does this attestation prove that `identityValue` (of `identityType`) and `attestation.wallet`
 * belong to the same Privy user, signed by `signer`? On success the wallet is returned as a
 * trusted value together with the attestation time.
 */
export async function verifyIdentity(input: VerifyIdentityInput): Promise<VerifyIdentityResult> {
  let type: IdentityType;
  try {
    type = resolveIdentityType(input.identityType);
  } catch (e) {
    return { valid: false, reason: (e as Error).message };
  }

  const proof = typeof input.attestation.proof === 'string' ? fromBase64(input.attestation.proof) : input.attestation.proof;
  const publicInputs =
    typeof input.attestation.publicInputs === 'string' ? fromBase64(input.attestation.publicInputs) : input.attestation.publicInputs;

  let claim;
  try {
    claim = decodeClaim(publicInputs);
  } catch (e) {
    return { valid: false, reason: `malformed attestation: ${(e as Error).message}` };
  }

  const trusted = await trustedKeys(input.signer);
  if (!trusted.some((k) => k.x === claim.signer.x && k.y === claim.signer.y)) {
    return { valid: false, reason: 'not signed by a trusted key' };
  }
  if (claim.identityType !== type) return { valid: false, reason: 'identity type mismatch' };
  if ((await identityHash(type, input.identityValue)) !== claim.identityHash) {
    return { valid: false, reason: 'identity value mismatch' };
  }
  if (claim.walletHash === null) return { valid: false, reason: 'attestation carries no wallet' };
  if ((await identityHash(IdentityType.Wallet, input.attestation.wallet)) !== claim.walletHash) {
    return { valid: false, reason: 'wallet mismatch' };
  }
  if (!(await verifyProof({ proof, publicInputs }))) return { valid: false, reason: 'invalid proof' };

  return { valid: true, wallet: input.attestation.wallet, issuedAt: claim.iat };
}

async function trustedKeys(signer: Signer): Promise<P256PublicKey[]> {
  if (typeof signer === 'string') return [parseP256PublicKeyPem(signer)];
  if ('jwksUrl' in signer) return fetchJwks(signer.jwksUrl);
  return [signer];
}

const jwksCache = new Map<string, { at: number; keys: P256PublicKey[] }>();
const JWKS_TTL_MS = 10 * 60 * 1000;

async function fetchJwks(url: string): Promise<P256PublicKey[]> {
  const hit = jwksCache.get(url);
  if (hit && Date.now() - hit.at < JWKS_TTL_MS) return hit.keys;
  const res = await fetch(url);
  if (!res.ok) throw new Error(`JWKS fetch failed: ${res.status}`);
  const body = (await res.json()) as { keys?: Array<{ kty?: string; crv?: string; x?: string; y?: string }> };
  const keys = (body.keys ?? [])
    .filter((k) => k.kty === 'EC' && k.crv === 'P-256' && k.x && k.y)
    .map((k) => ({ x: b64urlToBigInt(k.x!), y: b64urlToBigInt(k.y!) }));
  if (keys.length === 0) throw new Error('JWKS has no P-256 keys');
  jwksCache.set(url, { at: Date.now(), keys });
  return keys;
}

function fromBase64(s: string): Uint8Array {
  const std = s.replace(/-/g, '+').replace(/_/g, '/');
  return Uint8Array.from(atob(std.padEnd(std.length + ((4 - (std.length % 4)) % 4), '=')), (c) => c.charCodeAt(0));
}

function b64urlToBigInt(s: string): bigint {
  let v = 0n;
  for (const b of fromBase64(s)) v = (v << 8n) | BigInt(b);
  return v;
}
