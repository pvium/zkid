import { IdentityType, identityHash } from './identity.js';
import { resolveIdentityType, type IdentityTypeName } from './identityNames.js';
import { decodeClaim, type P256PublicKey, type PublicInputs } from './publicInputs.js';
import { parseP256PublicKeyPem } from './signer.js';
import { verifyProof } from './verify.js';
import { AttestationSigner, PVIUM_ENVIRONMENTS, type PviumEnvironmentName } from './environments.js';
import { CIRCUIT_VERSION, VK_SHA256 } from './vk.js';

/** What Pvium's resolution API returns for an identity: the proof plus the address it binds. */
export interface Attestation {
  /** Proof bytes, or base64 of them. */
  proof: Uint8Array | string;
  /** Public inputs: raw bytes, base64 of them, or the hex fields. */
  publicInputs: PublicInputs | string;
  /** The wallet address the proof binds to the identity, exactly as linked in Privy. */
  wallet: string;
  /** Circuit version that produced the proof, as reported by the prover. Checked when present. */
  circuitVersion?: number;
  vkHash?: string;
}

/**
 * Who is trusted to have signed the token behind an attestation.
 *
 * - `AttestationSigner.Production` / `AttestationSigner.Sandbox` (or the strings `'production'` /
 *   `'sandbox'`): Pvium's Privy apps, keys pinned in the SDK, JWKS consulted only for a key
 *   rotated in after this release (see environments.ts).
 * - a JWKS URL (`https://…/jwks.json`) or `{ jwksUrl }`: any JWKS; every P-256 key it serves
 *   is accepted. For self-hosted provers under your own Privy app.
 * - a SPKI PEM string, or raw `{ x, y }`: one specific key.
 */
export type Signer = AttestationSigner | PviumEnvironmentName | string | { jwksUrl: string } | P256PublicKey;

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

  const att = input.attestation;
  if (att.circuitVersion !== undefined && att.circuitVersion !== CIRCUIT_VERSION) {
    return { valid: false, reason: `attestation is for circuit version ${att.circuitVersion}; this SDK verifies version ${CIRCUIT_VERSION}` };
  }
  if (att.vkHash !== undefined && att.vkHash.toLowerCase() !== VK_SHA256) {
    return { valid: false, reason: 'attestation was produced by a different circuit build than this SDK verifies' };
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

  let trusted: P256PublicKey[];
  try {
    trusted = await trustedKeys(input.signer, claim.signer);
  } catch (e) {
    return { valid: false, reason: (e as Error).message };
  }
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
  // For an EVM wallet the circuit also exposes the address it read from the token; it must agree.
  const w = input.attestation.wallet;
  if (w.toLowerCase().startsWith('0x') && claim.wallet !== w.toLowerCase()) {
    return { valid: false, reason: 'wallet mismatch' };
  }
  if (!(await verifyProof({ proof, publicInputs }))) return { valid: false, reason: 'invalid proof' };

  return { valid: true, wallet: input.attestation.wallet, issuedAt: claim.iat };
}

async function trustedKeys(signer: Signer, claimSigner?: P256PublicKey): Promise<P256PublicKey[]> {
  if (typeof signer === 'string') {
    if (signer in PVIUM_ENVIRONMENTS) {
      const env = PVIUM_ENVIRONMENTS[signer as PviumEnvironmentName];
      const pinned = env.keys;
      // Pinned keys answer without a network call; fall back to the live JWKS only when the
      // attestation names a key we do not know (rotated in after this SDK release).
      if (!claimSigner || pinned.some((k) => k.x === claimSigner.x && k.y === claimSigner.y)) return pinned;
      try {
        return [...pinned, ...(await fetchJwks(env.jwksUrl))];
      } catch {
        return pinned;
      }
    }
    if (/^https?:\/\//i.test(signer)) return fetchJwks(signer);
    if (signer.includes('-----BEGIN')) return [parseP256PublicKeyPem(signer)];
    throw new Error(`unrecognised signer: expected AttestationSigner.Production/Sandbox, a JWKS URL, a PEM, or {x, y}`);
  }
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
