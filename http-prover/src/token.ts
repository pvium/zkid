import { createPublicKey, verify, type KeyObject } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { InputError } from './errors.js';

export interface ParsedToken {
  headerB64: string;
  payloadB64: string;
  /** `base64url(header) || "." || base64url(payload)`, what ES256 signs. */
  signingInput: Buffer;
  /** Decoded payload JSON bytes. */
  payload: Buffer;
  /** 64-byte `r || s` as found in the token (not yet low-s normalised). */
  signature: Buffer;
  kid?: string;
}

export function parseToken(jwt: string): ParsedToken {
  const parts = jwt.trim().split('.');
  if (parts.length !== 3) throw new InputError('token must have three segments');
  const [headerB64, payloadB64, sigB64] = parts;
  let header: { alg?: string; kid?: string };
  try {
    header = JSON.parse(Buffer.from(headerB64, 'base64url').toString('utf8'));
  } catch {
    throw new InputError('token header is not valid JSON');
  }
  if (header.alg !== 'ES256') throw new InputError(`unsupported alg ${header.alg}; expected ES256`);
  const signature = Buffer.from(sigB64, 'base64url');
  if (signature.length !== 64) throw new InputError('ES256 signature must be 64 bytes');
  return {
    headerB64,
    payloadB64,
    signingInput: Buffer.from(`${headerB64}.${payloadB64}`),
    payload: Buffer.from(payloadB64, 'base64url'),
    signature,
    kid: header.kid,
  };
}

export interface SignerKey {
  key: KeyObject;
  x: Buffer; // 32 bytes
  y: Buffer; // 32 bytes
  kid?: string;
}

function toSignerKey(key: KeyObject, kid?: string): SignerKey {
  const jwk = key.export({ format: 'jwk' });
  if (jwk.kty !== 'EC' || jwk.crv !== 'P-256' || !jwk.x || !jwk.y) throw new Error('signer key is not P-256');
  return { key, x: Buffer.from(jwk.x, 'base64url'), y: Buffer.from(jwk.y, 'base64url'), kid };
}

/**
 * Where trusted signer keys come from: one or more JWKS URLs (rotation-aware; several Privy apps,
 * e.g. production and sandbox, can be trusted at once) or a pinned PEM file.
 */
export type SignerSource = { jwksUrls: string[] } | { pemFile: string } | { pem: string };

const jwksCache = new Map<string, { at: number; keys: SignerKey[] }>();
const JWKS_TTL_MS = 10 * 60 * 1000;

export async function trustedKeys(source: SignerSource): Promise<SignerKey[]> {
  if ('pem' in source) return [toSignerKey(createPublicKey(source.pem))];
  if ('pemFile' in source) return [toSignerKey(createPublicKey(readFileSync(source.pemFile)))];
  const perUrl = await Promise.all(source.jwksUrls.map(fetchJwks));
  return perUrl.flat();
}

async function fetchJwks(url: string): Promise<SignerKey[]> {
  const hit = jwksCache.get(url);
  if (hit && Date.now() - hit.at < JWKS_TTL_MS) return hit.keys;
  const res = await fetch(url);
  if (!res.ok) throw new Error(`JWKS fetch failed for ${url}: ${res.status}`);
  const body = (await res.json()) as { keys?: Array<Record<string, string>> };
  const keys = (body.keys ?? [])
    .filter((k) => k.kty === 'EC' && k.crv === 'P-256')
    .map((k) => toSignerKey(createPublicKey({ key: k, format: 'jwk' }), k.kid));
  if (keys.length === 0) throw new Error(`JWKS at ${url} has no P-256 keys`);
  jwksCache.set(url, { at: Date.now(), keys });
  return keys;
}

/**
 * Find the trusted key that signed this token and check the signature natively, so a bad token
 * is rejected in milliseconds rather than after seconds of proving. The token's `kid` narrows
 * the candidates; the signature decides. Callers never choose a key.
 */
export async function authenticate(token: ParsedToken, source: SignerSource): Promise<SignerKey> {
  const keys = await trustedKeys(source);
  const candidates = token.kid ? keys.filter((k) => !k.kid || k.kid === token.kid) : keys;
  for (const k of candidates.length ? candidates : keys) {
    if (verify('sha256', token.signingInput, { key: k.key, dsaEncoding: 'ieee-p1363' }, token.signature)) return k;
  }
  throw new InputError('token is not signed by a trusted key', 401);
}

const P256_N = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n;

/**
 * ECDSA signatures are malleable: (r, s) and (r, n - s) are both valid. Barretenberg's in-circuit
 * verifier accepts only low-s, and JWT signers do not normalise, so every prover must do this.
 */
export function normalizeLowS(sig: Buffer): Buffer {
  const r = sig.subarray(0, 32);
  let s = BigInt('0x' + sig.subarray(32).toString('hex'));
  if (s > P256_N / 2n) s = P256_N - s;
  return Buffer.concat([r, Buffer.from(s.toString(16).padStart(64, '0'), 'hex')]);
}
