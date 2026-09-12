import type { P256PublicKey } from './publicInputs.js';

/**
 * Parse a P-256 public key from a SubjectPublicKeyInfo PEM (what Privy's dashboard shows as the
 * app verification key). The DER ends with the 65-byte uncompressed point 0x04 || x || y, so no
 * ASN.1 parser is needed.
 */
export function parseP256PublicKeyPem(pem: string): P256PublicKey {
  const body = pem
    .split('\n')
    .filter((l) => !l.startsWith('-----'))
    .join('')
    .trim();
  const der = Uint8Array.from(atob(body), (c) => c.charCodeAt(0));
  if (der.length < 65 || der[der.length - 65] !== 0x04) {
    throw new Error('expected an uncompressed P-256 public key in SPKI PEM');
  }
  const point = der.subarray(der.length - 65);
  return { x: bytesToBigInt(point.subarray(1, 33)), y: bytesToBigInt(point.subarray(33, 65)) };
}

function bytesToBigInt(b: Uint8Array): bigint {
  let v = 0n;
  for (const x of b) v = (v << 8n) | BigInt(x);
  return v;
}
