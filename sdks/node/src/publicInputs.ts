import { toHex } from './identity.js';

/** Number of public inputs the circuit emits: 2 inputs + 9 outputs. */
export const PUBLIC_INPUT_COUNT = 11;

/** Positions in the public input array (see circuit/src/main.nr). */
export const PI = {
  identityType: 0,
  wallet: 1,
  signerXHi: 2,
  signerXLo: 3,
  signerYHi: 4,
  signerYLo: 5,
  iat: 6,
  identityHashHi: 7,
  identityHashLo: 8,
  walletHashHi: 9,
  walletHashLo: 10,
} as const;

export interface P256PublicKey {
  x: bigint;
  y: bigint;
}

/** What a proof asserts, decoded from its public inputs. */
export interface IdentityClaim {
  identityType: number;
  /**
   * EVM address of the wallet linked in the same token, lowercase hex, checked in-circuit
   * against the address read from the token. Null for a non-EVM wallet or no wallet.
   */
  wallet: `0x${string}` | null;
  /** P-256 public key the token was signed with. */
  signer: P256PublicKey;
  /**
   * When Privy issued the token this proof was made from, unix seconds. This is the attestation
   * time; whether it is fresh enough is the caller's policy.
   */
  iat: number;
  /** sha256(prefix || type || normalize(value)); see identityHash(). */
  identityHash: `0x${string}`;
  /**
   * identityHash(IdentityType.Wallet, address) for a wallet linked in the same token, proving
   * the identity and the wallet belong to the same Privy user. Null when the proof has no wallet.
   */
  walletHash: `0x${string}` | null;
}

/** Accepts the raw 320-byte `public_inputs` file or an array of 32-byte hex fields. */
export type PublicInputs = Uint8Array | readonly string[];

/** Normalise public inputs to the `string[]` form bb.js expects (0x-prefixed, 32 bytes each). */
export function toPublicInputFields(inputs: PublicInputs): string[] {
  if (inputs instanceof Uint8Array) {
    if (inputs.length !== PUBLIC_INPUT_COUNT * 32) {
      throw new Error(`expected ${PUBLIC_INPUT_COUNT * 32} bytes of public inputs, got ${inputs.length}`);
    }
    const out: string[] = [];
    for (let i = 0; i < inputs.length; i += 32) out.push(toHex(inputs.subarray(i, i + 32)));
    return out;
  }
  if (inputs.length !== PUBLIC_INPUT_COUNT) {
    throw new Error(`expected ${PUBLIC_INPUT_COUNT} public inputs, got ${inputs.length}`);
  }
  return inputs.map((f) => {
    const h = f.startsWith('0x') ? f.slice(2) : f;
    if (!/^[0-9a-fA-F]{1,64}$/.test(h)) throw new Error(`bad public input field: ${f}`);
    return `0x${h.toLowerCase().padStart(64, '0')}`;
  });
}

/** Decode the claim carried by a proof's public inputs. Does not verify anything. */
export function decodeClaim(inputs: PublicInputs): IdentityClaim {
  const f = toPublicInputFields(inputs).map((h) => BigInt(h));
  const join = (hi: bigint, lo: bigint) => (hi << 128n) | lo;
  const hex32 = (v: bigint): `0x${string}` => `0x${v.toString(16).padStart(64, '0')}`;
  return {
    identityType: Number(f[PI.identityType]),
    wallet: f[PI.wallet] === 0n ? null : `0x${f[PI.wallet].toString(16).padStart(40, '0')}`,
    signer: { x: join(f[PI.signerXHi], f[PI.signerXLo]), y: join(f[PI.signerYHi], f[PI.signerYLo]) },
    iat: Number(f[PI.iat]),
    identityHash: hex32(join(f[PI.identityHashHi], f[PI.identityHashLo])),
    walletHash: (() => {
      const w = join(f[PI.walletHashHi], f[PI.walletHashLo]);
      return w === 0n ? null : hex32(w);
    })(),
  };
}
