import { Barretenberg, UltraHonkVerifierBackend } from '@aztec/bb.js';
import { VK_BASE64 } from './vk.js';
import { toPublicInputFields, type PublicInputs } from './publicInputs.js';

export interface ProofBundle {
  /** Raw proof bytes as produced by `bb prove -t evm` (or bb.js with verifierTarget 'evm'). */
  proof: Uint8Array;
  publicInputs: PublicInputs;
}

let vkCache: Uint8Array | undefined;
/** The circuit's UltraHonk verification key (EVM / keccak transcript), bundled with the package. */
export function verificationKey(): Uint8Array {
  if (!vkCache) vkCache = Uint8Array.from(atob(VK_BASE64), (c) => c.charCodeAt(0));
  return vkCache;
}

let apiPromise: Promise<Barretenberg> | undefined;
async function backend(): Promise<UltraHonkVerifierBackend> {
  apiPromise ??= Barretenberg.new({ threads: 1 });
  return new UltraHonkVerifierBackend(await apiPromise);
}

/** Release the Barretenberg WASM instance. Call when your process is done verifying. */
export async function shutdown(): Promise<void> {
  if (apiPromise) {
    const api = await apiPromise;
    apiPromise = undefined;
    await api.destroy();
  }
}

/**
 * Cryptographic check only: is this a valid proof for the Pvium identity circuit with these
 * public inputs? Says nothing about who signed the token or whether it has expired.
 */
export async function verifyProof(bundle: ProofBundle): Promise<boolean> {
  const publicInputs = toPublicInputFields(bundle.publicInputs);
  const v = await backend();
  try {
    return await v.verifyProof(
      { proof: bundle.proof, publicInputs, verificationKey: verificationKey() },
      { verifierTarget: 'evm' },
    );
  } catch {
    return false;
  }
}
