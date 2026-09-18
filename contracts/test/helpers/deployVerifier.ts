import { ethers } from 'hardhat';

/**
 * Deploys PviumZKVerifier (the bb-generated Honk verifier) together with the external libraries bb splits out of it
 * (RelationsLib, ZKTranscriptLib) and links them. Reuse this from deployment scripts.
 */
export async function deployVerifier() {
  const relations = await ethers.deployContract('RelationsLib');
  const transcript = await ethers.deployContract('ZKTranscriptLib');
  await Promise.all([relations.waitForDeployment(), transcript.waitForDeployment()]);

  const verifier = await ethers.deployContract('PviumZKVerifier', {
    libraries: {
      RelationsLib: await relations.getAddress(),
      ZKTranscriptLib: await transcript.getAddress(),
    },
  });
  await verifier.waitForDeployment();
  return { verifier, relations, transcript };
}

/** Deploys PviumIdentity bound to a verifier and one signer key (or pass `extraKeys` for a key set). */
export async function deployIdentityProof(
  verifierAddress: string,
  signerX: bigint,
  signerY: bigint,
  circuitVersion = 2,
  extraKeys: { x: bigint; y: bigint }[] = [],
) {
  const keys = [{ x: signerX, y: signerY }, ...extraKeys];
  const proof = await ethers.deployContract('PviumIdentity', [verifierAddress, circuitVersion, keys.map((k) => k.x), keys.map((k) => k.y)]);
  await proof.waitForDeployment();
  return proof;
}
