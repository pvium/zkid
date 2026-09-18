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

/** Deploys PviumIdentity bound to a verifier and a registered signer key. */
export async function deployIdentityProof(verifierAddress: string, signerX: bigint, signerY: bigint, circuitVersion = 2) {
  const proof = await ethers.deployContract('PviumIdentity', [verifierAddress, circuitVersion, signerX, signerY]);
  await proof.waitForDeployment();
  return proof;
}
