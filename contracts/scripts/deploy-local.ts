// Deploy the verifier + PviumIdentity to the running local node (npx hardhat node) using the test
// fixtures' signer key, and print the address. Used by examples/dart.
import { ethers } from 'hardhat';
import { createPublicKey } from 'crypto';
import { readFileSync } from 'fs';
import { join } from 'path';

async function main() {
  const relations = await ethers.deployContract('RelationsLib');
  const transcript = await ethers.deployContract('ZKTranscriptLib');
  await Promise.all([relations.waitForDeployment(), transcript.waitForDeployment()]);
  const verifier = await ethers.deployContract('PviumZKVerifier', {
    libraries: { RelationsLib: await relations.getAddress(), ZKTranscriptLib: await transcript.getAddress() },
  });
  await verifier.waitForDeployment();
  const jwk = createPublicKey(readFileSync(join(__dirname, '..', 'test', 'fixtures', 'privy_es256_public.pem'))).export({ format: 'jwk' });
  const x = BigInt('0x' + Buffer.from(jwk.x!, 'base64url').toString('hex'));
  const y = BigInt('0x' + Buffer.from(jwk.y!, 'base64url').toString('hex'));
  const gate = await ethers.deployContract('PviumIdentity', [await verifier.getAddress(), 1, [x], [y]]);
  await gate.waitForDeployment();
  console.log(JSON.stringify({ verifier: await verifier.getAddress(), pviumIdentity: await gate.getAddress() }));
}
main().catch((e) => { console.error(e); process.exit(1); });
