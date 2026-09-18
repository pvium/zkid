// Deploy the P2ID stack at chain-independent addresses. Run once per chain with the SAME values:
//   OWNER=0x… ATTESTER=0x… PRIVY_PEM=path/to/privy_es256_public.pem \
//   npx hardhat run scripts/deploy-deterministic.ts --network <name>
// Optional: SCHEME (default the current one in sdks/node/src/p2id.json), CIRCUIT_VERSION (default circuit/version.json),
//           DEFAULT_CHANGE_DELAY (default 7 days), MIN_REFUND_WINDOW (1 day), MAX_REFUND_WINDOW (90 days).
// Prints the addresses; record `factory` under that scheme in sdks/node/src/p2id.json (which freezes it).
import { ethers } from 'hardhat';
import { createPublicKey } from 'crypto';
import { readFileSync } from 'fs';
import { join } from 'path';
import { deployStack } from './lib/deterministic';

const DAY = 24 * 3600;

async function main() {
  const owner = process.env.OWNER;
  const pem = process.env.PRIVY_PEM;
  if (!owner || !pem) throw new Error('OWNER and PRIVY_PEM are required');
  const jwk = createPublicKey(readFileSync(pem)).export({ format: 'jwk' });
  const version = JSON.parse(readFileSync(join(__dirname, '..', '..', 'circuit', 'version.json'), 'utf8')).circuitVersion;
  const p2id = JSON.parse(readFileSync(join(__dirname, '..', '..', 'sdks', 'node', 'src', 'p2id.json'), 'utf8'));
  const scheme = process.env.SCHEME ?? p2id.current;
  const [signer] = await ethers.getSigners();
  const addresses = await deployStack(
    {
      owner,
      scheme,
      circuitVersion: Number(process.env.CIRCUIT_VERSION ?? version),
      signerX: BigInt('0x' + Buffer.from(jwk.x!, 'base64url').toString('hex')),
      signerY: BigInt('0x' + Buffer.from(jwk.y!, 'base64url').toString('hex')),
      attester: process.env.ATTESTER ?? ethers.ZeroAddress,
      defaultChangeDelay: Number(process.env.DEFAULT_CHANGE_DELAY ?? 7 * DAY),
      minRefundWindow: Number(process.env.MIN_REFUND_WINDOW ?? DAY),
      maxRefundWindow: Number(process.env.MAX_REFUND_WINDOW ?? 90 * DAY),
    },
    signer,
  );
  console.log(JSON.stringify({ scheme, chainId: Number((await ethers.provider.getNetwork()).chainId), ...addresses }, null, 2));
}
main().catch((e) => { console.error(e); process.exit(1); });
