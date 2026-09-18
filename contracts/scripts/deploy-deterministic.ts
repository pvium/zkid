// Deploy the P2ID stack at chain-independent addresses.
//
//   npx hardhat run scripts/deploy-deterministic.ts --network baseSepolia     # sandbox
//   npx hardhat run scripts/deploy-deterministic.ts --network base            # production
//   npx hardhat run scripts/deploy-deterministic.ts --network bsc             # production
//
// The network decides the environment (deploy.config.ts): testnets are `sandbox`, mainnets are
// `production`. Everything environment-specific is read with that suffix from contracts/.env:
//   PRIVY_JWKS_URL_SANDBOX / _PROD   the Privy app's JWKS (URL, or a path to a saved jwks.json)
//   OWNER_SANDBOX / _PROD            factory registry owner (a Safe at the same address everywhere)
//   ATTESTER_SANDBOX / _PROD         constraint attester, or "none"
// Shared, optional: DEPLOYER_KEY (or DEPLOYER_KEY_<SUFFIX>), DEFAULT_CHANGE_DELAY, MIN_REFUND_WINDOW,
// MAX_REFUND_WINDOW, SCHEME (default: `current` in sdks/node/src/p2id.json), CIRCUIT_VERSION.
//
// PREDICT=1 prints the addresses without sending anything (with no --network, set P2ID_ENV).
//
// Local runs (--network hardhat or localhost) need no .env: unset values default to the sandbox
// Privy JWKS, the first local account as owner, and no attester. Real networks never default.
// Every chain of one environment must end up with the same addresses; the script refuses to
// deploy a configuration that differs from an earlier deployment of the same scheme+environment.
import { ethers, network } from 'hardhat';
import { existsSync, mkdirSync, readFileSync, readdirSync, writeFileSync } from 'fs';
import { join } from 'path';
import { envFor, environmentOf, requireEnvFor, type P2IDEnvironment } from '../deploy.config';
import { checkStack, deployStack, predictStack, sortedKeys, stackStatus, type StackParams } from './lib/deterministic';

const DAY = 24 * 3600;
const SANDBOX_JWKS = 'https://auth.privy.io/api/v1/apps/cmhc6t92u001tju0cxkxg34on/jwks.json';
const isLocal = () => network.name === 'hardhat' || network.name === 'localhost';
const ROOT = join(__dirname, '..', '..');
const DEPLOYMENTS = join(__dirname, '..', 'deployments');

interface PrivyKey {
  kid: string;
  x: bigint;
  y: bigint;
}

/** GET a JSON document, retrying timeouts and 5xx/429 responses (Privy's JWKS endpoint has transient 500/504s). */
async function fetchJson(url: string, attempts = 5): Promise<unknown> {
  let last = '';
  for (let i = 1; i <= attempts; i++) {
    try {
      const res = await fetch(url, { signal: AbortSignal.timeout(15_000) });
      if (res.ok) return await res.json();
      last = `HTTP ${res.status}`;
      if (res.status < 500 && res.status !== 429) break; // 4xx other than 429 will not fix itself
    } catch (err) {
      last = (err as Error).message;
    }
    if (i < attempts) {
      const wait = 2000 * 2 ** (i - 1);
      console.log(`fetching ${url}: ${last}, retrying in ${wait / 1000}s (${i}/${attempts})`);
      await new Promise((r) => setTimeout(r, wait));
    }
  }
  throw new Error(`fetching ${url}: ${last} after ${attempts} attempts. Nothing was deployed. Retry later, or point PRIVY_JWKS_URL_* at a saved jwks.json.`);
}

/** Every ES256 signing key in a Privy JWKS, from a URL or a saved jwks.json. */
async function loadPrivyKeys(source: string): Promise<PrivyKey[]> {
  let body: unknown;
  if (/^https?:\/\//.test(source)) {
    body = await fetchJson(source);
  } else {
    body = JSON.parse(readFileSync(source, 'utf8'));
  }
  const keys = (body as { keys?: any[] }).keys;
  if (!Array.isArray(keys)) throw new Error(`${source} is not a JWKS (no "keys" array)`);
  const ec = keys.filter((k) => k.kty === 'EC' && k.crv === 'P-256' && (k.use === undefined || k.use === 'sig'));
  if (ec.length === 0) throw new Error(`${source} has no P-256 signing keys`);
  const hex = (b64: string) => BigInt('0x' + Buffer.from(b64, 'base64url').toString('hex'));
  return ec.map((k) => ({ kid: String(k.kid ?? ''), x: hex(k.x), y: hex(k.y) }));
}

function address(value: string, name: string): string {
  if (!ethers.isAddress(value)) throw new Error(`${name} is not an address: ${value}`);
  return ethers.getAddress(value);
}

/** Required per-environment setting; on a local chain, a sandbox default instead (reported). */
async function setting(name: string, environment: P2IDEnvironment, localDefault: () => Promise<string> | string): Promise<string> {
  const v = envFor(name, environment);
  if (v !== undefined) return v;
  if (!isLocal() || environment !== 'sandbox') return requireEnvFor(name, environment);
  const d = await localDefault();
  console.log(`(local run) ${name}_SANDBOX not set, using ${d}`);
  return d;
}

async function configFor(environment: P2IDEnvironment, scheme: string, circuitVersion: number) {
  const jwks = await setting('PRIVY_JWKS_URL', environment, () => SANDBOX_JWKS);
  const keys = await loadPrivyKeys(jwks);
  const owner = address(
    await setting('OWNER', environment, async () => (await ethers.getSigners())[0].address),
    `OWNER for ${environment}`,
  );
  const attesterRaw = await setting('ATTESTER', environment, () => 'none');
  const attester = attesterRaw.toLowerCase() === 'none' ? ethers.ZeroAddress : address(attesterRaw, `ATTESTER for ${environment}`);
  const num = (name: string, fallback: number) => Number(envFor(name, environment, { shared: true }) ?? fallback);
  const params: StackParams = {
    owner,
    scheme,
    circuitVersion,
    signerKeys: keys.map(({ x, y }) => ({ x, y })),
    attester,
    defaultChangeDelay: num('DEFAULT_CHANGE_DELAY', 7 * DAY),
    minRefundWindow: num('MIN_REFUND_WINDOW', DAY),
    maxRefundWindow: num('MAX_REFUND_WINDOW', 90 * DAY),
  };
  return { params, keys, jwks };
}

/** Earlier deployments of this scheme+environment (any chain); they fix what the addresses must be. */
function earlierRecords(scheme: string, environment: P2IDEnvironment): { file: string; record: any }[] {
  if (!existsSync(DEPLOYMENTS)) return [];
  return readdirSync(DEPLOYMENTS)
    .filter((f) => f.startsWith(`${scheme}.${environment}.`) && f.endsWith('.json'))
    .map((file) => ({ file, record: JSON.parse(readFileSync(join(DEPLOYMENTS, file), 'utf8')) }));
}

async function main() {
  // 1. Everything the addresses depend on is resolved before touching the chain: the Privy keys
  //    first (the only remote input), then the rest of the configuration. A failure here means
  //    nothing was sent.
  const environment = environmentOf(network.name);
  const p2id = JSON.parse(readFileSync(join(ROOT, 'sdks', 'node', 'src', 'p2id.json'), 'utf8'));
  const scheme: string = process.env.SCHEME ?? p2id.current;
  const circuitVersion = Number(process.env.CIRCUIT_VERSION ?? JSON.parse(readFileSync(join(ROOT, 'circuit', 'version.json'), 'utf8')).circuitVersion);
  const { params, keys, jwks } = await configFor(environment, scheme, circuitVersion);
  console.log(`${environment} on ${network.name}: ${keys.length} Privy keys (${keys.map((k) => k.kid).join(', ')}), owner ${params.owner}`);

  const predicted = await predictStack(params);
  const summary = {
    scheme,
    environment,
    privyJwks: jwks,
    privyKeys: sortedKeys(keys).map((k) => ({ kid: keys.find((q) => q.x === k.x && q.y === k.y)?.kid, x: '0x' + k.x.toString(16).padStart(64, '0'), y: '0x' + k.y.toString(16).padStart(64, '0') })),
    config: {
      owner: params.owner,
      attester: params.attester,
      circuitVersion: params.circuitVersion,
      defaultChangeDelay: params.defaultChangeDelay,
      minRefundWindow: params.minRefundWindow,
      maxRefundWindow: params.maxRefundWindow,
    },
  };
  if (process.env.PREDICT) {
    console.log(JSON.stringify({ ...summary, predicted: true, ...predicted }, null, 2));
    return;
  }

  // Same scheme + environment must mean the same addresses on every chain.
  const recorded: string | null = p2id.schemes[scheme]?.factories?.[environment] ?? null;
  if (recorded && recorded.toLowerCase() !== predicted.factory.toLowerCase()) {
    throw new Error(
      `this ${environment} configuration gives factory ${predicted.factory}, but sdks/node/src/p2id.json records ${recorded} for ${scheme}. ` +
        'Something differs from the configuration that was recorded (owner, attester, delays, or the Privy JWKS keys).',
    );
  }
  for (const { file, record } of earlierRecords(scheme, environment)) {
    if (record.factory.toLowerCase() !== predicted.factory.toLowerCase()) {
      const keysNow = JSON.stringify(summary.privyKeys.map((k) => k.x));
      const keysThen = JSON.stringify((record.privyKeys ?? []).map((k: any) => k.x));
      const hint = keysNow !== keysThen ? 'the Privy JWKS keys changed since then' : 'owner, attester or delays differ';
      throw new Error(`deployments/${file} has factory ${record.factory}; this run would give ${predicted.factory} (${hint}). Every ${environment} chain must match.`);
    }
  }

  const [signer] = await ethers.getSigners();
  if (!signer) {
    throw new Error(
      `no deployer key for ${environment}: set DEPLOYER_KEY or DEPLOYER_KEY_${environment === 'sandbox' ? 'SANDBOX' : 'PROD'} ` +
        'to a private key (0x followed by 64 hex characters)',
    );
  }

  // 2. What is already on this chain (e.g. from an interrupted run): those steps are skipped.
  const status = await stackStatus(predicted);
  const present = Object.entries(status).filter(([, v]) => v).map(([k]) => k);
  console.log(present.length === 0 ? 'nothing deployed yet on this chain' : `already deployed, will skip: ${present.join(', ')}`);

  // 3. Deploy what is missing, one contract at a time.
  const addresses = await deployStack(params, signer, (m) => console.log(m));
  await checkStack(params, addresses, p2id.schemes[scheme]?.vaultInitCodeHash);

  const chainId = Number((await ethers.provider.getNetwork()).chainId);
  const record = { ...summary, network: network.name, chainId, ...addresses };
  if (chainId !== 31337) {
    mkdirSync(DEPLOYMENTS, { recursive: true });
    writeFileSync(join(DEPLOYMENTS, `${scheme}.${environment}.${chainId}.json`), JSON.stringify(record, null, 2) + '\n');
  }
  console.log(JSON.stringify(record, null, 2));
  console.log(`\nwiring checks passed (${environment})`);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
