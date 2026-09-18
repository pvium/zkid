// Which chains the P2ID stack is deployed to, and which Pvium environment each one belongs to.
//
// An environment is a Privy app: `sandbox` for testnets, `production` for mainnets. Each has its own
// signing keys, so each is its own stack at its own addresses; within an environment every chain
// gets the identical configuration and therefore the identical addresses.
//
// Settings are read from contracts/.env. Per-environment values carry a suffix — _SANDBOX or _PROD —
// so a testnet run can never pick up production keys or owners, and vice versa. See .env.example.

export type P2IDEnvironment = 'sandbox' | 'production';

export interface DeployNetwork {
  chainId: number;
  environment: P2IDEnvironment;
  /** Env var holding the RPC URL; `defaultRpc` is used when it is unset. */
  rpcEnv: string;
  defaultRpc: string;
}

/** Add a chain here (one line) to make `--network <name>` available to the deploy script. */
export const DEPLOY_NETWORKS = {
  baseSepolia: { chainId: 84532, environment: 'sandbox', rpcEnv: 'BASE_SEPOLIA_RPC_URL', defaultRpc: 'https://sepolia.base.org' },
  base: { chainId: 8453, environment: 'production', rpcEnv: 'BASE_RPC_URL', defaultRpc: 'https://mainnet.base.org' },
  bsc: { chainId: 56, environment: 'production', rpcEnv: 'BSC_RPC_URL', defaultRpc: 'https://bsc-dataseed.bnbchain.org' },
} as const satisfies Record<string, DeployNetwork>;

export const ENV_SUFFIX: Record<P2IDEnvironment, string> = { sandbox: 'SANDBOX', production: 'PROD' };

/**
 * Read `${name}_${SUFFIX}` for the environment. Settings that must never be shared between
 * environments (owner, attester, Privy JWKS) are required in that form. `shared: true` settings
 * (deployer key, delays) fall back to the plain `${name}`.
 */
export function envFor(name: string, environment: P2IDEnvironment, opts: { shared?: boolean } = {}): string | undefined {
  const scoped = process.env[`${name}_${ENV_SUFFIX[environment]}`];
  if (scoped !== undefined && scoped !== '') return scoped;
  if (opts.shared) {
    const plain = process.env[name];
    if (plain !== undefined && plain !== '') return plain;
  }
  return undefined;
}

export function requireEnvFor(name: string, environment: P2IDEnvironment): string {
  const v = envFor(name, environment);
  if (v === undefined) throw new Error(`${name}_${ENV_SUFFIX[environment]} is required for the ${environment} environment (contracts/.env)`);
  return v;
}

/** The environment of a Hardhat network name; local networks default to sandbox unless P2ID_ENV says otherwise. */
export function environmentOf(networkName: string): P2IDEnvironment {
  const override = process.env.P2ID_ENV;
  if (override !== undefined && override !== '') {
    if (override !== 'sandbox' && override !== 'production') throw new Error(`P2ID_ENV must be sandbox or production, got "${override}"`);
    const configured = (DEPLOY_NETWORKS as Record<string, DeployNetwork>)[networkName];
    if (configured && configured.environment !== override) {
      throw new Error(`network ${networkName} is a ${configured.environment} network; refusing P2ID_ENV=${override}`);
    }
    return override;
  }
  const configured = (DEPLOY_NETWORKS as Record<string, DeployNetwork>)[networkName];
  if (configured) return configured.environment;
  if (networkName === 'hardhat' || networkName === 'localhost') return 'sandbox';
  throw new Error(`network ${networkName} has no environment: add it to DEPLOY_NETWORKS in deploy.config.ts or set P2ID_ENV`);
}
