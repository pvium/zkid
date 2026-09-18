import { HardhatUserConfig } from 'hardhat/config';
import '@nomicfoundation/hardhat-toolbox';
import { existsSync } from 'fs';
import { join } from 'path';
import { DEPLOY_NETWORKS, envFor } from './deploy.config';

// Deployment settings come from contracts/.env (git-ignored; see .env.example). Tests need none.
const envFile = join(__dirname, '.env');
if (existsSync(envFile)) (process as any).loadEnvFile?.(envFile);

// One Hardhat network per entry in deploy.config.ts, each paying from its environment's deployer.
const deployNetworks = Object.fromEntries(
  Object.entries(DEPLOY_NETWORKS).map(([name, n]) => {
    const key = envFor('DEPLOYER_KEY', n.environment, { shared: true });
    return [name, { url: process.env[n.rpcEnv] ?? n.defaultRpc, chainId: n.chainId, accounts: key ? [key] : [] }];
  }),
);

const config: HardhatUserConfig = {
  paths: {
    sources: './src',
  },
  solidity: {
    // The generated Honk verifier requires ^0.8.27.
    version: '0.8.28',
    settings: {
      optimizer: {
        enabled: true,
        runs: 200,
      },
      // No source-metadata hash in the bytecode: a vault's address depends on keccak256 of its
      // creation code, and that must change only when the code does, not when a comment does.
      metadata: { bytecodeHash: 'none' },
    },
  },
  networks: {
    hardhat: {
      chainId: 31337,
    },
    ...deployNetworks,
  },
  etherscan: { apiKey: process.env.ETHERSCAN_API_KEY ?? '' },
  sourcify: { enabled: false },
};

export default config;
