import { HardhatUserConfig } from 'hardhat/config';
import '@nomicfoundation/hardhat-toolbox';

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
  },
};

export default config;
