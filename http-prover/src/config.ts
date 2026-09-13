import { createHash } from 'node:crypto';
import { existsSync, readFileSync } from 'node:fs';
import { homedir, tmpdir } from 'node:os';
import { join } from 'node:path';
import type { SignerSource } from './token.js';

export interface CircuitVersion {
  circuitVersion: number;
  vkSha256: string;
}

export interface ProverConfig {
  circuitJson: string;
  vkPath: string;
  /** circuit/version.json copied next to the artifacts by `yarn sync`. */
  versionJson: string;
  bbBin: string;
  workDir: string;
  maxConcurrency: number;
  signer: SignerSource;
}

/** Build config from process.env (loaded from .env via `node --env-file=.env`). */
export function configFromEnv(env: NodeJS.ProcessEnv = process.env): ProverConfig {
  const jwksUrls = (env.PRIVY_JWKS_URL ?? '').split(',').map((u) => u.trim()).filter(Boolean);
  const signer: SignerSource = jwksUrls.length
    ? { jwksUrls }
    : env.PRIVY_PUBLIC_KEY_PEM_FILE
      ? { pemFile: env.PRIVY_PUBLIC_KEY_PEM_FILE }
      : (() => {
          throw new Error('set PRIVY_JWKS_URL or PRIVY_PUBLIC_KEY_PEM_FILE');
        })();
  const defaultBb = existsSync(join(homedir(), '.bb', 'bb')) ? join(homedir(), '.bb', 'bb') : 'bb';
  return {
    circuitJson: env.CIRCUIT_JSON ?? './circuit/pvium_identity.json',
    vkPath: env.VK_PATH ?? './circuit/vk',
    versionJson: env.CIRCUIT_VERSION_JSON ?? './circuit/version.json',
    bbBin: env.BB_BIN ?? defaultBb,
    workDir: env.WORK_DIR ?? tmpdir(),
    maxConcurrency: Math.max(1, Number(env.MAX_CONCURRENCY ?? 1)),
    signer,
  };
}

/**
 * Read the served circuit version and check the vk on disk really is that version's vk, so a
 * half-synced deployment fails at startup instead of minting proofs nobody can verify.
 */
export function loadCircuitVersion(cfg: ProverConfig): CircuitVersion {
  const v = JSON.parse(readFileSync(cfg.versionJson, 'utf8')) as CircuitVersion;
  const actual = '0x' + createHash('sha256').update(readFileSync(cfg.vkPath)).digest('hex');
  if (actual !== v.vkSha256) {
    throw new Error(`vk at ${cfg.vkPath} hashes to ${actual} but version.json says ${v.vkSha256} (circuit version ${v.circuitVersion})`);
  }
  return { circuitVersion: v.circuitVersion, vkSha256: v.vkSha256 };
}
