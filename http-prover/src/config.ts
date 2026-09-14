import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { gunzipSync } from 'node:zlib';
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
  /** Jobs allowed to wait for a slot before new requests get 503. */
  maxQueue: number;
  signer: SignerSource;
  /** Allow plain-http callback URLs (development only). */
  allowHttpCallbacks: boolean;
  /** SQLite file for the callback outbox (":memory:" for tests). */
  dbPath: string;
  /** How often the dispatcher re-tries due callback deliveries. */
  dispatchIntervalMs: number;
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
    maxQueue: Math.max(0, Number(env.MAX_QUEUE ?? 20)),
    signer,
    allowHttpCallbacks: env.ALLOW_HTTP_CALLBACKS === 'true',
    dbPath: env.DB_PATH ?? './data/prover.db',
    dispatchIntervalMs: Math.max(1_000, Number(env.DISPATCH_INTERVAL_MS ?? 30_000)),
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

/**
 * Confirm the bb binary runs and is the version the circuit was built with. Called at startup so
 * a missing or wrong prover fails the deploy's health check instead of the first user's request.
 */
export function checkBb(cfg: ProverConfig, expectedVersion = '5.0.0-nightly.20260522'): string {
  let out: string;
  try {
    out = execFileSync(cfg.bbBin, ['--version'], { encoding: 'utf8', timeout: 10_000 }).trim();
  } catch (e) {
    throw new Error(`bb not runnable at "${cfg.bbBin}" (${(e as Error).message}). Install it for this user: ~/.bb/bbup -v ${expectedVersion}, then set BB_BIN to its absolute path or unset it to use ~/.bb/bb`);
  }
  if (!out.includes(expectedVersion)) {
    throw new Error(`bb at "${cfg.bbBin}" is version "${out}" but the circuit was built with ${expectedVersion}`);
  }
  return out;
}

/**
 * The committed artifact is `<circuitJson>.gz` (stripped, ~4.6 MB). bb needs a plain file, so
 * inflate it next to the archive on first start if the plain file is missing.
 */
export function ensureCircuitJson(cfg: ProverConfig): void {
  if (existsSync(cfg.circuitJson)) return;
  const gz = cfg.circuitJson + '.gz';
  if (!existsSync(gz)) throw new Error(`circuit not found: neither ${cfg.circuitJson} nor ${gz} exists (run yarn sync)`);
  writeFileSync(cfg.circuitJson, gunzipSync(readFileSync(gz)));
}
