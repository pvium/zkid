import { Noir, type CompiledCircuit } from '@noir-lang/noir_js';
import { execFile } from 'node:child_process';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { promisify } from 'node:util';
import type { ProverConfig } from './config.js';
import type { CircuitInputs } from './witness.js';

const execFileAsync = promisify(execFile);

export interface ProofBundle {
  proof: Buffer;
  publicInputs: Buffer;
}

/** Solves the circuit with noir_js (in-process WASM) and proves with the native bb binary. */
export class Prover {
  private noir: Noir;
  private running = 0;
  private queue: Array<() => void> = [];

  constructor(private readonly cfg: ProverConfig) {
    const circuit = JSON.parse(readFileSync(cfg.circuitJson, 'utf8')) as CompiledCircuit;
    this.noir = new Noir(circuit);
  }

  /** Solve + prove, gated to `maxConcurrency` jobs at a time (each prove peaks ~3 GB). */
  async prove(inputs: CircuitInputs): Promise<ProofBundle> {
    await this.acquire();
    try {
      const { witness } = await this.noir.execute(inputs); // already gzip-compressed
      return await this.runBb(witness);
    } finally {
      this.release();
    }
  }

  /** bb proves and, with --verify, checks its own output against the vk before we return it. */
  private async runBb(witness: Uint8Array): Promise<ProofBundle> {
    const dir = await mkdtemp(join(this.cfg.workDir, 'pvium-prove-'));
    try {
      const witnessPath = join(dir, 'witness.gz');
      const outDir = join(dir, 'out');
      await writeFile(witnessPath, witness);
      await execFileAsync(
        this.cfg.bbBin,
        ['prove', '-b', this.cfg.circuitJson, '-w', witnessPath, '-t', 'evm', '-k', this.cfg.vkPath, '--verify', '-o', outDir],
        { timeout: 180_000, maxBuffer: 8 * 1024 * 1024 },
      );
      const [proof, publicInputs] = await Promise.all([readFile(join(outDir, 'proof')), readFile(join(outDir, 'public_inputs'))]);
      return { proof, publicInputs };
    } finally {
      await rm(dir, { recursive: true, force: true }); // the witness contains the token
    }
  }

  private acquire(): Promise<void> {
    if (this.running < this.cfg.maxConcurrency) {
      this.running++;
      return Promise.resolve();
    }
    return new Promise((resolve) => this.queue.push(() => { this.running++; resolve(); }));
  }

  private release(): void {
    this.running--;
    this.queue.shift()?.();
  }
}
