import { execFile } from 'node:child_process';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';
import { Worker } from 'node:worker_threads';
import type { ProverConfig } from './config.js';
import { InputError } from './errors.js';
import type { CircuitInputs } from './witness.js';

const execFileAsync = promisify(execFile);

export interface ProofBundle {
  proof: Buffer;
  publicInputs: Buffer;
}

/** Thrown when the wait queue is full; the HTTP layer maps it to 503 + Retry-After. */
export class QueueFullError extends Error {
  constructor(public readonly queued: number) {
    super(`prover queue is full (${queued} waiting)`);
    this.name = 'QueueFullError';
  }
}

/**
 * Solves the circuit in a worker thread (noir_js WASM) and proves with the native bb binary.
 * Jobs are gated to `maxConcurrency` at a time (each prove peaks ~3 GB) with a bounded wait queue.
 */
export class Prover {
  private worker: Worker;
  private nextId = 1;
  private pending = new Map<number, { resolve: (w: Uint8Array) => void; reject: (e: Error) => void }>();
  private running = 0;
  private queue: Array<() => void> = [];

  constructor(private readonly cfg: ProverConfig) {
    this.worker = new Worker(join(dirname(fileURLToPath(import.meta.url)), 'solver.worker.js'), {
      workerData: { circuitJson: cfg.circuitJson },
    });
    this.worker.on('message', (m: { id: number; witness?: Uint8Array; error?: string }) => {
      const p = this.pending.get(m.id);
      if (!p) return;
      this.pending.delete(m.id);
      if (m.witness) p.resolve(m.witness);
      else p.reject(new InputError(`circuit rejected the inputs: ${m.error}`));
    });
    this.worker.on('error', (e) => {
      for (const p of this.pending.values()) p.reject(e);
      this.pending.clear();
    });
    this.worker.unref();
  }

  get stats() {
    return { inFlight: this.running, queued: this.queue.length, maxConcurrency: this.cfg.maxConcurrency, maxQueue: this.cfg.maxQueue };
  }

  async prove(inputs: CircuitInputs): Promise<ProofBundle> {
    await this.acquire();
    try {
      const witness = await this.solve(inputs);
      return await this.runBb(witness);
    } finally {
      this.release();
    }
  }

  async close(): Promise<void> {
    await this.worker.terminate();
  }

  private solve(inputs: CircuitInputs): Promise<Uint8Array> {
    const id = this.nextId++;
    return new Promise((resolve, reject) => {
      this.pending.set(id, { resolve, reject });
      this.worker.postMessage({ id, inputs });
    });
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
    if (this.queue.length >= this.cfg.maxQueue) return Promise.reject(new QueueFullError(this.queue.length));
    return new Promise((resolve) => this.queue.push(() => { this.running++; resolve(); }));
  }

  private release(): void {
    this.running--;
    this.queue.shift()?.();
  }
}
