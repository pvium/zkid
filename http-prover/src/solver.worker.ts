// Worker thread: loads the circuit once and solves witnesses on request, so the ~3 s of
// synchronous WASM execution never blocks the HTTP event loop.
import { parentPort, workerData } from 'node:worker_threads';
import { readFileSync } from 'node:fs';
import { Noir, type CompiledCircuit } from '@noir-lang/noir_js';

const circuit = JSON.parse(readFileSync(workerData.circuitJson as string, 'utf8')) as CompiledCircuit;
const noir = new Noir(circuit);

parentPort!.on('message', async ({ id, inputs }: { id: number; inputs: Record<string, unknown> }) => {
  try {
    const { witness } = await noir.execute(inputs as never);
    parentPort!.postMessage({ id, witness }, [witness.buffer as ArrayBuffer]);
  } catch (e) {
    parentPort!.postMessage({ id, error: (e as Error).message });
  }
});
