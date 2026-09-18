import { randomUUID } from 'node:crypto';
import type { Attestation, AttestationRequest, AttestationService } from './attestation.js';
import { InputError } from './errors.js';
import type { Outbox } from './outbox.js';

export interface JobResult {
  jobId: string;
  status: 'ok' | 'error';
  attestation?: Attestation;
  error?: string;
  /** Echoed so the receiver can correlate without storing the job id. */
  identityType: string;
  identityValue: string;
  wallet: string | null;
}

/**
 * Validate a callback URL: absolute, https (http only when explicitly allowed). Callers who want to
 * authenticate deliveries put a secret in the URL (query string or path) and check it on receipt;
 * the attestation itself is also independently verifiable.
 */
export function parseCallbackUrl(raw: string, allowHttp: boolean): URL {
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    throw new InputError('callbackUrl is not a valid URL');
  }
  if (url.protocol !== 'https:' && !(allowHttp && url.protocol === 'http:')) throw new InputError('callbackUrl must use https');
  return url;
}

/** One delivery attempt. Resolves to `null` on 2xx, otherwise to an error string; `final` marks a 4xx we must not retry. */
export async function deliver(callbackUrl: string, jobId: string, body: string): Promise<{ error: string; final: boolean } | null> {
  try {
    const res = await fetch(callbackUrl, {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'x-pvium-job-id': jobId },
      body,
      signal: AbortSignal.timeout(15_000),
    });
    if (res.ok) return null;
    const final = res.status >= 400 && res.status < 500 && res.status !== 408 && res.status !== 429;
    return { error: `callback responded ${res.status}`, final };
  } catch (e) {
    return { error: (e as Error).message, final: false };
  }
}

/**
 * Generate the attestation, persist the outcome in the outbox, then try to deliver it once. If
 * delivery fails, the Dispatcher keeps retrying from the outbox. Never throws: the caller has
 * already answered 202. The row is written before the first attempt so a crash after proving
 * cannot lose the proof.
 */
export async function runWebhookJob(
  service: AttestationService,
  outbox: Outbox,
  req: AttestationRequest,
  callback: URL,
  jobId = randomUUID(),
): Promise<void> {
  const base = { jobId, identityType: req.identityType, identityValue: req.identityValue, wallet: req.wallet ?? null };
  let result: JobResult;
  try {
    result = { ...base, status: 'ok', attestation: await service.generate(req) };
  } catch (e) {
    result = { ...base, status: 'error', error: (e as Error).message };
  }
  const body = JSON.stringify(result);
  outbox.insert({ jobId, callbackUrl: callback.toString(), body, identityType: base.identityType, identityValue: base.identityValue, wallet: base.wallet });
  const failure = await deliver(callback.toString(), jobId, body);
  if (failure) outbox.markAttemptFailed(jobId, failure.error, failure.final);
  else outbox.markDelivered(jobId);
  console.log(`${new Date().toISOString()} job ${jobId} ${result.status} type=${req.identityType} wallet=${req.wallet ?? '-'} callback=${callback.host} delivery=${failure ? `failed (${failure.error})` : 'delivered'}`);
}

/** Periodically re-delivers due outbox rows. Runs once immediately on start (restart recovery). */
export class Dispatcher {
  private timer?: NodeJS.Timeout;
  private running = false;

  constructor(private readonly outbox: Outbox, private readonly intervalMs = 30_000, private readonly batch = 20) {}

  start(): void {
    void this.tick();
    this.timer = setInterval(() => void this.tick(), this.intervalMs);
    this.timer.unref();
  }

  stop(): void {
    if (this.timer) clearInterval(this.timer);
  }

  async tick(): Promise<void> {
    if (this.running) return;
    this.running = true;
    try {
      for (const job of this.outbox.due(this.batch)) {
        const failure = await deliver(job.callbackUrl, job.jobId, job.body);
        if (failure) this.outbox.markAttemptFailed(job.jobId, failure.error, failure.final);
        else this.outbox.markDelivered(job.jobId);
        console.log(`${new Date().toISOString()} job ${job.jobId} retry ${job.attempts + 1} delivery=${failure ? `failed (${failure.error})` : 'delivered'}`);
      }
    } catch (e) {
      console.error('dispatcher tick failed:', (e as Error).message);
    } finally {
      this.running = false;
    }
  }
}
