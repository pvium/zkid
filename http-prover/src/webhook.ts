import { randomUUID } from 'node:crypto';
import type { Attestation, AttestationRequest, AttestationService } from './attestation.js';
import { InputError } from './errors.js';

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

const RETRY_DELAYS_MS = [1_000, 5_000, 30_000];

/**
 * Run the job through the service and deliver the outcome to the callback, retrying delivery a few
 * times. Never throws: the caller has already answered 202.
 */
export async function runWebhookJob(
  service: AttestationService,
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
  const headers = { 'content-type': 'application/json', 'x-pvium-job-id': jobId };
  for (let attempt = 0; ; attempt++) {
    try {
      const res = await fetch(callback, { method: 'POST', headers, body, signal: AbortSignal.timeout(15_000) });
      if (res.ok) return;
      if (res.status >= 400 && res.status < 500 && res.status !== 408 && res.status !== 429) {
        console.error(`webhook ${jobId}: callback rejected with ${res.status}; not retrying`);
        return;
      }
    } catch (e) {
      if (attempt === RETRY_DELAYS_MS.length) {
        console.error(`webhook ${jobId}: delivery failed after ${attempt + 1} attempts: ${(e as Error).message}`);
        return;
      }
    }
    if (attempt === RETRY_DELAYS_MS.length) {
      console.error(`webhook ${jobId}: delivery failed after ${attempt + 1} attempts`);
      return;
    }
    await new Promise((r) => setTimeout(r, RETRY_DELAYS_MS[attempt]));
  }
}
