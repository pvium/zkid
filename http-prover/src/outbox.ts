// Durable outbox for callback jobs, on the SQLite built into Node (node:sqlite, no dependency).
// A row is written the moment a proof (or its error) exists and stays until the callback
// acknowledges it with a 2xx, so a restart never loses an attestation that was already paid for.
import { DatabaseSync } from 'node:sqlite';
import { mkdirSync } from 'node:fs';
import { dirname } from 'node:path';

export type JobStatus = 'pending' | 'delivered' | 'failed';

export interface JobRow {
  jobId: string;
  callbackUrl: string;
  /** JSON body to POST: { jobId, status, attestation | error, identityType, identityValue, wallet } */
  body: string;
  identityType: string;
  identityValue: string;
  wallet: string | null;
  status: JobStatus;
  attempts: number;
  nextAttemptAt: number; // unix ms
  lastError: string | null;
  createdAt: number;
  updatedAt: number;
  deliveredAt: number | null;
}

/** Retry schedule after a failed delivery, then every 6 h until GIVE_UP_AFTER_MS. */
const BACKOFF_MS = [60_000, 5 * 60_000, 30 * 60_000, 2 * 3_600_000];
const STEADY_MS = 6 * 3_600_000;
export const GIVE_UP_AFTER_MS = 48 * 3_600_000;

export class Outbox {
  private db: DatabaseSync;

  constructor(path: string) {
    if (path !== ':memory:') mkdirSync(dirname(path), { recursive: true });
    this.db = new DatabaseSync(path);
    this.db.exec(`
      PRAGMA journal_mode = WAL;
      PRAGMA synchronous = NORMAL;
      CREATE TABLE IF NOT EXISTS jobs (
        job_id          TEXT PRIMARY KEY,
        callback_url    TEXT NOT NULL,
        body            TEXT NOT NULL,
        identity_type   TEXT NOT NULL,
        identity_value  TEXT NOT NULL,
        wallet          TEXT,
        status          TEXT NOT NULL DEFAULT 'pending',
        attempts        INTEGER NOT NULL DEFAULT 0,
        next_attempt_at INTEGER NOT NULL,
        last_error      TEXT,
        created_at      INTEGER NOT NULL,
        updated_at      INTEGER NOT NULL,
        delivered_at    INTEGER
      );
      CREATE INDEX IF NOT EXISTS jobs_due ON jobs (status, next_attempt_at);
    `);
  }

  insert(job: Pick<JobRow, 'jobId' | 'callbackUrl' | 'body' | 'identityType' | 'identityValue' | 'wallet'>): void {
    const now = Date.now();
    this.db
      .prepare(
        `INSERT INTO jobs (job_id, callback_url, body, identity_type, identity_value, wallet, status, attempts, next_attempt_at, created_at, updated_at)
         VALUES (?, ?, ?, ?, ?, ?, 'pending', 0, ?, ?, ?)`,
      )
      .run(job.jobId, job.callbackUrl, job.body, job.identityType, job.identityValue, job.wallet, now, now, now);
  }

  get(jobId: string): JobRow | undefined {
    const r = this.db.prepare('SELECT * FROM jobs WHERE job_id = ?').get(jobId) as Record<string, unknown> | undefined;
    return r && toRow(r);
  }

  /** Pending jobs whose next attempt is due, oldest first. */
  due(limit: number, now = Date.now()): JobRow[] {
    return (this.db
      .prepare(`SELECT * FROM jobs WHERE status = 'pending' AND next_attempt_at <= ? ORDER BY next_attempt_at LIMIT ?`)
      .all(now, limit) as Record<string, unknown>[]).map(toRow);
  }

  markDelivered(jobId: string): void {
    const now = Date.now();
    this.db.prepare(`UPDATE jobs SET status = 'delivered', delivered_at = ?, updated_at = ?, last_error = NULL WHERE job_id = ?`).run(now, now, jobId);
  }

  /** Record a failed attempt; schedules the next one or gives up after GIVE_UP_AFTER_MS. */
  markAttemptFailed(jobId: string, error: string, final = false): void {
    const row = this.get(jobId);
    if (!row) return;
    const now = Date.now();
    const attempts = row.attempts + 1;
    const giveUp = final || now - row.createdAt > GIVE_UP_AFTER_MS;
    const delay = BACKOFF_MS[attempts - 1] ?? STEADY_MS;
    this.db
      .prepare(`UPDATE jobs SET status = ?, attempts = ?, next_attempt_at = ?, last_error = ?, updated_at = ? WHERE job_id = ?`)
      .run(giveUp ? 'failed' : 'pending', attempts, now + delay, error.slice(0, 500), now, jobId);
  }

  counts(): Record<JobStatus, number> {
    const out: Record<JobStatus, number> = { pending: 0, delivered: 0, failed: 0 };
    for (const r of this.db.prepare('SELECT status, COUNT(*) AS n FROM jobs GROUP BY status').all() as Array<{ status: JobStatus; n: number }>) {
      out[r.status] = r.n;
    }
    return out;
  }

  close(): void {
    this.db.close();
  }
}

function toRow(r: Record<string, unknown>): JobRow {
  return {
    jobId: r.job_id as string,
    callbackUrl: r.callback_url as string,
    body: r.body as string,
    identityType: r.identity_type as string,
    identityValue: r.identity_value as string,
    wallet: (r.wallet as string | null) ?? null,
    status: r.status as JobStatus,
    attempts: r.attempts as number,
    nextAttemptAt: r.next_attempt_at as number,
    lastError: (r.last_error as string | null) ?? null,
    createdAt: r.created_at as number,
    updatedAt: r.updated_at as number,
    deliveredAt: (r.delivered_at as number | null) ?? null,
  };
}
