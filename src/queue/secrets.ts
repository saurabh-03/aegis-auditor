/**
 * Per-scan credential handling at the queue boundary.
 *
 * `ScanOptions.auth` holds secrets (session cookies, bearer tokens, login
 * passwords). The persisted store never sees them — `ScanRecord` has no auth
 * field and the report is credential-free. The ONE place they would otherwise
 * be persisted is the BullMQ job payload: BullMQ retains completed/failed jobs
 * in Redis (`removeOnComplete`/`removeOnFail`), so a raw `auth` on the job would
 * sit in Redis long after the scan.
 *
 * Fix: never put `auth` on the persisted job. `splitJobSecret` separates the
 * secret from a sanitized job; the queue stashes the secret in a short-TTL Redis
 * key (auto-expiring, out of the retained job history) and the worker reattaches
 * it just before running. The in-process queue has no persistence boundary, so
 * it keeps `auth` on the in-memory job and never touches Redis.
 */

import type { ScanAuth } from '../core/types.js';
import type { ScanJob } from './types.js';

/**
 * Split a job into a sanitized copy (no credentials — safe to persist) and the
 * extracted `auth`. Pure; the original job is not mutated.
 */
export function splitJobSecret(job: ScanJob): { sanitized: ScanJob; auth?: ScanAuth } {
  if (!job.options.auth) return { sanitized: job };
  const { auth, ...restOptions } = job.options;
  return { sanitized: { ...job, options: restOptions }, auth };
}

/** Redis key holding a scan's transient credentials. */
export function secretKey(scanId: string): string {
  return `aegis:secret:${scanId}`;
}

/** How long a stashed credential may live in Redis before auto-expiry. */
export function secretTtlSec(): number {
  const n = Number(process.env.SCAN_SECRET_TTL_SEC ?? 3600);
  return Number.isFinite(n) && n > 0 ? n : 3600;
}

/** Minimal Redis surface we need — satisfied by ioredis. */
export interface RedisLike {
  set(key: string, value: string, mode: 'EX', ttlSec: number): Promise<unknown>;
  get(key: string): Promise<string | null>;
  del(key: string): Promise<unknown>;
}

/** Stash a scan's credentials in Redis with a bounded TTL. */
export async function stashSecret(redis: RedisLike, scanId: string, auth: ScanAuth): Promise<void> {
  await redis.set(secretKey(scanId), JSON.stringify(auth), 'EX', secretTtlSec());
}

/**
 * Read a scan's credentials back (worker side). Returns null if absent/expired.
 * Does NOT delete: BullMQ may retry the job, and the retry needs the credential
 * too — the TTL is what bounds the secret's lifetime, not a one-shot read.
 */
export async function readSecret(redis: RedisLike, scanId: string): Promise<ScanAuth | null> {
  const raw = await redis.get(secretKey(scanId)).catch(() => null);
  if (!raw) return null;
  try {
    return JSON.parse(raw) as ScanAuth;
  } catch {
    return null;
  }
}
