/** Minimal in-memory fixed-window rate limiter keyed by client IP. */

import { config } from '../core/config.js';

interface Window {
  count: number;
  resetAt: number;
}

const windows = new Map<string, Window>();

export function rateLimit(key: string): { ok: boolean; remaining: number; resetAt: number } {
  const now = Date.now();
  const { windowMs, max } = config.rateLimit;
  const existing = windows.get(key);

  if (!existing || existing.resetAt <= now) {
    const w = { count: 1, resetAt: now + windowMs };
    windows.set(key, w);
    return { ok: true, remaining: max - 1, resetAt: w.resetAt };
  }

  existing.count += 1;
  const ok = existing.count <= max;
  return { ok, remaining: Math.max(0, max - existing.count), resetAt: existing.resetAt };
}
