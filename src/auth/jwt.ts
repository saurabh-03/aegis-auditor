/**
 * Minimal HS256 JWT implementation using Node crypto (no external dependency).
 * Sufficient for first-party access/refresh tokens; swap for a vetted library
 * if you later need RS256/asymmetric keys or richer claim validation.
 */

import { createHmac, timingSafeEqual } from 'node:crypto';

function b64url(input: Buffer | string): string {
  return Buffer.from(input).toString('base64url');
}

export interface JwtClaims {
  sub: string; // user id
  typ: 'access' | 'refresh';
  [key: string]: unknown;
}

function secret(): string {
  return process.env.JWT_SECRET ?? 'dev-insecure-secret-change-me';
}

export function signJwt(claims: JwtClaims, ttlSeconds: number): string {
  const header = { alg: 'HS256', typ: 'JWT' };
  const now = Math.floor(Date.now() / 1000);
  const payload = { ...claims, iat: now, exp: now + ttlSeconds };
  const head = b64url(JSON.stringify(header));
  const body = b64url(JSON.stringify(payload));
  const sig = createHmac('sha256', secret()).update(`${head}.${body}`).digest('base64url');
  return `${head}.${body}.${sig}`;
}

export interface VerifyResult {
  valid: boolean;
  claims?: JwtClaims & { iat: number; exp: number };
  reason?: string;
}

export function verifyJwt(token: string): VerifyResult {
  const parts = token.split('.');
  if (parts.length !== 3) return { valid: false, reason: 'malformed' };
  const [head, body, sig] = parts as [string, string, string];
  const expected = createHmac('sha256', secret()).update(`${head}.${body}`).digest('base64url');
  const a = Buffer.from(sig);
  const b = Buffer.from(expected);
  if (a.length !== b.length || !timingSafeEqual(a, b)) return { valid: false, reason: 'bad_signature' };
  let claims: JwtClaims & { iat: number; exp: number };
  try {
    claims = JSON.parse(Buffer.from(body, 'base64url').toString('utf8'));
  } catch {
    return { valid: false, reason: 'bad_payload' };
  }
  if (typeof claims.exp === 'number' && claims.exp < Math.floor(Date.now() / 1000)) {
    return { valid: false, reason: 'expired' };
  }
  return { valid: true, claims };
}

export const ACCESS_TTL = 60 * 15; // 15 minutes
export const REFRESH_TTL = 60 * 60 * 24 * 30; // 30 days
