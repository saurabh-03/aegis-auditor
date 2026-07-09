/**
 * Project ownership verification. A project unlocks *active* scans only after
 * the owner proves control of the target by publishing a token, via either:
 *   1. DNS TXT record:   aegis-verify=<token>
 *   2. HTTP file:        https://<target>/.well-known/aegis-verify  (body = token)
 */

import { Resolver } from 'node:dns/promises';
import { normalizeTarget, timedFetch } from '../core/http.js';

export interface VerifyOutcome {
  verified: boolean;
  method: 'dns' | 'file' | null;
  detail: string;
}

export function makeOwnershipToken(): string {
  // 24 hex chars — enough entropy, easy to paste into DNS/file.
  return 'aegis-' + Math.random().toString(16).slice(2, 14) + Math.random().toString(16).slice(2, 8);
}

export async function verifyOwnership(target: string, token: string, timeoutMs = 8000): Promise<VerifyOutcome> {
  const url = normalizeTarget(target);
  const host = url.hostname;

  // 1) DNS TXT
  try {
    const resolver = new Resolver({ timeout: timeoutMs, tries: 2 });
    const txt = await resolver.resolveTxt(host);
    const flat = txt.map((chunks) => chunks.join(''));
    if (flat.some((r) => r.replace(/\s+/g, '').toLowerCase() === `aegis-verify=${token}`.toLowerCase())) {
      return { verified: true, method: 'dns', detail: `Found TXT aegis-verify=${token} on ${host}` };
    }
  } catch {
    /* fall through to file method */
  }

  // 2) /.well-known/aegis-verify
  try {
    const res = await timedFetch(`${url.origin}/.well-known/aegis-verify`, timeoutMs, { redirect: 'follow' });
    if (res.status === 200) {
      const body = (await res.text()).trim();
      if (body === token) {
        return { verified: true, method: 'file', detail: `File token matched at ${url.origin}/.well-known/aegis-verify` };
      }
    }
  } catch {
    /* ignore */
  }

  return {
    verified: false,
    method: null,
    detail:
      `Neither method succeeded. Add a DNS TXT record "aegis-verify=${token}" on ${host}, ` +
      `or serve the token at ${url.origin}/.well-known/aegis-verify, then retry.`,
  };
}
