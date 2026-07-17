/**
 * Active finding replay — the last mile of false-positive suppression.
 *
 * Active engines (ZAP/Nuclei) occasionally report an issue that a fresh request
 * no longer shows (transient state, a caching/proxy quirk, or a plain false
 * positive). For findings we can cheaply and SAFELY re-verify, we re-issue the
 * request and check a class-specific predicate:
 *
 *   - reproduced   → the issue is real right now → confidence raised to `confirmed`
 *   - contradicted → the issue does NOT reproduce → demoted to an `info` note so
 *                    it stops penalizing the score, but stays visible for audit
 *   - skipped      → not safely/cheaply verifiable (injection classes), or a
 *                    network error — the finding is left untouched
 *
 * Only deterministic, non-intrusive GETs are used: header presence/absence and
 * exposed-file reachability. Injection classes (SQLi/XSS/open-redirect) are
 * NEVER auto-replayed — re-sending an attack payload is intrusive — so they are
 * reported honestly as "not independently replayed".
 *
 * Pure w.r.t. everything except the injected `fetchFn`, so it is unit-testable
 * with a fake fetch.
 */

import { classifyFinding } from './quality.js';
import type { Finding } from './types.js';

export type ReplayOutcome = 'reproduced' | 'contradicted' | 'skipped';

/** Re-fetch helper: follows redirects, honors the scan timeout, injects auth. */
export type ReplayFetch = (url: string) => Promise<Response>;

export interface ReplayOptions {
  /** Fallback base when a finding has no location URL. */
  targetOrigin: string;
  log?: (msg: string) => void;
}

export interface ReplayResult {
  findings: Finding[];
  reproduced: number;
  contradicted: number;
  skipped: number;
}

/**
 * Per-class verifier. Returns:
 *   true  → issue reproduces, false → issue is gone (contradicted),
 *   null  → could not determine (network error) → skip.
 */
type Verifier = (url: string, fetchFn: ReplayFetch) => Promise<boolean | null>;

async function drain(res: Response): Promise<void> {
  await res.arrayBuffer().catch(() => undefined);
}

/** Build a header-absence verifier: reproduced when the header is missing. */
function headerAbsent(name: string): Verifier {
  return async (url, fetchFn) => {
    const res = await fetchFn(url).catch(() => null);
    if (!res) return null;
    await drain(res);
    return !res.headers.get(name);
  };
}

const VERIFIERS: Record<string, Verifier> = {
  csp: headerAbsent('content-security-policy'),
  hsts: headerAbsent('strict-transport-security'),
  'referrer-policy': headerAbsent('referrer-policy'),
  'permissions-policy': headerAbsent('permissions-policy'),

  nosniff: async (url, fetchFn) => {
    const res = await fetchFn(url).catch(() => null);
    if (!res) return null;
    await drain(res);
    const v = res.headers.get('x-content-type-options');
    return !v || !/nosniff/i.test(v); // reproduced when NOT correctly set
  },

  clickjacking: async (url, fetchFn) => {
    const res = await fetchFn(url).catch(() => null);
    if (!res) return null;
    await drain(res);
    const xfo = res.headers.get('x-frame-options');
    const csp = res.headers.get('content-security-policy') ?? '';
    return !xfo && !/frame-ancestors/i.test(csp); // reproduced when unprotected
  },

  'server-version': async (url, fetchFn) => {
    const res = await fetchFn(url).catch(() => null);
    if (!res) return null;
    await drain(res);
    const s = res.headers.get('server') ?? '';
    return /\d/.test(s); // reproduced when the Server header still leaks a version
  },

  'git-exposure': async (url, fetchFn) => {
    const res = await fetchFn(url).catch(() => null);
    if (!res) return null;
    if (res.status !== 200) {
      await drain(res);
      return false; // no longer exposed
    }
    const body = await res.text().catch(() => '');
    return /\[core\]|repositoryformatversion/i.test(body);
  },

  'env-exposure': async (url, fetchFn) => {
    const res = await fetchFn(url).catch(() => null);
    if (!res) return null;
    if (res.status !== 200) {
      await drain(res);
      return false;
    }
    const body = await res.text().catch(() => '');
    return /^[A-Z0-9_]+=.+/m.test(body) || /DB_PASSWORD|API_KEY|SECRET/i.test(body);
  },
};

/** Resolve which URL to re-request for a finding. */
function replayUrl(f: Finding, targetOrigin: string): string {
  if (f.location?.url) return f.location.url;
  const affected = f.evidence?.affectedUrls;
  if (Array.isArray(affected) && typeof affected[0] === 'string') return affected[0];
  return targetOrigin;
}

/**
 * Re-verify each replayable fail/warn finding. Non-replayable findings and
 * pass/info findings are returned unchanged (annotated `skipped` where relevant).
 */
export async function replayFindings(
  findings: Finding[],
  fetchFn: ReplayFetch,
  opts: ReplayOptions,
): Promise<ReplayResult> {
  const log = opts.log ?? (() => {});
  let reproduced = 0;
  let contradicted = 0;
  let skipped = 0;

  const out = await Promise.all(
    findings.map(async (f): Promise<Finding> => {
      if (f.status !== 'fail' && f.status !== 'warn') return f;
      const cls = classifyFinding(f);
      const verifier = cls ? VERIFIERS[cls.cls] : undefined;
      if (!verifier) {
        // Not safely replayable (e.g. injection) — report honestly.
        skipped++;
        return { ...f, evidence: { ...(f.evidence ?? {}), replay: 'not-replayed' } };
      }

      const url = replayUrl(f, opts.targetOrigin);
      const result = await verifier(url, fetchFn);

      if (result === null) {
        skipped++;
        return { ...f, evidence: { ...(f.evidence ?? {}), replay: 'inconclusive' } };
      }
      if (result) {
        reproduced++;
        return {
          ...f,
          confidence: 'confirmed',
          evidence: { ...(f.evidence ?? {}), replay: 'reproduced', replayUrl: url },
        };
      }
      // Contradicted: demote so it no longer penalizes the score, keep it visible.
      contradicted++;
      log(`Replay contradicted "${f.title}" at ${url} — demoting to info.`);
      return {
        ...f,
        status: 'info',
        confidence: 'tentative',
        title: /not reproduced/i.test(f.title) ? f.title : `${f.title} (not reproduced on replay)`,
        evidence: { ...(f.evidence ?? {}), replay: 'not-reproduced', replayUrl: url },
      };
    }),
  );

  return { findings: out, reproduced, contradicted, skipped };
}
