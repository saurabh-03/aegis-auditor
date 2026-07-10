/**
 * OSV.dev client — live, keyless vulnerability lookups (https://osv.dev).
 *
 * OSV takes a package + version and returns the vulnerabilities affecting it,
 * so we do not range-match ourselves. Responses are normalized into the same
 * {@link CveEntry} shape used by the offline dataset, including a real CVSS v3.1
 * base score computed from the advisory's severity vector.
 *
 * All network failures degrade to an empty result — callers merge with the
 * offline dataset so a scan never hard-fails on OSV being unreachable.
 */

import { config } from '../core/config.js';
import type { CveEntry } from './cve-db.js';

const OSV_ENDPOINT = 'https://api.osv.dev/v1/query';

/** Fingerprint component name -> OSV package coordinates. High-precision only. */
export const PACKAGE_MAP: Record<string, { name: string; ecosystem: string }> = {
  jQuery: { name: 'jquery', ecosystem: 'npm' },
  Bootstrap: { name: 'bootstrap', ecosystem: 'npm' },
  Lodash: { name: 'lodash', ecosystem: 'npm' },
  'Moment.js': { name: 'moment', ecosystem: 'npm' },
};

interface OsvSeverity {
  type: string;
  score: string;
}
interface OsvEvent {
  introduced?: string;
  fixed?: string;
}
interface OsvAffected {
  ranges?: Array<{ type: string; events: OsvEvent[] }>;
}
interface OsvVuln {
  id: string;
  summary?: string;
  details?: string;
  aliases?: string[];
  withdrawn?: string;
  severity?: OsvSeverity[];
  affected?: OsvAffected[];
  references?: Array<{ type: string; url: string }>;
  database_specific?: { severity?: string; cwe_ids?: string[] };
}

/** CVSS v3.x base-score metric weights. */
const W = {
  AV: { N: 0.85, A: 0.62, L: 0.55, P: 0.2 },
  AC: { L: 0.77, H: 0.44 },
  UI: { N: 0.85, R: 0.62 },
  C: { N: 0, L: 0.22, H: 0.56 },
} as const;

/** Compute a CVSS v3.1 base score from a vector string. Returns 0 if unparseable. */
export function cvssBaseScore(vector: string): number {
  const m: Record<string, string> = {};
  for (const part of vector.split('/')) {
    const [k, v] = part.split(':');
    if (k && v) m[k] = v;
  }
  if (!m.AV || !m.AC || !m.PR || !m.UI || !m.S || !m.C || !m.I || !m.A) return 0;

  const scopeChanged = m.S === 'C';
  const prTable = scopeChanged ? { N: 0.85, L: 0.68, H: 0.5 } : { N: 0.85, L: 0.62, H: 0.27 };

  const av = W.AV[m.AV as keyof typeof W.AV] ?? 0;
  const ac = W.AC[m.AC as keyof typeof W.AC] ?? 0;
  const pr = prTable[m.PR as keyof typeof prTable] ?? 0;
  const ui = W.UI[m.UI as keyof typeof W.UI] ?? 0;
  const c = W.C[m.C as keyof typeof W.C] ?? 0;
  const i = W.C[m.I as keyof typeof W.C] ?? 0;
  const a = W.C[m.A as keyof typeof W.C] ?? 0;

  const iscBase = 1 - (1 - c) * (1 - i) * (1 - a);
  const impact = scopeChanged
    ? 7.52 * (iscBase - 0.029) - 3.25 * Math.pow(iscBase - 0.02, 15)
    : 6.42 * iscBase;
  const exploitability = 8.22 * av * ac * pr * ui;

  if (impact <= 0) return 0;
  const raw = scopeChanged
    ? Math.min(1.08 * (impact + exploitability), 10)
    : Math.min(impact + exploitability, 10);
  // CVSS "roundup" to one decimal.
  return Math.ceil(raw * 10) / 10;
}

export function severityFromScore(score: number): CveEntry['severity'] {
  if (score >= 9) return 'critical';
  if (score >= 7) return 'high';
  if (score >= 4) return 'medium';
  return 'low';
}

function pickCve(vuln: OsvVuln): string {
  return vuln.aliases?.find((a) => a.startsWith('CVE-')) ?? vuln.id;
}

function pickFixedIn(vuln: OsvVuln): string {
  for (const aff of vuln.affected ?? []) {
    for (const range of aff.ranges ?? []) {
      const fixed = range.events.find((e) => e.fixed)?.fixed;
      if (fixed) return fixed;
    }
  }
  return 'latest';
}

function pickReference(vuln: OsvVuln, cve: string): string {
  const advisory = vuln.references?.find((r) => r.type === 'ADVISORY')?.url;
  if (advisory) return advisory;
  return cve.startsWith('CVE-') ? `https://nvd.nist.gov/vuln/detail/${cve}` : `https://osv.dev/vulnerability/${vuln.id}`;
}

/** Query OSV for a single package+version. Returns [] on any failure. */
export async function queryOsv(
  component: string,
  pkgName: string,
  ecosystem: string,
  version: string,
  timeoutMs: number,
): Promise<CveEntry[]> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetch(OSV_ENDPOINT, {
      method: 'POST',
      signal: controller.signal,
      headers: { 'content-type': 'application/json', 'user-agent': config.userAgent },
      body: JSON.stringify({ version, package: { name: pkgName, ecosystem } }),
    });
    if (!res.ok) return [];
    const body = (await res.json()) as { vulns?: OsvVuln[] };
    const out: CveEntry[] = [];
    for (const vuln of body.vulns ?? []) {
      if (vuln.withdrawn) continue;
      const cve = pickCve(vuln);
      const vector = vuln.severity?.find((s) => s.type.startsWith('CVSS_V3'))?.score ?? '';
      let cvss = vector ? cvssBaseScore(vector) : 0;
      let severity: CveEntry['severity'];
      if (cvss > 0) {
        severity = severityFromScore(cvss);
      } else {
        // No parseable CVSS v3 vector (e.g. CVSS v4-only advisories): fall back to
        // the advisory's severity label and a representative score so ordering
        // and display stay coherent rather than showing a misleading 0.
        severity = mapLabel(vuln.database_specific?.severity);
        cvss = nominalScore(severity);
      }
      const cwe = vuln.database_specific?.cwe_ids?.[0];
      out.push({
        cve,
        cvss,
        severity,
        component,
        introduced: '0.0.0',
        fixedIn: pickFixedIn(vuln),
        summary: vuln.summary ?? vuln.details?.slice(0, 200) ?? 'See advisory for details.',
        weakness: cwe ?? 'Known vulnerability',
        reference: pickReference(vuln, cve),
      });
    }
    return out;
  } catch {
    return [];
  } finally {
    clearTimeout(timer);
  }
}

/** Representative CVSS when only a severity label is available (no v3 vector). */
function nominalScore(severity: CveEntry['severity']): number {
  return severity === 'critical' ? 9.0 : severity === 'high' ? 7.5 : severity === 'medium' ? 5.0 : 2.0;
}

function mapLabel(label?: string): CveEntry['severity'] {
  switch ((label ?? '').toUpperCase()) {
    case 'CRITICAL':
      return 'critical';
    case 'HIGH':
      return 'high';
    case 'MODERATE':
    case 'MEDIUM':
      return 'medium';
    default:
      return 'low';
  }
}
