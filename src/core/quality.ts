/**
 * Finding-quality pass: cross-engine deduplication + corroboration.
 *
 * The crawler-driven active engines (Nuclei, ZAP) plus the passive modules
 * routinely report the SAME underlying issue many times — e.g. "missing CSP" as
 * one passive finding, six per-endpoint ZAP alerts, and a Nuclei hit. Left raw
 * that is noise, and it also distorts scoring (each duplicate applies its own
 * severity penalty). This pass collapses duplicates into one representative
 * finding that records which engines corroborated it and which URLs it affects.
 *
 * Corroboration is a signal, not just cleanup: when two or more independent
 * engines flag the same issue, confidence is raised to `confirmed` — the same
 * reasoning a human triager uses.
 *
 * Pure and side-effect-free so it is fully unit-testable. Only `fail`/`warn`
 * findings are considered; `pass`/`info` are passed through untouched.
 */

import type { Confidence, Finding, Severity } from './types.js';

const SEV_RANK: Record<Severity, number> = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
const CONF_RANK: Record<Confidence, number> = { confirmed: 3, firm: 2, tentative: 1 };

function confRank(c?: Confidence): number {
  return c ? CONF_RANK[c] : 0;
}

/**
 * Issue classes. `siteWide` classes (header/TLS/server posture) describe the
 * whole site and collapse across all paths; the rest are location-specific and
 * only merge at the same URL+param. Order matters — first match wins.
 */
const CLASS_RULES: Array<{ re: RegExp; cls: string; siteWide: boolean }> = [
  { re: /content.?security.?policy|\bcsp\b/i, cls: 'csp', siteWide: true },
  { re: /strict.?transport.?security|\bhsts\b/i, cls: 'hsts', siteWide: true },
  { re: /clickjack|x.?frame.?options|frame.?ancestors/i, cls: 'clickjacking', siteWide: true },
  { re: /x.?content.?type.?options|nosniff|mime.?sniff/i, cls: 'nosniff', siteWide: true },
  { re: /referrer.?policy/i, cls: 'referrer-policy', siteWide: true },
  { re: /permissions.?policy|feature.?policy/i, cls: 'permissions-policy', siteWide: true },
  { re: /server.{0,20}version|version.{0,20}(leak|disclos)|x.?powered.?by/i, cls: 'server-version', siteWide: true },
  { re: /\.git|git.?config|git repository/i, cls: 'git-exposure', siteWide: false },
  { re: /\.env|environment file/i, cls: 'env-exposure', siteWide: false },
  { re: /sql.?injection|sqli/i, cls: 'sqli', siteWide: false },
  { re: /cross.?site.?scripting|\bxss\b/i, cls: 'xss', siteWide: false },
  { re: /open.?redirect/i, cls: 'open-redirect', siteWide: false },
];

function slug(s: string): string {
  return s.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '').slice(0, 60);
}

/** Location key (host + path + param) for location-specific findings. */
function locationKey(f: Finding): string {
  const url = f.location?.url;
  if (!url) return '';
  try {
    const u = new URL(url);
    return `${u.host}${u.pathname}#${f.location?.param ?? ''}`;
  } catch {
    return `${url}#${f.location?.param ?? ''}`;
  }
}

/**
 * A stable signature identifying "the same issue". Includes the category so a
 * merge never moves a finding between scoring buckets. Unknown issue types fall
 * back to cwe+title at their exact location — conservative, so distinct issues
 * are never wrongly merged.
 */
export function signatureOf(f: Finding): string {
  const title = f.title ?? '';
  const rule = CLASS_RULES.find((r) => r.re.test(title));
  if (rule) {
    return rule.siteWide
      ? `${f.category}|sw|${rule.cls}`
      : `${f.category}|loc|${rule.cls}|${locationKey(f)}`;
  }
  const cwe = (f.cwe && f.cwe[0]) || '';
  return `${f.category}|fb|${cwe}|${slug(title)}|${locationKey(f)}`;
}

/** Pick the representative: highest severity, then confidence, then a fail over a warn. */
function pickRepresentative(group: Finding[]): Finding {
  return [...group].sort((a, b) => {
    if (SEV_RANK[b.severity] !== SEV_RANK[a.severity]) return SEV_RANK[b.severity] - SEV_RANK[a.severity];
    if (confRank(b.confidence) !== confRank(a.confidence)) return confRank(b.confidence) - confRank(a.confidence);
    const st = (x: Finding) => (x.status === 'fail' ? 0 : 1);
    return st(a) - st(b);
  })[0] as Finding;
}

export interface RefineResult {
  /** Deduplicated findings (pass/info preserved as-is). */
  findings: Finding[];
  /** How many findings were collapsed away by merging. */
  merged: number;
}

/**
 * Deduplicate corroborating findings. `fail`/`warn` findings sharing a signature
 * are collapsed into one representative carrying `corroboratedBy` (the distinct
 * modules that reported it) and, in evidence, the affected URLs and occurrence
 * count. When ≥2 distinct engines agree, confidence is raised to `confirmed`.
 */
export function refineFindings(findings: Finding[]): RefineResult {
  const scored: Finding[] = [];
  const passthrough: Finding[] = [];
  for (const f of findings) {
    if (f.status === 'fail' || f.status === 'warn') scored.push(f);
    else passthrough.push(f);
  }

  const groups = new Map<string, Finding[]>();
  for (const f of scored) {
    const key = signatureOf(f);
    const g = groups.get(key);
    if (g) g.push(f);
    else groups.set(key, [f]);
  }

  const deduped: Finding[] = [];
  let merged = 0;

  for (const group of groups.values()) {
    if (group.length === 1) {
      deduped.push(group[0] as Finding);
      continue;
    }
    merged += group.length - 1;

    const rep = pickRepresentative(group);
    const modules = [...new Set(group.map((f) => f.module))].sort();
    const affectedUrls = [
      ...new Set(group.map((f) => f.location?.url).filter((u): u is string => Boolean(u))),
    ].slice(0, 25);

    const out: Finding = {
      ...rep,
      corroboratedBy: modules,
      evidence: {
        ...(rep.evidence ?? {}),
        occurrences: group.length,
        ...(affectedUrls.length ? { affectedUrls } : {}),
        reportedBy: modules,
      },
    };

    // Independent corroboration → confirmed. Distinct *engines*, not two alerts
    // from the same tool.
    if (modules.length >= 2 && confRank(out.confidence) < CONF_RANK.confirmed) {
      out.confidence = 'confirmed';
    }
    deduped.push(out);
  }

  return { findings: [...deduped, ...passthrough], merged };
}
