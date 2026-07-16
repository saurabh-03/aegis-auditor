/**
 * Nuclei active-DAST module. ACTIVE, authorization-gated.
 *
 * Reads the shared attack surface (`ctx.getSurface()`), hands the discovered
 * endpoints to the Nuclei binary via the adapter, and maps each template match
 * into a fully-explained {@link Finding}. Because `mode: 'active'`, the engine's
 * existing gate (scanner.ts) only runs this when `authorized && includeActive`
 * — which the project layer sets only after domain-ownership verification.
 *
 * Graceful degradation: if Nuclei isn't installed the adapter returns null and
 * this module emits a single info finding rather than failing the scan.
 *
 * The result→Finding mapping (`mapNucleiResults`) is exported and pure so it can
 * be unit-tested against fixture output without the binary present.
 */

import { createHash } from 'node:crypto';
import { config } from '../../core/config.js';
import { finding, pass } from '../../core/finding.js';
import { buildAuthHeaders } from '../../core/http.js';
import { runNuclei, type NucleiResult, type NucleiSeverity } from '../../integrations/nuclei.js';
import type { Confidence, Finding, ModuleResult, ScanContext, ScanModule, Severity } from '../../core/types.js';

const MODULE = 'nuclei';

/** Nuclei severity → Aegis severity. 'unknown' is treated as informational. */
const SEVERITY_MAP: Record<NucleiSeverity, Severity> = {
  critical: 'critical',
  high: 'high',
  medium: 'medium',
  low: 'low',
  info: 'info',
  unknown: 'info',
};

function probabilityFor(sev: Severity): 'low' | 'medium' | 'high' {
  if (sev === 'critical' || sev === 'high') return 'high';
  if (sev === 'medium') return 'medium';
  return 'low';
}

/** Info-severity templates are usually fingerprints/exposures → lower confidence. */
function confidenceFor(sev: Severity): Confidence {
  return sev === 'info' ? 'tentative' : 'firm';
}

function shortHash(s: string): string {
  return createHash('sha1').update(s).digest('hex').slice(0, 10);
}

/**
 * Map normalized Nuclei results into Findings. Dedups by template + matched
 * location so the same template firing on the same endpoint yields one finding;
 * the id embeds a hash of the location so the regression-diff engine tracks
 * "this issue on this endpoint" across scans.
 */
export function mapNucleiResults(results: NucleiResult[]): Finding[] {
  const byKey = new Map<string, NucleiResult>();
  for (const r of results) {
    const key = `${r.templateId}::${r.matchedAt}`;
    if (!byKey.has(key)) byKey.set(key, r);
  }

  const findings: Finding[] = [];
  for (const r of byKey.values()) {
    const severity = SEVERITY_MAP[r.severity];
    const status = severity === 'info' ? 'warn' : 'fail';
    const refs = r.reference.length ? r.reference : [`https://cloud.projectdiscovery.io/public/${r.templateId}`];

    findings.push(
      finding({
        id: `nuclei.${r.templateId}.${shortHash(r.matchedAt)}`,
        module: MODULE,
        category: 'security',
        title: r.name || r.templateId,
        severity,
        status,
        confidence: confidenceFor(severity),
        location: { url: r.matchedAt },
        risk:
          r.description?.trim() ||
          `Nuclei template "${r.templateId}" matched at this endpoint, indicating a known vulnerability or exposure.`,
        whyItMatters:
          'This match comes from a community-maintained detection template for a known issue (CVE, misconfiguration, or exposure). Known issues are the ones attackers scan for first because working exploits are already public.',
        technical: `Template "${r.templateId}" (severity: ${r.severity}) matched at ${r.matchedAt}.` +
          (r.cve.length ? ` CVE: ${r.cve.join(', ')}.` : '') +
          (r.cwe.length ? ` CWE: ${r.cwe.join(', ')}.` : '') +
          (r.cvss !== undefined ? ` CVSS: ${r.cvss}.` : ''),
        businessImpact:
          severity === 'critical' || severity === 'high'
            ? 'A known, likely-exploitable weakness exposed to the internet — high breach potential.'
            : severity === 'medium'
            ? 'A known weakness that meaningfully increases attack surface.'
            : 'Information disclosure or minor exposure useful to an attacker during reconnaissance.',
        probability: probabilityFor(severity),
        ...(r.cve.length ? { cve: r.cve } : {}),
        ...(r.cwe.length ? { cwe: r.cwe } : {}),
        remediation:
          r.remediation?.trim() ||
          'Consult the linked template/advisory for the specific fix (patch the affected component, remove the exposure, or apply the recommended configuration).',
        estimatedFixTime: severity === 'critical' || severity === 'high' ? '0.5-2 days' : '1-4 hours',
        references: refs,
        ...(r.request || r.response
          ? { requestResponse: { request: r.request ?? '', response: r.response ?? '' } }
          : {}),
        evidence: { templateId: r.templateId, tags: r.tags, matchedAt: r.matchedAt, cvss: r.cvss },
      }),
    );
  }

  // Most-severe first is applied globally by the scorer; return as-is.
  return findings;
}

export const nucleiModule: ScanModule = {
  name: MODULE,
  title: 'Nuclei Template Scan',
  category: 'security',
  mode: 'active',
  description:
    'Runs the Nuclei engine (community CVE/misconfiguration templates) against crawled endpoints. Requires authorization; degrades to info if Nuclei is not installed.',
  async run(ctx: ScanContext): Promise<ModuleResult> {
    const t0 = performance.now();

    const surface = await ctx.getSurface();
    // Unique absolute URLs, capped to bound run time.
    const urls = [...new Set(surface.endpoints.map((e) => e.url))].slice(0, config.nuclei.maxTargets);

    if (urls.length === 0) {
      return {
        module: MODULE,
        category: 'security',
        ok: true,
        findings: [pass(MODULE, 'security', 'nuclei.no-targets', 'No endpoints to scan', 'The crawl produced no endpoints for template scanning.')],
        durationMs: Math.round(performance.now() - t0),
        data: { targets: 0 },
      };
    }

    const authHeaders = buildAuthHeaders(ctx.auth);
    if (ctx.auth) ctx.log('Nuclei: running authenticated (session headers injected).');
    ctx.log(`Nuclei: scanning ${urls.length} endpoint(s)…`);
    ctx.progress(0.01, `starting · ${urls.length} endpoints`);
    const results = await runNuclei(urls, {
      binaryPath: config.nuclei.binaryPath,
      severities: config.nuclei.severities,
      rateLimit: config.nuclei.rateLimit,
      timeoutMs: config.nuclei.timeoutMs,
      includeRequestResponse: true,
      ...(Object.keys(authHeaders).length ? { headers: authHeaders } : {}),
      onProgress: (fraction, note) => ctx.progress(fraction, note),
      log: ctx.log,
    });

    // Adapter returned null → binary unavailable. Emit one informational finding.
    if (results === null) {
      return {
        module: MODULE,
        category: 'security',
        ok: true,
        findings: [
          finding({
            id: 'nuclei.unavailable',
            module: MODULE,
            category: 'security',
            title: 'Active template scan skipped — Nuclei not installed',
            severity: 'info',
            status: 'info',
            risk: 'Known-CVE/misconfiguration template scanning did not run, so those issues were not checked.',
            whyItMatters:
              'Nuclei provides thousands of community detections for known vulnerabilities. Without it, this scan covers configuration/posture but not known-CVE probing of discovered endpoints.',
            technical: `The Nuclei binary "${config.nuclei.binaryPath}" was not found on PATH. Install it (https://github.com/projectdiscovery/nuclei) or set NUCLEI_BIN to enable active template scanning.`,
            businessImpact: 'Reduced detection coverage; no direct risk introduced.',
            probability: 'low',
            remediation: 'Install Nuclei on the worker host and re-run an authorized active scan.',
            estimatedFixTime: '15 minutes',
            references: ['https://github.com/projectdiscovery/nuclei'],
          }),
        ],
        durationMs: Math.round(performance.now() - t0),
        data: { available: false, targets: urls.length },
      };
    }

    const findings = mapNucleiResults(results);
    if (findings.length === 0) {
      findings.push(
        pass(
          MODULE,
          'security',
          'nuclei.clean',
          'No Nuclei template matches',
          `Nuclei scanned ${urls.length} endpoint(s) at the configured severity floor (${config.nuclei.severities.join(', ')}) and found no matches.`,
        ),
      );
    }

    return {
      module: MODULE,
      category: 'security',
      ok: true,
      findings,
      durationMs: Math.round(performance.now() - t0),
      data: {
        available: true,
        targets: urls.length,
        matches: results.length,
        severities: config.nuclei.severities,
      },
    };
  },
};
