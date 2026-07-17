/**
 * OWASP ZAP active-DAST module. ACTIVE, authorization-gated.
 *
 * Drives a ZAP daemon (via the adapter) to actively scan the crawled endpoints —
 * submitting payloads to find injection/XSS/misconfiguration classes that
 * passive checks can't. Because `mode: 'active'`, the engine only runs it on an
 * authorized scan (authorized && includeActive), which the project layer permits
 * only after domain-ownership verification.
 *
 * The daemon is optional infrastructure (a worker sidecar): if `ZAP_API_URL`
 * isn't configured or the daemon is unreachable, the module emits a single info
 * finding instead of failing. `mapZapAlerts` is exported and pure so the
 * alert→Finding mapping is unit-testable without a running daemon.
 */

import { createHash } from 'node:crypto';
import { config } from '../../core/config.js';
import { finding, pass } from '../../core/finding.js';
import { buildAuthHeaders } from '../../core/http.js';
import { runZapScan, type ZapAlert, type ZapRisk } from '../../integrations/zap.js';
import type { Confidence, Finding, ModuleResult, ScanContext, ScanModule, Severity } from '../../core/types.js';

const MODULE = 'zap';

/** ZAP risk → Aegis severity. ZAP tops out at High (no distinct 'critical'). */
const RISK_MAP: Record<ZapRisk, Severity> = {
  High: 'high',
  Medium: 'medium',
  Low: 'low',
  Informational: 'info',
};

/** ZAP confidence label → Aegis confidence. False positives are filtered upstream. */
function mapConfidence(zapConfidence: string): Confidence {
  const c = zapConfidence.toLowerCase();
  if (c === 'confirmed' || c === 'high') return 'confirmed';
  if (c === 'medium') return 'firm';
  return 'tentative';
}

function probabilityFor(sev: Severity): 'low' | 'medium' | 'high' {
  if (sev === 'critical' || sev === 'high') return 'high';
  if (sev === 'medium') return 'medium';
  return 'low';
}

function shortHash(s: string): string {
  return createHash('sha1').update(s).digest('hex').slice(0, 10);
}

/**
 * Map normalized ZAP alerts into Findings. Drops false positives, dedups by
 * plugin + URL + param (ZAP fires per-request), and builds per-endpoint ids so
 * the regression-diff engine tracks an alert on a specific endpoint over time.
 */
export function mapZapAlerts(alerts: ZapAlert[]): Finding[] {
  const byKey = new Map<string, ZapAlert>();
  for (const a of alerts) {
    if (a.confidence.toLowerCase() === 'false positive') continue;
    const key = `${a.pluginId}::${a.url}::${a.param ?? ''}`;
    if (!byKey.has(key)) byKey.set(key, a);
  }

  const findings: Finding[] = [];
  for (const a of byKey.values()) {
    const severity = RISK_MAP[a.risk];
    const status = severity === 'info' ? 'warn' : 'fail';
    const refs = (a.reference ?? '')
      .split(/\s+/)
      .map((r) => r.trim())
      .filter((r) => /^https?:\/\//.test(r));

    const evidenceBits: string[] = [];
    if (a.attack) evidenceBits.push(`Attack: ${a.attack}`);
    if (a.evidence) evidenceBits.push(`Evidence: ${a.evidence}`);

    findings.push(
      finding({
        id: `zap.${a.pluginId}.${shortHash(`${a.url}::${a.param ?? ''}`)}`,
        module: MODULE,
        category: 'security',
        title: a.name,
        severity,
        status,
        confidence: mapConfidence(a.confidence),
        location: { url: a.url, ...(a.param ? { param: a.param } : {}), ...(a.method ? { method: a.method } : {}) },
        risk:
          a.description?.trim() ||
          `ZAP flagged "${a.name}" at this endpoint through active testing (payload submission).`,
        whyItMatters:
          'This was found by actively exercising the endpoint — ZAP submitted crafted input and observed a vulnerable response. Active findings represent reachable, demonstrable weaknesses rather than configuration inference.',
        technical:
          `ZAP plugin ${a.pluginId} raised "${a.name}" (risk: ${a.risk}, confidence: ${a.confidence}) at ${a.url}` +
          `${a.param ? ` on parameter "${a.param}"` : ''}${a.method ? ` via ${a.method}` : ''}.` +
          (evidenceBits.length ? ` ${evidenceBits.join(' · ')}.` : ''),
        businessImpact:
          severity === 'high'
            ? 'A demonstrable, exploitable weakness exposed to the internet — high breach potential.'
            : severity === 'medium'
            ? 'A confirmed weakness that meaningfully increases attack surface.'
            : 'Minor issue or information disclosure useful to an attacker.',
        probability: probabilityFor(severity),
        ...(a.cweid ? { cwe: [`CWE-${a.cweid}`] } : {}),
        remediation:
          a.solution?.trim() ||
          'Review the affected endpoint/parameter and apply input validation, output encoding, or the control ZAP recommends for this alert class.',
        estimatedFixTime: severity === 'high' ? '0.5-3 days' : severity === 'medium' ? '2-8 hours' : '1-2 hours',
        references: refs,
        ...(evidenceBits.length
          ? { requestResponse: { request: a.attack ?? '', response: a.evidence ?? '' } }
          : {}),
        evidence: { pluginId: a.pluginId, param: a.param, method: a.method, cweid: a.cweid, wascid: a.wascid },
      }),
    );
  }

  return findings;
}

export const zapModule: ScanModule = {
  name: MODULE,
  title: 'OWASP ZAP Active Scan',
  category: 'security',
  mode: 'active',
  description:
    'Runs an OWASP ZAP active scan (payload injection) against crawled endpoints via a ZAP daemon. Requires authorization; degrades to info if no daemon is configured.',
  async run(ctx: ScanContext): Promise<ModuleResult> {
    const t0 = performance.now();

    // Not configured → skip cleanly (no daemon to talk to).
    if (!config.zap.apiUrl) {
      return {
        module: MODULE,
        category: 'security',
        ok: true,
        findings: [
          finding({
            id: 'zap.unconfigured',
            module: MODULE,
            category: 'security',
            title: 'Active scan skipped — ZAP daemon not configured',
            severity: 'info',
            status: 'info',
            risk: 'Active injection/XSS testing did not run, so those vulnerability classes were not exercised.',
            whyItMatters:
              'ZAP actively submits payloads to find injection, XSS, and related flaws that passive posture checks cannot detect. Without a configured daemon this coverage is absent.',
            technical: 'Set ZAP_API_URL (and ZAP_API_KEY) to a reachable ZAP daemon on the worker to enable active scanning.',
            businessImpact: 'Reduced detection coverage; no direct risk introduced.',
            probability: 'low',
            remediation: 'Run a ZAP daemon as a worker sidecar and set ZAP_API_URL; then re-run an authorized active scan.',
            estimatedFixTime: '30 minutes',
            references: ['https://www.zaproxy.org/docs/docker/about/'],
          }),
        ],
        durationMs: Math.round(performance.now() - t0),
        data: { configured: false },
      };
    }

    const surface = await ctx.getSurface();
    const urls = [...new Set(surface.endpoints.map((e) => e.url))].slice(0, config.zap.maxSeedUrls);

    const authHeaders = buildAuthHeaders(ctx.auth);
    if (ctx.auth) ctx.log('ZAP: running authenticated (session headers via replacer rules).');
    ctx.log(`ZAP: active scan of ${ctx.target.origin} seeded with ${urls.length} endpoint(s)…`);
    ctx.progress(0.01, `seeding ${urls.length} endpoints`);
    const alerts = await runZapScan(urls, {
      apiUrl: config.zap.apiUrl,
      apiKey: config.zap.apiKey,
      target: ctx.target.origin,
      timeoutMs: config.zap.timeoutMs,
      maxSeedUrls: config.zap.maxSeedUrls,
      ...(Object.keys(authHeaders).length ? { headers: authHeaders } : {}),
      onProgress: (fraction, note) => ctx.progress(fraction, note),
      log: ctx.log,
    });

    // Daemon unreachable → info finding.
    if (alerts === null) {
      return {
        module: MODULE,
        category: 'security',
        ok: true,
        findings: [
          finding({
            id: 'zap.unavailable',
            module: MODULE,
            category: 'security',
            title: 'Active scan skipped — ZAP daemon unreachable',
            severity: 'info',
            status: 'info',
            risk: 'Active injection/XSS testing did not run because the ZAP daemon could not be reached.',
            whyItMatters:
              'The ZAP daemon is configured but did not respond, so active vulnerability testing was skipped for this scan.',
            technical: `Could not reach the ZAP daemon at ${config.zap.apiUrl}. Check that the daemon is running and the API key is correct.`,
            businessImpact: 'Reduced detection coverage for this run; no direct risk introduced.',
            probability: 'low',
            remediation: 'Verify the ZAP daemon health and connectivity from the worker, then re-run the scan.',
            estimatedFixTime: '15 minutes',
            references: ['https://www.zaproxy.org/docs/docker/about/'],
          }),
        ],
        durationMs: Math.round(performance.now() - t0),
        data: { configured: true, available: false, targets: urls.length },
      };
    }

    const findings = mapZapAlerts(alerts);
    if (findings.length === 0) {
      findings.push(
        pass(
          MODULE,
          'security',
          'zap.clean',
          'No ZAP active-scan alerts',
          `ZAP actively scanned ${ctx.target.origin} (${urls.length} seeded endpoint(s)) and raised no actionable alerts.`,
        ),
      );
    }

    return {
      module: MODULE,
      category: 'security',
      ok: true,
      findings,
      durationMs: Math.round(performance.now() - t0),
      data: { configured: true, available: true, targets: urls.length, alerts: alerts.length },
    };
  },
};
