/** Module 16 — CORS configuration analysis. */

import { finding, pass } from '../core/finding.js';
import type { Finding, ModuleResult, ScanContext, ScanModule } from '../core/types.js';

const MODULE = 'cors';
const PROBE_ORIGIN = 'https://aegis-audit-probe.example';

export const corsModule: ScanModule = {
  name: MODULE,
  title: 'CORS',
  category: 'security',
  mode: 'passive',
  description: 'Probes Cross-Origin Resource Sharing headers for permissive reflection.',
  async run(ctx: ScanContext): Promise<ModuleResult> {
    const t0 = performance.now();
    const findings: Finding[] = [];

    // A single benign GET with an Origin header — passive, no state change.
    const res = await ctx.fetch(ctx.target.toString(), {
      redirect: 'manual',
      headers: { origin: PROBE_ORIGIN },
    }).catch(() => null);

    if (!res) {
      findings.push(pass(MODULE, 'security', 'cors.unreachable', 'CORS probe skipped', 'Could not complete the CORS probe request.'));
      return { module: MODULE, category: 'security', ok: true, findings, durationMs: Math.round(performance.now() - t0) };
    }

    const acao = res.headers.get('access-control-allow-origin');
    const acac = res.headers.get('access-control-allow-credentials');

    if (!acao) {
      findings.push(pass(MODULE, 'security', 'cors.none', 'No CORS headers on homepage', 'The homepage does not emit Access-Control-Allow-Origin, so it is not exposed cross-origin.'));
    } else if (acao === '*' && acac === 'true') {
      findings.push(
        finding({
          id: 'cors.wildcard-credentials',
          module: MODULE,
          category: 'security',
          title: 'CORS allows any origin with credentials',
          severity: 'critical',
          status: 'fail',
          risk: 'Any website can read authenticated responses from this endpoint on behalf of a logged-in user.',
          whyItMatters:
            'Allow-Origin: * together with Allow-Credentials: true lets a malicious site make credentialed cross-origin requests and read the responses — a direct data-theft vector.',
          technical:
            'Browsers technically forbid `*` with credentials, but servers that reflect it are usually reflecting the request Origin too. Confirm whether the Origin is reflected; either way this configuration is dangerous.',
          businessImpact: 'Mass exfiltration of user data; account and session compromise.',
          probability: 'high',
          owasp: ['A05:2021-Security Misconfiguration', 'A01:2021-Broken Access Control'],
          remediation: 'Never combine credentials with a wildcard. Use a strict server-side allow-list of trusted origins.',
          estimatedFixTime: '2-4 hours',
          exampleCode:
            "// Express\nconst allowed = new Set(['https://app.example.com']);\napp.use((req,res,next)=>{\n  const o = req.headers.origin;\n  if (o && allowed.has(o)) {\n    res.setHeader('Access-Control-Allow-Origin', o);\n    res.setHeader('Access-Control-Allow-Credentials','true');\n    res.setHeader('Vary','Origin');\n  }\n  next();\n});",
          references: ['https://portswigger.net/web-security/cors'],
          evidence: { acao, acac },
        }),
      );
    } else if (acao === PROBE_ORIGIN) {
      findings.push(
        finding({
          id: 'cors.origin-reflection',
          module: MODULE,
          category: 'security',
          title: 'CORS reflects arbitrary request Origin',
          severity: acac === 'true' ? 'high' : 'medium',
          status: 'fail',
          risk: 'The server echoes whatever Origin is sent, effectively allowing all origins.',
          whyItMatters:
            'Reflecting the Origin header defeats the purpose of an allow-list. If credentials are also allowed, attacker sites can read authenticated data.',
          technical: `The probe sent Origin: ${PROBE_ORIGIN} and the server reflected it in Access-Control-Allow-Origin. Allow-Credentials=${acac ?? 'unset'}.`,
          businessImpact: 'Cross-origin data theft, especially for authenticated APIs.',
          probability: acac === 'true' ? 'high' : 'medium',
          owasp: ['A05:2021-Security Misconfiguration'],
          remediation: 'Validate Origin against a fixed allow-list instead of reflecting it.',
          estimatedFixTime: '2-4 hours',
          references: ['https://portswigger.net/web-security/cors'],
          evidence: { acao, acac },
        }),
      );
    } else if (acao === '*') {
      findings.push(
        finding({
          id: 'cors.wildcard',
          module: MODULE,
          category: 'security',
          title: 'CORS allows any origin (no credentials)',
          severity: 'low',
          status: 'warn',
          risk: 'Public wildcard CORS is acceptable for truly public data but risky if the endpoint ever returns anything sensitive.',
          whyItMatters:
            'Access-Control-Allow-Origin: * exposes responses to every site. This is fine for public assets but a liability if the same origin serves user-specific data elsewhere.',
          technical: 'Confirm no authenticated or user-specific data is served under this origin with a wildcard policy.',
          businessImpact: 'Potential data exposure if the policy is applied too broadly.',
          probability: 'low',
          owasp: ['A05:2021-Security Misconfiguration'],
          remediation: 'Scope CORS to specific origins for any non-public endpoints.',
          estimatedFixTime: '1-2 hours',
          references: ['https://developer.mozilla.org/docs/Web/HTTP/CORS'],
          evidence: { acao },
        }),
      );
    } else {
      findings.push(pass(MODULE, 'security', 'cors.scoped', 'CORS origin is scoped', `Access-Control-Allow-Origin is set to a specific origin (${acao}), not a wildcard or reflection.`, { acao }));
    }

    return { module: MODULE, category: 'security', ok: true, findings, durationMs: Math.round(performance.now() - t0), data: { acao, acac } };
  },
};
