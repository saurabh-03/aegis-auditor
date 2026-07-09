/** Module 17 — Content Security Policy analysis. */

import { finding, pass } from '../core/finding.js';
import type { Finding, ModuleResult, ScanContext, ScanModule } from '../core/types.js';

const MODULE = 'csp';

function parseCsp(value: string): Map<string, string[]> {
  const map = new Map<string, string[]>();
  for (const directive of value.split(';')) {
    const parts = directive.trim().split(/\s+/);
    const name = parts.shift()?.toLowerCase();
    if (name) map.set(name, parts);
  }
  return map;
}

export const cspModule: ScanModule = {
  name: MODULE,
  title: 'Content Security Policy',
  category: 'security',
  mode: 'passive',
  description: 'Parses and evaluates the CSP for unsafe directives and gaps.',
  async run(ctx: ScanContext): Promise<ModuleResult> {
    const t0 = performance.now();
    const page = await ctx.getPage();
    const findings: Finding[] = [];
    const raw = page.headers['content-security-policy'];

    if (!raw) {
      findings.push(
        finding({
          id: 'csp.missing',
          module: MODULE,
          category: 'security',
          title: 'No Content-Security-Policy header',
          severity: 'high',
          status: 'fail',
          risk: 'Cross-site scripting (XSS) payloads face no browser-side execution barrier.',
          whyItMatters:
            'CSP is the single most effective browser control against XSS. Without it, any injected script runs with full page privileges — reading cookies, tokens, and DOM.',
          technical:
            'A CSP restricts which sources of script, style, image, frame, and connect are allowed. A strong nonce/hash-based script-src neutralizes most reflected and stored XSS.',
          businessImpact:
            'Account takeover, data exfiltration, defacement, and Magecart-style payment-skimming attacks.',
          probability: 'high',
          owasp: ['A03:2021-Injection', 'A05:2021-Security Misconfiguration'],
          remediation:
            'Deploy a strict, nonce-based CSP. Start in Report-Only mode to catch violations, then enforce.',
          estimatedFixTime: '1-3 days',
          exampleCode:
            "Content-Security-Policy: default-src 'self'; script-src 'self' 'nonce-{RANDOM}'; object-src 'none'; base-uri 'self'; frame-ancestors 'self'",
          references: [
            'https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html',
            'https://csp.withgoogle.com/docs/strict-csp.html',
          ],
        }),
      );
      return { module: MODULE, category: 'security', ok: true, findings, durationMs: Math.round(performance.now() - t0) };
    }

    const csp = parseCsp(raw);
    const scriptSrc = csp.get('script-src') ?? csp.get('default-src') ?? [];

    const problems: Array<{ id: string; token: string; sev: Finding['severity']; note: string; fix: string }> = [];
    if (scriptSrc.includes("'unsafe-inline'"))
      problems.push({
        id: 'csp.unsafe-inline',
        token: "'unsafe-inline'",
        sev: 'high',
        note: "'unsafe-inline' in script-src allows inline <script> and event handlers to execute, which defeats most of CSP's XSS protection.",
        fix: "Remove 'unsafe-inline' and adopt nonces or hashes for the inline scripts you actually need.",
      });
    if (scriptSrc.includes("'unsafe-eval'"))
      problems.push({
        id: 'csp.unsafe-eval',
        token: "'unsafe-eval'",
        sev: 'medium',
        note: "'unsafe-eval' permits eval()/new Function(), a common XSS and gadget sink.",
        fix: "Remove 'unsafe-eval' and refactor code that relies on dynamic evaluation.",
      });
    if (scriptSrc.includes('*') || scriptSrc.some((s) => s === 'https:' || s === 'http:'))
      problems.push({
        id: 'csp.wildcard',
        token: '* / scheme-wide',
        sev: 'high',
        note: 'A wildcard or scheme-wide source in script-src lets an attacker load script from any host, nullifying the allow-list.',
        fix: 'Replace wildcards with specific hosts or (preferably) nonces/hashes.',
      });

    for (const p of problems) {
      findings.push(
        finding({
          id: p.id,
          module: MODULE,
          category: 'security',
          title: `Unsafe CSP directive: ${p.token}`,
          severity: p.sev,
          status: 'fail',
          risk: 'The CSP is present but weakened enough to permit script injection.',
          whyItMatters:
            'A permissive CSP gives a false sense of security — scanners see a policy, but attackers can still execute scripts.',
          technical: p.note,
          businessImpact: 'XSS-driven account takeover and data theft despite a nominal CSP being in place.',
          probability: 'high',
          owasp: ['A03:2021-Injection', 'A05:2021-Security Misconfiguration'],
          remediation: p.fix,
          estimatedFixTime: '0.5-2 days',
          exampleCode:
            "script-src 'self' 'nonce-{RANDOM}'; object-src 'none'; base-uri 'self'",
          references: ['https://csp.withgoogle.com/docs/strict-csp.html'],
          evidence: { policy: raw },
        }),
      );
    }

    // Missing hardening directives.
    for (const [dir, sev, why] of [
      ['object-src', 'medium', "object-src 'none' blocks legacy plugin-based script execution (Flash/Java)."],
      ['base-uri', 'medium', "base-uri 'self' prevents <base> tag hijacking that redirects relative script URLs."],
      ['frame-ancestors', 'low', 'frame-ancestors controls who may embed the page (clickjacking).'],
    ] as const) {
      if (!csp.has(dir)) {
        findings.push(
          finding({
            id: `csp.missing.${dir}`,
            module: MODULE,
            category: 'security',
            title: `CSP is missing the ${dir} directive`,
            severity: sev,
            status: 'warn',
            risk: `Without ${dir}, a specific bypass class remains open.`,
            whyItMatters: why,
            technical: `Add "${dir}" to the policy. ${why}`,
            businessImpact: 'Residual XSS/clickjacking surface despite having a CSP.',
            probability: 'medium',
            owasp: ['A05:2021-Security Misconfiguration'],
            remediation: `Add ${dir} to your Content-Security-Policy.`,
            estimatedFixTime: '15 minutes',
            exampleCode: dir === 'object-src' ? "object-src 'none'" : `${dir} 'self'`,
            references: ['https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html'],
            evidence: { policy: raw },
          }),
        );
      }
    }

    if (problems.length === 0) {
      findings.push(pass(MODULE, 'security', 'csp.ok', 'CSP present with no unsafe script sources', 'The Content-Security-Policy does not use unsafe-inline, unsafe-eval, or wildcards in script-src.', { policy: raw }));
    }

    return {
      module: MODULE,
      category: 'security',
      ok: true,
      findings,
      durationMs: Math.round(performance.now() - t0),
      data: { policy: raw, directives: Object.fromEntries(csp) },
    };
  },
};
