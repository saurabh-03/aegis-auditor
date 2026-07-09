/** Module 3 — Cookie Security analysis. */

import { finding, pass } from '../core/finding.js';
import type { Finding, ModuleResult, ScanContext, ScanModule } from '../core/types.js';

const MODULE = 'cookies';

interface ParsedCookie {
  name: string;
  attributes: Set<string>;
  sameSite?: string;
  raw: string;
}

function parseCookie(line: string): ParsedCookie {
  const parts = line.split(';').map((p) => p.trim());
  const first = parts.shift() ?? '';
  const name = first.split('=')[0] ?? first;
  const attributes = new Set<string>();
  let sameSite: string | undefined;
  for (const p of parts) {
    const [k, v] = p.split('=');
    const key = (k ?? '').toLowerCase();
    attributes.add(key);
    if (key === 'samesite') sameSite = (v ?? '').toLowerCase();
  }
  return { name, attributes, sameSite, raw: line };
}

/** Cookies that look session/auth-related get stricter treatment. */
function looksSensitive(name: string): boolean {
  return /sess|sid|token|auth|jwt|csrf|remember|login/i.test(name);
}

export const cookiesModule: ScanModule = {
  name: MODULE,
  title: 'Cookie Security',
  category: 'security',
  mode: 'passive',
  description: 'Evaluates Set-Cookie flags (HttpOnly, Secure, SameSite) and session hygiene.',
  async run(ctx: ScanContext): Promise<ModuleResult> {
    const t0 = performance.now();
    const page = await ctx.getPage();
    const findings: Finding[] = [];
    const cookies = page.setCookie.map(parseCookie);

    if (cookies.length === 0) {
      findings.push(pass(MODULE, 'security', 'cookies.none', 'No cookies set on initial response', 'The homepage did not set cookies, so no cookie-flag weaknesses apply here.'));
      return { module: MODULE, category: 'security', ok: true, findings, durationMs: Math.round(performance.now() - t0) };
    }

    for (const c of cookies) {
      const sensitive = looksSensitive(c.name);
      const issues: string[] = [];
      if (!c.attributes.has('httponly')) issues.push('HttpOnly');
      if (!c.attributes.has('secure')) issues.push('Secure');
      if (!c.sameSite) issues.push('SameSite');

      if (issues.length === 0) {
        findings.push(pass(MODULE, 'security', `cookies.ok.${c.name}`, `Cookie "${c.name}" is hardened`, `HttpOnly, Secure, and SameSite are all set.`, { cookie: c.raw }));
        continue;
      }

      const missingHttpOnly = issues.includes('HttpOnly');
      const missingSecure = issues.includes('Secure');
      const severity: Finding['severity'] = sensitive && (missingHttpOnly || missingSecure) ? 'high' : missingSecure ? 'medium' : 'low';

      findings.push(
        finding({
          id: `cookies.weak.${c.name}`,
          module: MODULE,
          category: 'security',
          title: `Cookie "${c.name}" missing ${issues.join(', ')}`,
          severity,
          status: 'fail',
          risk: sensitive
            ? 'A session/auth cookie without hardening can be stolen via XSS or sent over plaintext.'
            : 'Missing cookie flags increase the blast radius of XSS and network attacks.',
          whyItMatters:
            (missingHttpOnly ? 'Without HttpOnly, JavaScript (including injected XSS) can read the cookie and exfiltrate the session. ' : '') +
            (missingSecure ? 'Without Secure, the cookie can be transmitted over unencrypted HTTP and captured on the network. ' : '') +
            (!c.sameSite ? 'Without SameSite, the cookie is attached to cross-site requests, enabling CSRF.' : ''),
          technical:
            `Set-Cookie observed: ${c.raw}. ` +
            'Recommended baseline for session cookies: HttpOnly; Secure; SameSite=Lax (or Strict for high-value flows); scoped Path; short Max-Age.',
          businessImpact: sensitive
            ? 'Session hijacking → account takeover, fraud, data breach, and compliance failure.'
            : 'Elevated attack surface and audit findings.',
          probability: sensitive ? 'high' : 'medium',
          owasp: ['A05:2021-Security Misconfiguration', 'A07:2021-Identification and Authentication Failures'],
          remediation: `Re-issue the cookie with the missing flags: ${issues.join(', ')}.`,
          estimatedFixTime: '15 minutes',
          exampleCode: `Set-Cookie: ${c.name}=<value>; HttpOnly; Secure; SameSite=Lax; Path=/`,
          references: [
            'https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html',
            'https://developer.mozilla.org/docs/Web/HTTP/Headers/Set-Cookie',
          ],
          evidence: { cookie: c.raw, sensitive },
        }),
      );

      // SameSite=None without Secure is invalid and risky.
      if (c.sameSite === 'none' && missingSecure) {
        findings.push(
          finding({
            id: `cookies.samesite-none.${c.name}`,
            module: MODULE,
            category: 'security',
            title: `Cookie "${c.name}" uses SameSite=None without Secure`,
            severity: 'medium',
            status: 'fail',
            risk: 'SameSite=None cookies are rejected by modern browsers unless Secure is set, and are sent cross-site.',
            whyItMatters: 'The cookie will be dropped by current browsers and, where accepted, is exposed to CSRF and network interception.',
            technical: 'Per the cookie spec, SameSite=None requires the Secure attribute.',
            businessImpact: 'Broken sessions for users on updated browsers plus CSRF exposure.',
            probability: 'medium',
            owasp: ['A05:2021-Security Misconfiguration'],
            remediation: 'Add Secure, or change SameSite to Lax/Strict if cross-site delivery is not required.',
            estimatedFixTime: '10 minutes',
            exampleCode: `Set-Cookie: ${c.name}=<value>; SameSite=None; Secure; HttpOnly`,
            references: ['https://developer.mozilla.org/docs/Web/HTTP/Headers/Set-Cookie/SameSite'],
          }),
        );
      }
    }

    return {
      module: MODULE,
      category: 'security',
      ok: true,
      findings,
      durationMs: Math.round(performance.now() - t0),
      data: { cookies: cookies.map((c) => ({ name: c.name, attributes: [...c.attributes], sameSite: c.sameSite })) },
    };
  },
};
