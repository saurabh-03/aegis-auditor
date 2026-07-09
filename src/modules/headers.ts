/** Module 2 — Security Headers analysis. */

import { finding, pass } from '../core/finding.js';
import type { Finding, ModuleResult, ScanContext, ScanModule } from '../core/types.js';

const MODULE = 'security-headers';

interface HeaderCheck {
  header: string;
  present: (value: string | undefined, headers: Record<string, string>) => boolean;
  missing: Omit<Finding, 'module' | 'category'>;
  weakCheck?: (value: string) => Omit<Finding, 'module' | 'category'> | null;
}

const CHECKS: HeaderCheck[] = [
  {
    header: 'strict-transport-security',
    present: (v) => !!v,
    missing: {
      id: 'headers.hsts.missing',
      title: 'HTTP Strict Transport Security (HSTS) not enabled',
      severity: 'high',
      status: 'fail',
      risk: 'Users can be downgraded to plaintext HTTP and have traffic intercepted.',
      whyItMatters:
        'Without HSTS a visitor’s first request (or a manipulated link) can be served over HTTP, letting a network attacker read or alter the page before HTTPS is enforced.',
      technical:
        'The Strict-Transport-Security header instructs browsers to only ever connect to this host over TLS for a given max-age. Missing it leaves the site vulnerable to SSL-stripping / downgrade attacks on public networks.',
      businessImpact:
        'Session hijacking and credential theft on hostile networks (cafés, airports), plus failure of most security compliance baselines (PCI-DSS, SOC 2).',
      probability: 'medium',
      owasp: ['A05:2021-Security Misconfiguration', 'A02:2021-Cryptographic Failures'],
      remediation:
        'Send Strict-Transport-Security with a max-age of at least 6 months, includeSubDomains, and preload once you are confident all subdomains support HTTPS.',
      estimatedFixTime: '15 minutes',
      exampleCode:
        'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload',
      references: [
        'https://developer.mozilla.org/docs/Web/HTTP/Headers/Strict-Transport-Security',
        'https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html',
      ],
    },
    weakCheck: (v) => {
      const m = /max-age=(\d+)/i.exec(v);
      const maxAge = m ? Number.parseInt(m[1] ?? '0', 10) : 0;
      if (maxAge >= 15552000) return null;
      return {
        id: 'headers.hsts.weak',
        title: 'HSTS max-age is too short',
        severity: 'low',
        status: 'warn',
        risk: 'A short HSTS lifetime narrows the protection window against downgrade attacks.',
        whyItMatters:
          'If the cached HSTS policy expires quickly, users who have not visited recently are again exposed to a first-request downgrade.',
        technical: `Observed max-age=${maxAge}s. Recommended minimum is 15552000s (180 days); 31536000s (1 year) is standard.`,
        businessImpact: 'Marginally increased exposure window; may fail stricter audits.',
        probability: 'low',
        owasp: ['A05:2021-Security Misconfiguration'],
        remediation: 'Increase max-age to at least 31536000 (1 year).',
        estimatedFixTime: '5 minutes',
        exampleCode: 'Strict-Transport-Security: max-age=31536000; includeSubDomains',
        references: [
          'https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html',
        ],
      };
    },
  },
  {
    header: 'x-frame-options',
    present: (v, h) => !!v || /frame-ancestors/i.test(h['content-security-policy'] ?? ''),
    missing: {
      id: 'headers.xfo.missing',
      title: 'Clickjacking protection missing (X-Frame-Options / frame-ancestors)',
      severity: 'medium',
      status: 'fail',
      risk: 'The site can be embedded in a hostile iframe and used for clickjacking.',
      whyItMatters:
        'An attacker can overlay your site invisibly on their own page and trick users into clicking buttons (e.g. “delete account”, “transfer funds”) they cannot see.',
      technical:
        'Neither X-Frame-Options nor a CSP frame-ancestors directive was present. Modern guidance prefers CSP frame-ancestors, which supersedes X-Frame-Options where supported.',
      businessImpact:
        'Account takeover, fraudulent actions performed by tricked users, and reputational damage.',
      probability: 'medium',
      owasp: ['A05:2021-Security Misconfiguration'],
      remediation:
        'Set Content-Security-Policy: frame-ancestors \'self\'; (or a strict allow-list). Optionally also send X-Frame-Options: DENY for legacy browsers.',
      estimatedFixTime: '10 minutes',
      exampleCode:
        "Content-Security-Policy: frame-ancestors 'self';\nX-Frame-Options: DENY",
      references: [
        'https://cheatsheetseries.owasp.org/cheatsheets/Clickjacking_Defense_Cheat_Sheet.html',
      ],
    },
  },
  {
    header: 'x-content-type-options',
    present: (v) => (v ?? '').toLowerCase().includes('nosniff'),
    missing: {
      id: 'headers.xcto.missing',
      title: 'X-Content-Type-Options: nosniff missing',
      severity: 'low',
      status: 'fail',
      risk: 'Browsers may MIME-sniff responses, enabling some XSS and drive-by attacks.',
      whyItMatters:
        'Without nosniff, a browser might interpret an uploaded or user-controlled file as a script or stylesheet, turning a harmless upload into executable content.',
      technical:
        'X-Content-Type-Options: nosniff disables content-type sniffing so responses are treated strictly as their declared Content-Type.',
      businessImpact: 'Increased XSS surface; commonly flagged by security scanners and audits.',
      probability: 'low',
      owasp: ['A05:2021-Security Misconfiguration'],
      remediation: 'Add the header to every response.',
      estimatedFixTime: '5 minutes',
      exampleCode: 'X-Content-Type-Options: nosniff',
      references: [
        'https://developer.mozilla.org/docs/Web/HTTP/Headers/X-Content-Type-Options',
      ],
    },
  },
  {
    header: 'referrer-policy',
    present: (v) => !!v,
    missing: {
      id: 'headers.referrer.missing',
      title: 'Referrer-Policy not set',
      severity: 'low',
      status: 'warn',
      risk: 'Full URLs (possibly containing tokens) may leak to third parties via the Referer header.',
      whyItMatters:
        'Query strings sometimes carry session tokens, reset links, or PII. A permissive referrer policy can send these to external sites the user navigates to.',
      technical:
        'Set a conservative policy such as strict-origin-when-cross-origin (the modern browser default, but worth making explicit) or no-referrer for sensitive apps.',
      businessImpact: 'Data leakage, privacy-regulation exposure (GDPR/CCPA).',
      probability: 'low',
      owasp: ['A05:2021-Security Misconfiguration'],
      remediation: 'Add Referrer-Policy: strict-origin-when-cross-origin.',
      estimatedFixTime: '5 minutes',
      exampleCode: 'Referrer-Policy: strict-origin-when-cross-origin',
      references: ['https://developer.mozilla.org/docs/Web/HTTP/Headers/Referrer-Policy'],
    },
  },
  {
    header: 'permissions-policy',
    present: (v) => !!v,
    missing: {
      id: 'headers.permissions.missing',
      title: 'Permissions-Policy not set',
      severity: 'low',
      status: 'warn',
      risk: 'Powerful browser features (camera, microphone, geolocation) are not explicitly restricted.',
      whyItMatters:
        'If the site is ever XSS-ed or embeds compromised third-party scripts, an explicit Permissions-Policy limits what those scripts can access.',
      technical:
        'Permissions-Policy (formerly Feature-Policy) lets you allow-list which origins may use sensitive APIs. Default-deny for features you do not use.',
      businessImpact: 'Defense-in-depth gap; privacy exposure if third-party scripts misbehave.',
      probability: 'low',
      owasp: ['A05:2021-Security Misconfiguration'],
      remediation: 'Disable unused features explicitly.',
      estimatedFixTime: '15 minutes',
      exampleCode: 'Permissions-Policy: geolocation=(), camera=(), microphone=()',
      references: ['https://developer.mozilla.org/docs/Web/HTTP/Headers/Permissions-Policy'],
    },
  },
  {
    header: 'cross-origin-opener-policy',
    present: (v) => !!v,
    missing: {
      id: 'headers.coop.missing',
      title: 'Cross-Origin-Opener-Policy not set',
      severity: 'low',
      status: 'warn',
      risk: 'Cross-origin windows can share a browsing context group, enabling some side-channel attacks.',
      whyItMatters:
        'COOP isolates your top-level window from cross-origin openers, mitigating XS-Leaks and Spectre-style cross-origin information leaks.',
      technical:
        'Set Cross-Origin-Opener-Policy: same-origin. Combined with COEP this enables cross-origin isolation and access to high-resolution timers safely.',
      businessImpact: 'Defense-in-depth against advanced cross-origin leaks.',
      probability: 'low',
      owasp: ['A05:2021-Security Misconfiguration'],
      remediation: 'Add COOP (and COEP if you need cross-origin isolation).',
      estimatedFixTime: '20 minutes',
      exampleCode: 'Cross-Origin-Opener-Policy: same-origin',
      references: ['https://developer.mozilla.org/docs/Web/HTTP/Headers/Cross-Origin-Opener-Policy'],
    },
  },
];

/** Server tech-leak headers that should be removed. */
const LEAKY_HEADERS = ['server', 'x-powered-by', 'x-aspnet-version', 'x-aspnetmvc-version'];

export const securityHeadersModule: ScanModule = {
  name: MODULE,
  title: 'Security Headers',
  category: 'security',
  mode: 'passive',
  description: 'Analyzes HTTP response security headers and grades the configuration.',
  async run(ctx: ScanContext): Promise<ModuleResult> {
    const t0 = performance.now();
    const page = await ctx.getPage();
    const findings: Finding[] = [];

    for (const check of CHECKS) {
      const value = page.headers[check.header];
      if (!check.present(value, page.headers)) {
        findings.push({ ...check.missing, module: MODULE, category: 'security' });
        continue;
      }
      if (value && check.weakCheck) {
        const weak = check.weakCheck(value);
        if (weak) findings.push({ ...weak, module: MODULE, category: 'security' });
        else
          findings.push(
            pass(MODULE, 'security', `${check.missing.id}.ok`, check.header, `Present and adequately configured: ${value}`, { value }),
          );
      } else {
        findings.push(
          pass(MODULE, 'security', `${check.missing.id}.ok`, check.header, `Present: ${value}`, { value }),
        );
      }
    }

    // Information-disclosure headers.
    for (const h of LEAKY_HEADERS) {
      const v = page.headers[h];
      if (v) {
        findings.push(
          finding({
            id: `headers.leak.${h}`,
            module: MODULE,
            category: 'security',
            title: `Server discloses technology via "${h}" header`,
            severity: 'low',
            status: 'warn',
            risk: 'Version disclosure helps attackers target known CVEs for your stack.',
            whyItMatters:
              'Advertising exact server/framework versions lets attackers skip reconnaissance and go straight to matching public exploits.',
            technical: `The "${h}" response header exposes "${v}". Remove or genericize it at the reverse proxy / app layer.`,
            businessImpact: 'Reduced attacker effort; commonly flagged in penetration tests.',
            probability: 'low',
            owasp: ['A05:2021-Security Misconfiguration'],
            remediation: `Strip or override the ${h} header at your web server / CDN.`,
            estimatedFixTime: '10 minutes',
            exampleCode:
              h === 'server'
                ? '# nginx\nserver_tokens off;\nmore_clear_headers Server;'
                : `# nginx\nmore_clear_headers ${h};\n# express\napp.disable('x-powered-by');`,
            references: ['https://owasp.org/www-project-secure-headers/'],
            evidence: { header: h, value: v },
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
      data: { headers: page.headers },
    };
  },
};
