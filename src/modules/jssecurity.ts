/** Module 10 — JavaScript / secret exposure analysis (passive, homepage HTML + inline scripts). */

import { finding, pass } from '../core/finding.js';
import type { Finding, ModuleResult, ScanContext, ScanModule } from '../core/types.js';

const MODULE = 'js-security';

interface SecretPattern {
  id: string;
  label: string;
  regex: RegExp;
  severity: Finding['severity'];
  note: string;
}

/**
 * Patterns are intentionally conservative to limit false positives. A match is
 * reported as "potential" exposure requiring human confirmation — never as a
 * confirmed breach. We do NOT print the full secret back in findings.
 */
const PATTERNS: SecretPattern[] = [
  { id: 'aws-akid', label: 'AWS Access Key ID', regex: /\bAKIA[0-9A-Z]{16}\b/, severity: 'critical', note: 'An AWS access key ID pattern was found in client-delivered code.' },
  { id: 'google-api', label: 'Google API key', regex: /\bAIza[0-9A-Za-z\-_]{35}\b/, severity: 'high', note: 'A Google API key pattern was found. Restrict it by referrer/IP and API.' },
  { id: 'firebase-db', label: 'Firebase database URL', regex: /https:\/\/[a-z0-9-]+\.firebaseio\.com/i, severity: 'medium', note: 'A Firebase Realtime Database URL is embedded. Ensure security rules are not open.' },
  { id: 'stripe-live', label: 'Stripe live secret key', regex: /\bsk_live_[0-9A-Za-z]{16,}\b/, severity: 'critical', note: 'A Stripe LIVE secret key pattern was found in client code — rotate immediately.' },
  { id: 'slack-token', label: 'Slack token', regex: /\bxox[baprs]-[0-9A-Za-z-]{10,}\b/, severity: 'high', note: 'A Slack token pattern was found.' },
  { id: 'private-key', label: 'Private key block', regex: /-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----/, severity: 'critical', note: 'A private key block is embedded in the page.' },
  { id: 'jwt', label: 'JSON Web Token', regex: /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/, severity: 'medium', note: 'A JWT is present in client code; verify it is not a long-lived privileged token.' },
];

export const jsSecurityModule: ScanModule = {
  name: MODULE,
  title: 'JavaScript Security',
  category: 'security',
  mode: 'passive',
  description: 'Scans homepage HTML/inline scripts for exposed keys, secrets, and debug leftovers.',
  async run(ctx: ScanContext): Promise<ModuleResult> {
    const t0 = performance.now();
    const page = await ctx.getPage();
    const body = page.body;
    const findings: Finding[] = [];
    let anyHit = false;

    for (const p of PATTERNS) {
      const m = p.regex.exec(body);
      if (!m) continue;
      anyHit = true;
      const snippet = redact(m[0]);
      findings.push(
        finding({
          id: `js.secret.${p.id}`,
          module: MODULE,
          category: 'security',
          title: `Potential ${p.label} exposed in client code`,
          severity: p.severity,
          status: 'fail',
          risk: 'Secrets shipped to the browser are readable by anyone and can be abused directly.',
          whyItMatters:
            'Anything in HTML or client-side JavaScript is fully visible to every visitor. A leaked key can be used to run up cloud bills, access data, or impersonate your service.',
          technical: `${p.note} Detected token (redacted): ${snippet}. Confirm whether this is a real credential; if so, revoke and rotate it, and move server-only secrets out of client bundles.`,
          businessImpact: 'Direct financial loss, data breach, and service abuse depending on the key’s scope.',
          probability: p.severity === 'critical' ? 'high' : 'medium',
          owasp: ['A02:2021-Cryptographic Failures', 'A05:2021-Security Misconfiguration'],
          remediation: 'Revoke/rotate the credential, remove it from client code, and inject secrets only server-side. Add secret scanning to CI.',
          estimatedFixTime: '2-8 hours',
          exampleCode: '# Add pre-commit / CI secret scanning\n# e.g. gitleaks, trufflehog, or GitHub secret scanning',
          references: ['https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html'],
          evidence: { pattern: p.id, redacted: snippet },
        }),
      );
    }

    // Source map exposure
    if (/\/\/[#@]\s*sourceMappingURL=.+\.map/.test(body) || /\.js\.map/.test(body)) {
      anyHit = true;
      findings.push(
        finding({
          id: 'js.sourcemap',
          module: MODULE,
          category: 'security',
          title: 'Source maps referenced in production',
          severity: 'low',
          status: 'warn',
          risk: 'Source maps expose your original, unminified source and internal structure.',
          whyItMatters: 'Shipping .map files makes reverse-engineering trivial and can reveal comments, internal endpoints, and logic.',
          technical: 'A sourceMappingURL or .js.map reference was found. Disable source map emission (or restrict access) for production builds.',
          businessImpact: 'Easier reconnaissance and IP exposure.',
          probability: 'low',
          owasp: ['A05:2021-Security Misconfiguration'],
          remediation: 'Do not deploy source maps publicly; upload them privately to your error tracker instead.',
          estimatedFixTime: '30 minutes',
          references: ['https://web.dev/articles/source-maps'],
        }),
      );
    }

    // Debug leftovers
    const consoleCount = (body.match(/console\.(log|debug|warn|error)\s*\(/g) ?? []).length;
    if (consoleCount > 5) {
      anyHit = true;
      findings.push(
        finding({
          id: 'js.console-noise',
          module: MODULE,
          category: 'maintainability',
          title: `Numerous console statements in delivered HTML (${consoleCount})`,
          severity: 'info',
          status: 'warn',
          risk: 'Leftover debug logging can leak data and indicates a non-production build.',
          whyItMatters: 'Console statements may print sensitive values and suggest the bundle was not properly stripped for production.',
          technical: `${consoleCount} inline console.* calls detected. Strip these in the production build pipeline.`,
          businessImpact: 'Minor information leakage and code-hygiene signal.',
          probability: 'low',
          remediation: 'Remove debug logging via your bundler (e.g. drop_console) for production.',
          estimatedFixTime: '30 minutes',
          references: ['https://terser.org/docs/options/#compress-options'],
          evidence: { consoleCount },
        }),
      );
    }

    if (!anyHit) {
      findings.push(pass(MODULE, 'security', 'js.clean', 'No exposed secrets detected in homepage', 'No high-confidence secret patterns, source maps, or excessive debug logging were found in the homepage HTML. (Note: this passive check does not fetch or scan external bundles.)'));
    }

    return { module: MODULE, category: 'security', ok: true, findings, durationMs: Math.round(performance.now() - t0) };
  },
};

function redact(token: string): string {
  if (token.length <= 8) return '****';
  return `${token.slice(0, 4)}…${token.slice(-3)}`;
}
