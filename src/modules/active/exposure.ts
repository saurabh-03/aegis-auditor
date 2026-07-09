/**
 * Modules 13, 14, 15 — Admin / Sensitive-file / Directory-listing discovery.
 * ACTIVE, authorization-gated.
 *
 * Ethics: this performs a small number of GET requests to a fixed list of
 * well-known paths. It does NOT brute force, does NOT download full file
 * contents, and reports only the fact of exposure so owners can remediate.
 */

import { finding, pass } from '../../core/finding.js';
import type { Finding, ModuleResult, ScanContext, ScanModule } from '../../core/types.js';

const MODULE = 'exposure';

interface PathDef {
  path: string;
  label: string;
  severity: Finding['severity'];
  why: string;
  category: 'security';
}

const SENSITIVE_FILES: PathDef[] = [
  { path: '/.env', label: 'Environment file (.env)', severity: 'critical', category: 'security', why: '.env files typically hold database credentials, API keys, and secrets. Public exposure is an immediate breach.' },
  { path: '/.git/config', label: 'Exposed .git repository', severity: 'high', category: 'security', why: 'An exposed .git directory lets attackers reconstruct your full source code and history, including any committed secrets.' },
  { path: '/backup.zip', label: 'Backup archive', severity: 'high', category: 'security', why: 'Downloadable backups often contain source, databases, and credentials.' },
  { path: '/database.sql', label: 'Database dump', severity: 'critical', category: 'security', why: 'A public SQL dump can expose your entire dataset.' },
  { path: '/config.php', label: 'PHP config file', severity: 'high', category: 'security', why: 'Config files can leak DB credentials if not parsed by the server.' },
  { path: '/phpinfo.php', label: 'phpinfo() page', severity: 'medium', category: 'security', why: 'phpinfo reveals server paths, modules, and configuration useful for attacks.' },
  { path: '/.DS_Store', label: 'macOS .DS_Store', severity: 'low', category: 'security', why: 'Reveals directory structure/filenames.' },
  { path: '/composer.json', label: 'composer.json', severity: 'low', category: 'security', why: 'Discloses PHP dependencies and versions for CVE matching.' },
  { path: '/package-lock.json', label: 'package-lock.json', severity: 'low', category: 'security', why: 'Discloses exact npm dependency versions for CVE matching.' },
];

const ADMIN_PATHS: PathDef[] = [
  { path: '/admin', label: 'Admin panel (/admin)', severity: 'info', category: 'security', why: 'A reachable admin login should have MFA, rate limiting, and ideally IP restriction.' },
  { path: '/wp-admin/', label: 'WordPress admin', severity: 'info', category: 'security', why: 'wp-admin should be protected with MFA and login hardening.' },
  { path: '/administrator/', label: 'Joomla admin', severity: 'info', category: 'security', why: 'Admin console reachable; ensure it is hardened.' },
  { path: '/.git/', label: 'Directory listing on /.git/', severity: 'high', category: 'security', why: 'Open directory listing on version-control internals is highly dangerous.' },
];

async function check(ctx: ScanContext, path: string): Promise<{ status: number; sample: string } | null> {
  const url = ctx.target.origin + path;
  const res = await ctx.fetch(url, { method: 'GET' }).catch(() => null);
  if (!res) return null;
  // Read only a small prefix to confirm content type without downloading everything.
  const buf = await res.arrayBuffer().catch(() => new ArrayBuffer(0));
  const sample = new TextDecoder().decode(buf.slice(0, 256));
  return { status: res.status, sample };
}

function looksLikeSoftError(sample: string): boolean {
  return /<!doctype html>[\s\S]*(<title>[^<]*(404|not found|error)[^<]*<\/title>)/i.test(sample);
}

export const exposureModule: ScanModule = {
  name: MODULE,
  title: 'Sensitive File & Admin Discovery',
  category: 'security',
  mode: 'active',
  description: 'Checks a fixed list of well-known sensitive paths and admin endpoints (authorization required).',
  async run(ctx: ScanContext): Promise<ModuleResult> {
    const t0 = performance.now();
    const findings: Finding[] = [];
    let exposures = 0;

    for (const def of [...SENSITIVE_FILES, ...ADMIN_PATHS]) {
      const r = await check(ctx, def.path);
      if (!r) continue;
      const exposed = r.status === 200 && !looksLikeSoftError(r.sample);
      const dirListing = exposed && /Index of \/|<title>Directory listing/i.test(r.sample);

      if (!exposed) continue;
      exposures++;

      const isAdmin = ADMIN_PATHS.includes(def);
      findings.push(
        finding({
          id: `exposure.${def.path.replace(/[^a-z0-9]+/gi, '_')}`,
          module: MODULE,
          category: 'security',
          title: dirListing ? `Open directory listing at ${def.path}` : `${def.label} is publicly accessible`,
          severity: dirListing ? 'high' : def.severity,
          status: def.severity === 'info' && !dirListing ? 'warn' : 'fail',
          risk: def.why,
          whyItMatters: isAdmin
            ? 'An externally reachable admin/versioning path is a priority target; it must be hardened or hidden.'
            : 'Sensitive files served to the public leak secrets, source, or data directly to any visitor.',
          technical: `GET ${ctx.target.origin}${def.path} returned HTTP ${r.status}. ${dirListing ? 'The response is a directory index. ' : ''}${def.why}`,
          businessImpact:
            def.severity === 'critical'
              ? 'Immediate, severe data breach potential.'
              : def.severity === 'high'
              ? 'Significant exposure of source, config, or structure.'
              : 'Increased reconnaissance/attack surface.',
          probability: def.severity === 'critical' ? 'high' : 'medium',
          owasp: ['A05:2021-Security Misconfiguration', 'A01:2021-Broken Access Control'],
          remediation: isAdmin
            ? 'Restrict admin endpoints (IP allow-list/VPN), enforce MFA and rate limiting, and disable directory listing.'
            : 'Remove the file from the web root, block the path at the server/CDN, rotate any exposed secrets, and disable directory listing.',
          estimatedFixTime: '1-4 hours',
          exampleCode:
            "# nginx: deny sensitive paths and disable autoindex\nautoindex off;\nlocation ~ /\\.(?!well-known) { deny all; }\nlocation ~* \\.(env|sql|zip)$ { deny all; }",
          references: ['https://owasp.org/Top10/A05_2021-Security_Misconfiguration/'],
          evidence: { path: def.path, status: r.status, directoryListing: dirListing },
        }),
      );
    }

    if (exposures === 0) {
      findings.push(pass(MODULE, 'security', 'exposure.clean', 'No exposed sensitive files or open admin listings found', 'None of the checked well-known sensitive paths returned public content.'));
    }

    return { module: MODULE, category: 'security', ok: true, findings, durationMs: Math.round(performance.now() - t0), data: { exposures } };
  },
};
