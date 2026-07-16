/**
 * Aegis Auditor CLI.
 *
 * Usage:
 *   npm run scan -- example.com
 *   npm run scan -- example.com --format md
 *   npm run scan -- example.com --active --authorized   (intrusive; owner only)
 *   npm run scan -- example.com --only ssl,security-headers
 *   npm run scan -- example.com --active --authorized \
 *     --auth-header "Authorization: Bearer <token>" --auth-cookie "session=<id>"
 */

import { normalizeTarget } from './core/http.js';
import { runScan } from './core/scanner.js';
import type { ScanAuth, ScanOptions } from './core/types.js';
import { ALL_MODULES } from './modules/registry.js';
import { toMarkdown } from './report/markdown.js';
import { summarize } from './core/scoring.js';

interface Args {
  target: string;
  format: 'summary' | 'json' | 'md';
  active: boolean;
  authorized: boolean;
  only?: string[];
  skip?: string[];
  authHeaders: Record<string, string>;
  authCookie?: string;
  exclude?: string[];
}

function parseArgs(argv: string[]): Args {
  const args: Args = { target: '', format: 'summary', active: false, authorized: false, authHeaders: {} };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (!a) continue;
    if (a === '--format') args.format = (argv[++i] as Args['format']) ?? 'summary';
    else if (a === '--active') args.active = true;
    else if (a === '--authorized') args.authorized = true;
    else if (a === '--only') args.only = (argv[++i] ?? '').split(',').filter(Boolean);
    else if (a === '--skip') args.skip = (argv[++i] ?? '').split(',').filter(Boolean);
    else if (a === '--auth-header') {
      // "Name: value" — split on the first colon only.
      const raw = argv[++i] ?? '';
      const idx = raw.indexOf(':');
      if (idx > 0) args.authHeaders[raw.slice(0, idx).trim()] = raw.slice(idx + 1).trim();
    } else if (a === '--auth-cookie') args.authCookie = argv[++i];
    else if (a === '--exclude') args.exclude = (argv[++i] ?? '').split(',').filter(Boolean);
    else if (!a.startsWith('--')) args.target = a;
  }
  return args;
}

/** Assemble ScanAuth from CLI flags, or undefined when none were supplied. */
function buildAuth(args: Args): ScanAuth | undefined {
  const hasHeaders = Object.keys(args.authHeaders).length > 0;
  if (!hasHeaders && !args.authCookie && !args.exclude) return undefined;
  return {
    ...(hasHeaders ? { headers: args.authHeaders } : {}),
    ...(args.authCookie ? { cookies: args.authCookie } : {}),
    ...(args.exclude ? { excludeUrlPatterns: args.exclude } : {}),
  };
}

const COLOR = {
  reset: '\x1b[0m',
  bold: '\x1b[1m',
  red: '\x1b[31m',
  green: '\x1b[32m',
  yellow: '\x1b[33m',
  cyan: '\x1b[36m',
  gray: '\x1b[90m',
};

function bar(score: number): string {
  const filled = Math.round(score / 5);
  const color = score >= 90 ? COLOR.green : score >= 70 ? COLOR.yellow : COLOR.red;
  return `${color}${'█'.repeat(filled)}${COLOR.gray}${'░'.repeat(20 - filled)}${COLOR.reset}`;
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  if (!args.target) {
    console.error(
      'Usage: npm run scan -- <target> [--format summary|json|md] [--active --authorized] [--only a,b] [--skip c]\n' +
        '                 [--auth-header "Name: value"] [--auth-cookie "k=v; …"] [--exclude /logout,/admin]',
    );
    process.exit(1);
  }

  if (args.active && !args.authorized) {
    console.error(`${COLOR.red}Refusing to run active modules without --authorized.${COLOR.reset}`);
    console.error('Active checks (port scan, sensitive-file discovery) are only permitted against targets you own or are authorized to test.');
    process.exit(2);
  }

  const target = normalizeTarget(args.target);
  const auth = buildAuth(args);
  const options: ScanOptions = {
    authorized: args.authorized,
    includeActive: args.active,
    ...(args.only ? { only: args.only } : {}),
    ...(args.skip ? { skip: args.skip } : {}),
    ...(auth ? { auth } : {}),
  };
  if (auth) console.error(`${COLOR.cyan}Authenticated scan: credentials will be sent with requests (never stored in the report).${COLOR.reset}`);

  console.error(`${COLOR.cyan}Scanning ${target.toString()} …${COLOR.reset}`);
  const report = await runScan(target, ALL_MODULES, options, {
    onModuleFinish: (r) =>
      console.error(`  ${r.ok ? COLOR.green + '✓' : COLOR.red + '✗'} ${r.module}${COLOR.reset} ${COLOR.gray}(${r.durationMs}ms)${COLOR.reset}`),
  });

  if (args.format === 'json') {
    process.stdout.write(JSON.stringify(report, null, 2));
    return;
  }
  if (args.format === 'md') {
    process.stdout.write(toMarkdown(report));
    return;
  }

  // summary
  const s = summarize(report);
  console.log('');
  console.log(`${COLOR.bold}Overall Score: ${report.overall.score}/100 (${report.overall.grade})${COLOR.reset}`);
  console.log('');
  for (const c of report.categories) {
    const ran = Object.values(c.findingCounts).reduce((a, b) => a + b, 0);
    if (ran === 0) continue;
    console.log(`  ${c.category.padEnd(16)} ${bar(c.score)} ${String(c.score).padStart(3)} ${COLOR.gray}${c.grade}${COLOR.reset}`);
  }
  console.log('');
  console.log(`  ${COLOR.red}${s.critical} critical${COLOR.reset}  ${COLOR.yellow}${s.high} high${COLOR.reset}  ${s.medium} medium  ${s.low} low  ${COLOR.green}${s.passed} passing${COLOR.reset}`);
  console.log('');
  const fails = report.findings.filter((f) => f.status === 'fail').slice(0, 12);
  for (const f of fails) {
    console.log(`  ${COLOR.bold}${f.severity.toUpperCase()}${COLOR.reset} ${f.title}`);
    console.log(`    ${COLOR.gray}${f.risk}${COLOR.reset}`);
    console.log(`    ${COLOR.cyan}Fix (${f.estimatedFixTime}):${COLOR.reset} ${f.remediation}`);
    console.log('');
  }
  console.log(`${COLOR.gray}Run with --format md > report.md for the full explained report.${COLOR.reset}`);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
