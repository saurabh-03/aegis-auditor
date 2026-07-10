/**
 * Aegis SCA CLI — software-composition analysis for a dependency manifest.
 *
 * Usage:
 *   npm run sca -- path/to/package-lock.json
 *   npm run sca -- yarn.lock --fail-on critical
 *   npm run sca -- composer.lock --source osv --json
 *
 * Exit codes make it a CI gate:
 *   0  no vulnerabilities at or above the --fail-on threshold (default: high)
 *   1  vulnerabilities at/above threshold found
 *   2  usage / parse error
 */

import { readFileSync } from 'node:fs';
import { parseManifest } from './intel/manifest.js';
import { matchPackages } from './intel/cve-match.js';
import type { Severity } from './core/types.js';

const SEV_RANK: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
const C = { reset: '\x1b[0m', bold: '\x1b[1m', red: '\x1b[31m', yellow: '\x1b[33m', green: '\x1b[32m', cyan: '\x1b[36m', gray: '\x1b[90m' };
const sevColor = (s: string) => (s === 'critical' ? C.red : s === 'high' ? C.red : s === 'medium' ? C.yellow : C.gray);

interface Args {
  file: string;
  failOn: string;
  source: 'local' | 'osv' | 'both';
  json: boolean;
}

function parseArgs(argv: string[]): Args {
  const a: Args = { file: '', failOn: 'high', source: 'both', json: false };
  for (let i = 0; i < argv.length; i++) {
    const t = argv[i];
    if (t === '--fail-on') a.failOn = (argv[++i] ?? 'high').toLowerCase();
    else if (t === '--source') a.source = (argv[++i] as Args['source']) ?? 'both';
    else if (t === '--json') a.json = true;
    else if (t && !t.startsWith('--')) a.file = t;
  }
  return a;
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  if (!args.file) {
    console.error('Usage: npm run sca -- <manifest> [--fail-on critical|high|medium|low] [--source local|osv|both] [--json]');
    process.exit(2);
  }

  let content: string;
  try {
    content = readFileSync(args.file, 'utf8');
  } catch (err) {
    console.error(`Cannot read ${args.file}: ${(err as Error).message}`);
    process.exit(2);
  }

  let manifest;
  try {
    manifest = parseManifest(content, args.file);
  } catch (err) {
    console.error((err as Error).message);
    process.exit(2);
  }

  const { matches, sourceUsed, scanned } = await matchPackages(manifest.packages, { source: args.source });

  const summary = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const m of matches) summary[m.entry.severity as keyof typeof summary]++;

  const threshold = SEV_RANK[args.failOn] ?? SEV_RANK.high!;
  const gating = matches.filter((m) => (SEV_RANK[m.entry.severity] ?? 0) >= threshold).length;

  if (args.json) {
    console.log(
      JSON.stringify(
        {
          manifest: manifest.format,
          ecosystem: manifest.ecosystem,
          scanned,
          sourceUsed,
          summary,
          failOn: args.failOn,
          failing: gating,
          vulnerabilities: matches.map((m) => ({
            package: m.component,
            version: m.version,
            cve: m.entry.cve,
            cvss: m.entry.cvss,
            severity: m.entry.severity,
            weakness: m.entry.weakness,
            fixedIn: m.entry.fixedIn,
            reference: m.entry.reference,
          })),
        },
        null,
        2,
      ),
    );
    process.exit(gating > 0 ? 1 : 0);
  }

  console.error(`${C.cyan}SCA${C.reset} ${manifest.format} · ${scanned} packages · source: ${sourceUsed}`);
  console.log('');
  if (matches.length === 0) {
    console.log(`${C.green}✓ No known vulnerabilities found.${C.reset}`);
  } else {
    for (const m of matches) {
      const sc = sevColor(m.entry.severity);
      console.log(`${sc}${C.bold}${m.entry.severity.toUpperCase().padEnd(8)}${C.reset} ${m.component}@${m.version}  ${sc}${m.entry.cve}${C.reset} ${C.gray}(CVSS ${m.entry.cvss})${C.reset}`);
      console.log(`  ${C.gray}${m.entry.weakness} — fix: ${m.entry.fixedIn}${C.reset}`);
    }
    console.log('');
    console.log(
      `${C.red}${summary.critical} critical${C.reset}  ${C.red}${summary.high} high${C.reset}  ${C.yellow}${summary.medium} medium${C.reset}  ${summary.low} low`,
    );
  }
  console.log('');
  if (gating > 0) {
    console.error(`${C.red}✗ ${gating} vulnerabilit${gating === 1 ? 'y' : 'ies'} at or above "${args.failOn}" — failing.${C.reset}`);
    process.exit(1);
  }
  console.error(`${C.green}✓ Nothing at or above "${args.failOn}".${C.reset}`);
  process.exit(0);
}

// Reference Severity type so it is available for future typed output.
export type { Severity };

main().catch((err) => {
  console.error(err);
  process.exit(2);
});
