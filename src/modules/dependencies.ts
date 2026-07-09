/** Module 19 — Dependency Intelligence: match detected components to known CVEs. */

import { finding, pass } from '../core/finding.js';
import type { Finding, ModuleResult, ScanContext, ScanModule } from '../core/types.js';
import { detectTechnologies } from './fingerprint.js';
import { matchVulnerabilities } from '../intel/cve-match.js';

const MODULE = 'dependencies';

const SEV_ORDER = { critical: 4, high: 3, medium: 2, low: 1 } as const;

export const dependenciesModule: ScanModule = {
  name: MODULE,
  title: 'Dependency Intelligence',
  category: 'security',
  mode: 'passive',
  description: 'Matches detected component versions against known CVEs and suggests upgrades.',
  async run(ctx: ScanContext): Promise<ModuleResult> {
    const t0 = performance.now();
    const page = await ctx.getPage();
    const detected = detectTechnologies(page);
    const { matches, sourceUsed } = await matchVulnerabilities(detected);
    const findings: Finding[] = [];

    // Group matches per component+version so one finding lists all its CVEs.
    const groups = new Map<string, typeof matches>();
    for (const m of matches) {
      const key = `${m.component}@${m.version}`;
      const arr = groups.get(key) ?? [];
      arr.push(m);
      groups.set(key, arr);
    }

    for (const [key, group] of groups) {
      const first = group[0]!;
      const worst = group.reduce((a, b) => (SEV_ORDER[b.entry.severity] > SEV_ORDER[a.entry.severity] ? b : a));
      const cves = group.map((g) => g.entry.cve);
      const maxCvss = Math.max(...group.map((g) => g.entry.cvss));
      const fixVersions = [...new Set(group.map((g) => g.entry.fixedIn))].sort();

      findings.push(
        finding({
          id: `deps.vuln.${key.replace(/[^a-z0-9]+/gi, '_')}`,
          module: MODULE,
          category: 'security',
          title: `${first.component} ${first.version} has ${group.length} known ${group.length === 1 ? 'vulnerability' : 'vulnerabilities'}`,
          severity: worst.entry.severity,
          status: 'fail',
          risk: `A publicly-detectable, outdated ${first.component} exposes the site to ${worst.entry.weakness.toLowerCase()} and other documented flaws.`,
          whyItMatters:
            `The page loads ${first.component} ${first.version}, which appears in public vulnerability databases. ` +
            `Attackers routinely fingerprint library versions and fire matching exploits automatically. Highest CVSS here: ${maxCvss}.`,
          technical:
            `Matched CVEs: ${group.map((g) => `${g.entry.cve} (CVSS ${g.entry.cvss}, ${g.entry.weakness}) — ${g.entry.summary}`).join(' | ')}. ` +
            `Upgrade ${first.component} to at least ${fixVersions[fixVersions.length - 1]} (or the latest stable).`,
          businessImpact:
            worst.entry.severity === 'critical' || worst.entry.severity === 'high'
              ? 'Potential account compromise, data theft, or denial of service via a well-documented, automatable exploit.'
              : 'Elevated XSS/abuse surface and audit/compliance findings for running outdated components.',
          probability: SEV_ORDER[worst.entry.severity] >= 3 ? 'high' : 'medium',
          cve: cves,
          owasp: ['A06:2021-Vulnerable and Outdated Components'],
          remediation: `Upgrade ${first.component} from ${first.version} to ${fixVersions[fixVersions.length - 1]}+ and add automated dependency scanning (Dependabot/Renovate) to prevent regressions.`,
          estimatedFixTime: '2-8 hours',
          exampleCode:
            first.component === 'jQuery'
              ? '<!-- Replace with a current, SRI-protected version -->\n<script src="https://code.jquery.com/jquery-3.7.1.min.js" integrity="sha256-..." crossorigin="anonymous"></script>'
              : `# Update the dependency to a fixed release\nnpm install ${first.component.toLowerCase().replace(/\.js$/, '')}@latest`,
          references: [...new Set(group.map((g) => g.entry.reference)), 'https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/'],
          evidence: { component: first.component, version: first.version, cves },
        }),
      );
    }

    if (matches.length === 0) {
      const versioned = detected.filter((d) => d.version);
      findings.push(
        pass(
          MODULE,
          'security',
          'deps.clean',
          versioned.length ? 'No known CVEs matched for detected component versions' : 'No versioned components to match',
          versioned.length
            ? `Checked ${versioned.map((d) => `${d.name} ${d.version}`).join(', ')} against the local CVE dataset; no matches. (Passive detection only covers components visible in the homepage; run SCA in CI for full coverage.)`
            : 'No component versions were detectable from the homepage. Run software-composition analysis (SCA) in CI for authoritative coverage.',
          { versioned },
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
        source: sourceUsed,
        matches: matches.map((m) => ({
          component: m.component,
          version: m.version,
          cve: m.entry.cve,
          cvss: m.entry.cvss,
          severity: m.entry.severity,
          weakness: m.entry.weakness,
          fixedIn: m.entry.fixedIn,
          reference: m.entry.reference,
        })),
      },
    };
  },
};
