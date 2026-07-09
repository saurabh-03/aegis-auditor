/** Module 5 — Technology detection (passive fingerprinting). */

import { finding, pass } from '../core/finding.js';
import type { Finding, ModuleResult, ScanContext, ScanModule } from '../core/types.js';
import { detectTechnologies } from './fingerprint.js';

const MODULE = 'tech';

export const techModule: ScanModule = {
  name: MODULE,
  title: 'Technology Detection',
  category: 'infrastructure',
  mode: 'passive',
  description: 'Fingerprints CMS, frameworks, CDN, hosting, and libraries from headers and HTML.',
  async run(ctx: ScanContext): Promise<ModuleResult> {
    const t0 = performance.now();
    const page = await ctx.getPage();
    const findings: Finding[] = [];
    const detected = detectTechnologies(page);

    if (detected.length === 0) {
      findings.push(pass(MODULE, 'infrastructure', 'tech.none', 'No common technologies fingerprinted', 'The passive fingerprint did not match known signatures (this can indicate a hardened or custom stack).'));
    } else {
      findings.push(
        pass(
          MODULE,
          'infrastructure',
          'tech.detected',
          `Detected ${detected.length} technologies`,
          detected.map((d) => `${d.name}${d.version ? ' ' + d.version : ''} (${d.category})`).join(', '),
          { detected },
        ),
      );
    }

    // Flag exposed version numbers as a maintainability/security signal.
    const versioned = detected.filter((d) => d.version);
    if (versioned.length > 0) {
      findings.push(
        finding({
          id: 'tech.version-disclosure',
          module: MODULE,
          category: 'security',
          title: 'Library/framework versions are publicly detectable',
          severity: 'low',
          status: 'warn',
          risk: 'Exposed versions let attackers map your stack to known CVEs.',
          whyItMatters: `Detected versions: ${versioned.map((d) => `${d.name} ${d.version}`).join(', ')}. Attackers cross-reference these against public vulnerability databases.`,
          technical: 'Cross-check each detected version against the NVD/GitHub Advisory Database and upgrade any that are behind. This module does not assert a specific CVE without a version match; use the Dependency Intelligence module for that.',
          businessImpact: 'Lower attacker effort and a larger exploitable surface if any component is outdated.',
          probability: 'low',
          owasp: ['A06:2021-Vulnerable and Outdated Components'],
          remediation: 'Keep components patched and avoid leaking exact versions where feasible.',
          estimatedFixTime: 'Ongoing',
          references: ['https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/'],
          evidence: { versioned },
        }),
      );
    }

    return { module: MODULE, category: 'infrastructure', ok: true, findings, durationMs: Math.round(performance.now() - t0), data: { detected } };
  },
};
