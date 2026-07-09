/**
 * Deterministic, offline advisor. Synthesizes an executive summary, prioritized
 * actions, remediation checklist, and grouped findings directly from the
 * structured (already-explained) findings — no LLM required. Always available.
 */

import type { AuditReport } from '../core/types.js';
import { actionableFindings, checklist, counts, groupFindings } from './shared.js';
import type { Advisor, AdvisorOutput } from './types.js';

export class LocalAdvisor implements Advisor {
  readonly provider = 'local' as const;

  async advise(report: AuditReport): Promise<AdvisorOutput> {
    const c = counts(report);
    const top = actionableFindings(report).slice(0, 5);
    const host = safeHost(report.target);

    const posture =
      report.overall.score >= 90
        ? 'strong'
        : report.overall.score >= 75
        ? 'reasonable but improvable'
        : report.overall.score >= 60
        ? 'weak and in need of attention'
        : 'poor and carrying material risk';

    const headline =
      c.critical > 0
        ? `${c.critical} critical issue${c.critical > 1 ? 's require' : ' requires'} immediate action.`
        : c.high > 0
        ? `${c.high} high-severity issue${c.high > 1 ? 's should' : ' should'} be prioritized this sprint.`
        : 'No critical or high-severity issues were found — focus on incremental hardening.';

    const executiveSummary =
      `${host} scored ${report.overall.score}/100 (${report.overall.grade}) — an overall security and scalability posture that is ${posture}. ` +
      `The audit ran ${report.modules.filter((m) => m.ok).length} modules and found ${c.critical} critical, ${c.high} high, ${c.medium} medium, and ${c.low} low-severity issues, with ${c.passed} checks passing. ` +
      `${headline} ` +
      (top.length
        ? `The most impactful items are: ${top.map((f) => f.title).join('; ')}. Addressing these first yields the largest risk reduction for the effort.`
        : '');

    const prioritizedActions = top.map((f, i) => {
      const verb = f.severity === 'critical' || f.severity === 'high' ? 'Immediately' : 'Then';
      return `${i + 1}. ${verb} ${lowerFirst(f.remediation)} (${f.title} — ~${f.estimatedFixTime}, ${f.severity}).`;
    });

    return {
      provider: 'local',
      executiveSummary,
      prioritizedActions,
      remediationChecklist: checklist(report),
      groups: groupFindings(report),
    };
  }
}

function safeHost(target: string): string {
  try {
    return new URL(target).hostname;
  } catch {
    return target;
  }
}

function lowerFirst(s: string): string {
  return s ? s.charAt(0).toLowerCase() + s.slice(1) : s;
}
