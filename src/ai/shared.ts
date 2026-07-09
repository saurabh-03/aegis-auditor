/** Shared advisor helpers used by both the local and Anthropic advisors. */

import type { AuditReport, Finding } from '../core/types.js';
import type { ChecklistItem, FindingGroup } from './types.js';

const SEV_RANK: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
const PROB_RANK: Record<string, number> = { high: 3, medium: 2, low: 1 };

/** Priority score: severity dominates, probability breaks ties. */
export function priority(f: Finding): number {
  return (SEV_RANK[f.severity] ?? 0) * 10 + (PROB_RANK[f.probability] ?? 0);
}

export function actionableFindings(report: AuditReport): Finding[] {
  return report.findings
    .filter((f) => f.status === 'fail' || f.status === 'warn')
    .sort((a, b) => priority(b) - priority(a));
}

export function checklist(report: AuditReport): ChecklistItem[] {
  return actionableFindings(report).map((f) => ({
    findingId: f.id,
    title: f.title,
    severity: f.severity,
    category: f.category,
    estimatedFixTime: f.estimatedFixTime,
  }));
}

/** Group findings by their primary OWASP category, falling back to audit category. */
export function groupFindings(report: AuditReport): FindingGroup[] {
  const map = new Map<string, string[]>();
  for (const f of actionableFindings(report)) {
    const theme = f.owasp?.[0] ?? `Category: ${f.category}`;
    const arr = map.get(theme) ?? [];
    arr.push(f.id);
    map.set(theme, arr);
  }
  return [...map.entries()]
    .map(([theme, findingIds]) => ({ theme, findingIds, count: findingIds.length }))
    .sort((a, b) => b.count - a.count);
}

export function counts(report: AuditReport): { critical: number; high: number; medium: number; low: number; passed: number } {
  const out = { critical: 0, high: 0, medium: 0, low: 0, passed: 0 };
  for (const f of report.findings) {
    if (f.status === 'pass') out.passed++;
    else if (f.severity === 'critical') out.critical++;
    else if (f.severity === 'high') out.high++;
    else if (f.severity === 'medium') out.medium++;
    else if (f.severity === 'low') out.low++;
  }
  return out;
}
