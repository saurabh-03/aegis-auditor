/**
 * Report diffing & regression assessment.
 *
 * Compares a new AuditReport against the previous one for the same target to
 * detect regressions (score drops, newly-introduced issues) and improvements
 * (resolved issues). Pure and deterministic — the basis for monitoring alerts.
 */

import type { AuditReport, Category, Finding, Severity } from './types.js';

export interface FindingDelta {
  id: string;
  title: string;
  severity: Severity;
  category: Category;
}

export interface CategoryDelta {
  category: Category;
  prev: number;
  curr: number;
  delta: number;
}

export interface ReportDiff {
  prevScore: number;
  currScore: number;
  scoreDelta: number;
  prevGrade: string;
  currGrade: string;
  /** Failing/warning findings present now but not before. */
  newFindings: FindingDelta[];
  /** Failing/warning findings present before but not now. */
  resolvedFindings: FindingDelta[];
  categoryDeltas: CategoryDelta[];
}

/** A finding is "active" (counts as an issue) when it did not pass. */
function isActive(f: Finding): boolean {
  return f.status === 'fail' || f.status === 'warn';
}

function toDelta(f: Finding): FindingDelta {
  return { id: f.id, title: f.title, severity: f.severity, category: f.category };
}

/** Diff two reports. Returns null when there is no prior baseline to compare. */
export function diffReports(prev: AuditReport | null, curr: AuditReport): ReportDiff | null {
  if (!prev) return null;

  const prevActive = new Map(prev.findings.filter(isActive).map((f) => [f.id, f]));
  const currActive = new Map(curr.findings.filter(isActive).map((f) => [f.id, f]));

  const newFindings: FindingDelta[] = [];
  for (const [id, f] of currActive) if (!prevActive.has(id)) newFindings.push(toDelta(f));

  const resolvedFindings: FindingDelta[] = [];
  for (const [id, f] of prevActive) if (!currActive.has(id)) resolvedFindings.push(toDelta(f));

  const prevCat = new Map(prev.categories.map((c) => [c.category, c.score]));
  const categoryDeltas: CategoryDelta[] = curr.categories
    .map((c) => {
      const before = prevCat.get(c.category) ?? c.score;
      return { category: c.category, prev: before, curr: c.score, delta: c.score - before };
    })
    .filter((d) => d.delta !== 0);

  const sevRank: Record<Severity, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  newFindings.sort((a, b) => sevRank[a.severity] - sevRank[b.severity]);
  resolvedFindings.sort((a, b) => sevRank[a.severity] - sevRank[b.severity]);

  return {
    prevScore: prev.overall.score,
    currScore: curr.overall.score,
    scoreDelta: curr.overall.score - prev.overall.score,
    prevGrade: prev.overall.grade,
    currGrade: curr.overall.grade,
    newFindings,
    resolvedFindings,
    categoryDeltas,
  };
}

export interface RegressionAssessment {
  isRegression: boolean;
  level: 'none' | 'minor' | 'major';
  reasons: string[];
}

/**
 * Decide whether a diff represents a regression worth alerting on.
 * Major: any new critical/high finding, or a score drop of 15+.
 * Minor: a score drop of 5-14, or a new medium finding.
 */
export function assessRegression(diff: ReportDiff | null): RegressionAssessment {
  if (!diff) return { isRegression: false, level: 'none', reasons: [] };

  const reasons: string[] = [];
  const newCriticalHigh = diff.newFindings.filter((f) => f.severity === 'critical' || f.severity === 'high');
  const newMedium = diff.newFindings.filter((f) => f.severity === 'medium');

  let level: RegressionAssessment['level'] = 'none';

  if (newCriticalHigh.length > 0) {
    level = 'major';
    reasons.push(`${newCriticalHigh.length} new high/critical issue(s): ${newCriticalHigh.map((f) => f.title).join('; ')}`);
  }
  if (diff.scoreDelta <= -15) {
    level = 'major';
    reasons.push(`Overall score dropped ${Math.abs(diff.scoreDelta)} points (${diff.prevScore} → ${diff.currScore})`);
  }
  if (level !== 'major') {
    if (diff.scoreDelta <= -5) {
      level = 'minor';
      reasons.push(`Overall score dropped ${Math.abs(diff.scoreDelta)} points (${diff.prevScore} → ${diff.currScore})`);
    }
    if (newMedium.length > 0) {
      level = 'minor';
      reasons.push(`${newMedium.length} new medium issue(s)`);
    }
  }

  return { isRegression: level !== 'none', level, reasons };
}
