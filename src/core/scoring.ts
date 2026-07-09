/**
 * Scoring engine.
 *
 * Each category starts at 100. Every failing/warning finding deducts points
 * based on severity (see {@link SEVERITY_WEIGHT}). Warnings apply half weight.
 * Scores are clamped to [0, 100]. The overall score is a weighted mean of the
 * category scores, matching the "Overall Score" gauge in the product spec.
 */

import {
  CATEGORIES,
  SEVERITY_WEIGHT,
  type AuditReport,
  type Category,
  type CategoryScore,
  type Finding,
  type FindingStatus,
} from './types.js';

/** Relative weight of each category in the overall score. */
export const CATEGORY_WEIGHTS: Record<Category, number> = {
  security: 3,
  performance: 2,
  infrastructure: 1.5,
  scalability: 1.5,
  seo: 1,
  accessibility: 1,
  maintainability: 1,
};

export function gradeFor(score: number): string {
  if (score >= 97) return 'A+';
  if (score >= 93) return 'A';
  if (score >= 90) return 'A-';
  if (score >= 87) return 'B+';
  if (score >= 83) return 'B';
  if (score >= 80) return 'B-';
  if (score >= 77) return 'C+';
  if (score >= 73) return 'C';
  if (score >= 70) return 'C-';
  if (score >= 60) return 'D';
  return 'F';
}

function emptyCounts(): Record<FindingStatus, number> {
  return { pass: 0, warn: 0, fail: 0, info: 0 };
}

export function scoreCategory(category: Category, findings: Finding[]): CategoryScore {
  const relevant = findings.filter((f) => f.category === category);
  const counts = emptyCounts();
  let penalty = 0;

  for (const f of relevant) {
    counts[f.status] += 1;
    if (f.status === 'fail') penalty += SEVERITY_WEIGHT[f.severity];
    else if (f.status === 'warn') penalty += SEVERITY_WEIGHT[f.severity] / 2;
  }

  const score = Math.max(0, Math.min(100, Math.round(100 - penalty)));
  return { category, score, grade: gradeFor(score), findingCounts: counts };
}

export function scoreAll(findings: Finding[]): {
  categories: CategoryScore[];
  overall: { score: number; grade: string };
} {
  const categories = CATEGORIES.map((c) => scoreCategory(c, findings));

  // Only weight categories that actually had at least one check run, so a scan
  // that skipped (say) accessibility doesn't drag the overall down to 100->lower.
  let weightSum = 0;
  let weighted = 0;
  for (const cat of categories) {
    const ran =
      cat.findingCounts.pass +
      cat.findingCounts.warn +
      cat.findingCounts.fail +
      cat.findingCounts.info;
    if (ran === 0) continue;
    const w = CATEGORY_WEIGHTS[cat.category];
    weightSum += w;
    weighted += w * cat.score;
  }

  const overallScore = weightSum === 0 ? 100 : Math.round(weighted / weightSum);
  return {
    categories,
    overall: { score: overallScore, grade: gradeFor(overallScore) },
  };
}

/** Sort findings for report display: worst first, passes last. */
export function sortFindings(findings: Finding[]): Finding[] {
  const statusRank: Record<FindingStatus, number> = { fail: 0, warn: 1, info: 2, pass: 3 };
  const sevRank = { critical: 0, high: 1, medium: 2, low: 3, info: 4 } as const;
  return [...findings].sort((a, b) => {
    if (statusRank[a.status] !== statusRank[b.status]) {
      return statusRank[a.status] - statusRank[b.status];
    }
    return sevRank[a.severity] - sevRank[b.severity];
  });
}

/** Convenience roll-up used by report renderers. */
export function summarize(report: AuditReport): {
  critical: number;
  high: number;
  medium: number;
  low: number;
  passed: number;
} {
  const out = { critical: 0, high: 0, medium: 0, low: 0, passed: 0 };
  for (const f of report.findings) {
    if (f.status === 'pass') out.passed += 1;
    else if (f.status !== 'info') out[f.severity as 'critical' | 'high' | 'medium' | 'low'] += 1;
  }
  return out;
}
