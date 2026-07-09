/** AI Security Advisor types (Module 24). */

import type { AuditReport } from '../core/types.js';

export interface ChecklistItem {
  findingId: string;
  title: string;
  severity: string;
  category: string;
  estimatedFixTime: string;
}

export interface FindingGroup {
  theme: string;
  findingIds: string[];
  count: number;
}

export interface AdvisorOutput {
  provider: 'local' | 'anthropic';
  model?: string;
  /** Management-friendly narrative of the overall posture. */
  executiveSummary: string;
  /** Highest-impact actions, ordered. */
  prioritizedActions: string[];
  /** Every actionable finding as a checkable remediation item. */
  remediationChecklist: ChecklistItem[];
  /** Findings grouped by theme (e.g. OWASP category) to reduce duplication. */
  groups: FindingGroup[];
}

export interface Advisor {
  readonly provider: 'local' | 'anthropic';
  advise(report: AuditReport): Promise<AdvisorOutput>;
}

export interface Ticket {
  title: string;
  body: string;
  labels: string[];
  severity: string;
}
