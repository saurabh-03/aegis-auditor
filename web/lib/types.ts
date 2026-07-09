/** Frontend mirror of the backend report/finding shapes (see ../../src/core/types.ts). */

export type Severity = 'info' | 'low' | 'medium' | 'high' | 'critical';
export type FindingStatus = 'pass' | 'warn' | 'fail' | 'info';
export type Category =
  | 'security'
  | 'performance'
  | 'infrastructure'
  | 'scalability'
  | 'seo'
  | 'accessibility'
  | 'maintainability';

export interface Finding {
  id: string;
  module: string;
  category: Category;
  title: string;
  severity: Severity;
  status: FindingStatus;
  risk: string;
  whyItMatters: string;
  technical: string;
  businessImpact: string;
  probability: 'low' | 'medium' | 'high';
  cve?: string[];
  owasp?: string[];
  remediation: string;
  estimatedFixTime: string;
  exampleCode?: string;
  references: string[];
}

export interface CategoryScore {
  category: Category;
  score: number;
  grade: string;
  findingCounts: Record<FindingStatus, number>;
}

/** Per-module structured data used by the inspector panels. Loosely typed
 *  because each module contributes its own shape (see src/modules/*). */
export type ModuleData = Record<string, unknown>;

export interface AuditReport {
  target: string;
  scannedAt: string;
  durationMs: number;
  overall: { score: number; grade: string };
  categories: CategoryScore[];
  findings: Finding[];
  data?: Record<string, ModuleData | undefined>;
  meta: { engineVersion: string; passiveOnly: boolean };
}

export interface User {
  id: string;
  email: string;
  name: string | null;
}

export interface Organization {
  id: string;
  name: string;
  slug: string;
  role: string;
}

export interface Project {
  id: string;
  orgId: string;
  name: string;
  target: string;
  verifiedAt: string | null;
}

export interface AdvisorOutput {
  provider: string;
  model?: string;
  executiveSummary: string;
  prioritizedActions: string[];
  remediationChecklist: { findingId: string; title: string; severity: string; category: string; estimatedFixTime: string }[];
  groups: { theme: string; findingIds: string[]; count: number }[];
}

export interface ProgressEvent {
  scanId: string;
  type: 'queued' | 'running' | 'module' | 'completed' | 'failed';
  progress?: number;
  module?: string;
  moduleOk?: boolean;
  overall?: number;
  grade?: string;
  error?: string;
}
