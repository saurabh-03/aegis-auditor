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

export interface ApiKey {
  id: string;
  orgId: string;
  userId: string;
  name: string;
  keyPrefix: string;
  lastUsedAt: string | null;
  createdAt: string;
  revokedAt: string | null;
}

export type WebhookEvent = 'regression' | 'scan_complete';
export interface Webhook {
  id: string;
  orgId: string;
  url: string;
  events: WebhookEvent[];
  active: boolean;
  createdAt: string;
}

export type Cadence = 'daily' | 'weekly' | 'monthly';

/** Optional per-scan credentials collected in the UI (never stored client-side). */
export interface ScanAuthInput {
  authHeaders?: Record<string, string>;
  authCookie?: string;
  excludeUrlPatterns?: string[];
  formLogin?: { loginUrl: string; username: string; password: string };
}

export interface Schedule {
  id: string;
  projectId: string;
  orgId: string;
  cadence: Cadence;
  includeActive: boolean;
  enabled: boolean;
  webhookUrl: string | null;
  nextRunAt: string;
  lastRunAt: string | null;
  createdAt: string;
}

export interface AppNotification {
  id: string;
  orgId: string;
  type: 'regression' | 'scan_complete';
  scanId: string | null;
  projectId: string | null;
  title: string;
  body: string;
  severity: 'info' | 'warning' | 'critical';
  read: boolean;
  createdAt: string;
}

export interface FindingDelta {
  id: string;
  title: string;
  severity: Severity;
  category: Category;
}

export interface ReportDiff {
  prevScore: number;
  currScore: number;
  scoreDelta: number;
  prevGrade: string;
  currGrade: string;
  newFindings: FindingDelta[];
  resolvedFindings: FindingDelta[];
  categoryDeltas: { category: Category; prev: number; curr: number; delta: number }[];
}

export interface RegressionAssessment {
  isRegression: boolean;
  level: 'none' | 'minor' | 'major';
  reasons: string[];
}

export interface ProgressEvent {
  scanId: string;
  type: 'queued' | 'running' | 'module' | 'module-progress' | 'completed' | 'failed';
  progress?: number;
  module?: string;
  moduleOk?: boolean;
  /** Fraction (0..1) within the current module, for `module-progress`. */
  moduleProgress?: number;
  /** Short label for `module-progress`, e.g. "40% · 20/50 req". */
  note?: string;
  overall?: number;
  grade?: string;
  error?: string;
}
