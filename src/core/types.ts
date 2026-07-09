/**
 * Core domain types shared across the scanning engine, modules, scoring,
 * reporting, and the API layer.
 *
 * The design goal: every finding is *self-explaining*. A finding never just
 * says "Missing CSP" — it carries severity, risk, why it matters, technical
 * and business explanations, remediation, example code, OWASP/CVE mappings,
 * and references. See {@link Finding}.
 */

/** Audit categories that roll up into the overall score. */
export type Category =
  | 'security'
  | 'performance'
  | 'infrastructure'
  | 'scalability'
  | 'seo'
  | 'accessibility'
  | 'maintainability';

export const CATEGORIES: Category[] = [
  'security',
  'performance',
  'infrastructure',
  'scalability',
  'seo',
  'accessibility',
  'maintainability',
];

/** Severity levels, ordered. Higher index = more severe. */
export type Severity = 'info' | 'low' | 'medium' | 'high' | 'critical';

export const SEVERITY_ORDER: Severity[] = ['info', 'low', 'medium', 'high', 'critical'];

/** Point penalty applied to a category score for a failing finding. */
export const SEVERITY_WEIGHT: Record<Severity, number> = {
  info: 0,
  low: 3,
  medium: 8,
  high: 18,
  critical: 35,
};

/** Outcome of a single check. */
export type FindingStatus = 'pass' | 'warn' | 'fail' | 'info';

/** Likelihood that a weakness is exploited or causes impact. */
export type Probability = 'low' | 'medium' | 'high';

/**
 * A fully-explained audit finding. This is the atomic unit of a report.
 *
 * Passive modules must be able to populate every field from evidence they
 * observed. Fields that do not apply (e.g. `cve` for a config issue) may be
 * omitted, but the explanatory fields (`risk`, `whyItMatters`, `technical`,
 * `businessImpact`, `remediation`) are always required for non-pass findings.
 */
export interface Finding {
  /** Stable identifier, e.g. `headers.csp.missing`. Used for dedup & history. */
  id: string;
  /** Module that produced the finding, e.g. `security-headers`. */
  module: string;
  category: Category;
  title: string;
  severity: Severity;
  status: FindingStatus;
  /** One-line statement of the risk. */
  risk: string;
  /** Plain-language explanation for non-experts. */
  whyItMatters: string;
  /** Deep technical explanation of the mechanism. */
  technical: string;
  /** What this means for the business / stakeholders. */
  businessImpact: string;
  probability: Probability;
  /** CVE identifiers when a specific vulnerable component/version is matched. */
  cve?: string[];
  /** OWASP category mappings, e.g. `A05:2021-Security Misconfiguration`. */
  owasp?: string[];
  /** Concrete remediation guidance. */
  remediation: string;
  /** Human estimate of engineering effort, e.g. "15 minutes", "0.5 day". */
  estimatedFixTime: string;
  /** Copy-paste-ready example config/code fixing the issue. */
  exampleCode?: string;
  references: string[];
  /** Raw observed evidence (headers, values, timings) for auditability. */
  evidence?: Record<string, unknown>;
}

/** Result returned by a single module run. */
export interface ModuleResult {
  module: string;
  category: Category;
  /** True if the module ran to completion. */
  ok: boolean;
  /** Populated when `ok` is false. */
  error?: string;
  findings: Finding[];
  /** Milliseconds the module took. */
  durationMs: number;
  /** Arbitrary structured data for visualizations (cert timeline, DNS, etc.). */
  data?: Record<string, unknown>;
}

/** Whether a module is safe to run without owner authorization. */
export type ScanMode = 'passive' | 'active';

/** Contract every scanning module implements. */
export interface ScanModule {
  /** Unique key, e.g. `ssl`. */
  name: string;
  /** Human title, e.g. "SSL / TLS Analysis". */
  title: string;
  category: Category;
  mode: ScanMode;
  /** Short description shown in UI and docs. */
  description: string;
  run(ctx: ScanContext): Promise<ModuleResult>;
}

/** Options that shape a scan. */
export interface ScanOptions {
  /**
   * Explicit authorization from the requester that they own or are permitted
   * to test the target. Required for any `active` module to execute.
   */
  authorized: boolean;
  /** Restrict to these module names; empty/undefined = all eligible. */
  only?: string[];
  /** Skip these module names. */
  skip?: string[];
  /** Include active (intrusive) modules. Requires `authorized`. */
  includeActive?: boolean;
  /** Per-request timeout in ms for network calls. */
  timeoutMs?: number;
}

/** Snapshot of the target's homepage fetched once and shared by modules. */
export interface PageSnapshot {
  finalUrl: string;
  status: number;
  headers: Record<string, string>;
  /** Raw `set-cookie` header lines. */
  setCookie: string[];
  body: string;
  /** Redirect chain leading to the final URL. */
  redirects: RedirectHop[];
  /** Total time-to-first-byte-ish latency in ms for the final request. */
  latencyMs: number;
}

export interface RedirectHop {
  url: string;
  status: number;
  location: string;
}

/** Shared context passed to every module. */
export interface ScanContext {
  target: URL;
  options: Required<Pick<ScanOptions, 'authorized' | 'timeoutMs'>> & ScanOptions;
  now: Date;
  log: (msg: string) => void;
  /** Cached homepage fetch; first caller triggers the network request. */
  getPage(): Promise<PageSnapshot>;
  /** Generic fetch helper honoring the scan timeout. */
  fetch(url: string, init?: RequestInit): Promise<Response>;
}

/** Aggregate score for one category. */
export interface CategoryScore {
  category: Category;
  score: number; // 0..100
  grade: string; // A+ .. F
  findingCounts: Record<FindingStatus, number>;
}

/** The complete audit report. */
export interface AuditReport {
  target: string;
  scannedAt: string;
  durationMs: number;
  authorized: boolean;
  overall: {
    score: number;
    grade: string;
  };
  categories: CategoryScore[];
  findings: Finding[];
  modules: Array<Pick<ModuleResult, 'module' | 'category' | 'ok' | 'error' | 'durationMs'>>;
  /** Module-specific structured data keyed by module name. */
  data: Record<string, Record<string, unknown> | undefined>;
  meta: {
    engineVersion: string;
    passiveOnly: boolean;
  };
}
