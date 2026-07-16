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
 * How sure the engine is that a finding is real. Passive checks are effectively
 * `confirmed` (they observe a fact); active scanners (ZAP/Nuclei) range from a
 * template match (`tentative`/`firm`) to a verified exploit (`confirmed`).
 */
export type Confidence = 'tentative' | 'firm' | 'confirmed';

/**
 * WHERE a finding was observed. Passive, site-wide findings omit this; active
 * per-endpoint findings carry it so the report and the regression-diff engine
 * can track "this issue on this endpoint" over time.
 */
export interface FindingLocation {
  url: string;
  param?: string;
  method?: string;
}

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
  /** CWE weakness identifiers, e.g. `CWE-79`. Populated by active scanners. */
  cwe?: string[];
  /** OWASP category mappings, e.g. `A05:2021-Security Misconfiguration`. */
  owasp?: string[];
  /** Engine confidence; defaults to `confirmed` for passive fact-based checks. */
  confidence?: Confidence;
  /**
   * Modules that independently reported this issue, set by the finding-quality
   * pass when duplicates are merged. ≥2 distinct engines raises confidence.
   */
  corroboratedBy?: string[];
  /** Endpoint/parameter the finding was observed at (active findings). */
  location?: FindingLocation;
  /** Captured request/response evidence for triage (active findings). */
  requestResponse?: { request: string; response: string };
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

/**
 * Automated form-login: drive a real browser to submit a login form and capture
 * the resulting session, so the scan can authenticate from a username/password
 * instead of a hand-copied cookie/token. Requires the optional browser engine.
 */
export interface FormLogin {
  /** URL of the page containing the login form. */
  loginUrl: string;
  username: string;
  password: string;
  /** CSS selector for the username field (default: heuristic guess). */
  usernameSelector?: string;
  /** CSS selector for the password field (default: `input[type=password]`). */
  passwordSelector?: string;
  /** CSS selector for the submit control (default: heuristic guess). */
  submitSelector?: string;
}

/**
 * Credentials for an authenticated scan. Lets the crawler and active modules
 * reach past a login wall so logged-in surface is tested, not just the public
 * shell.
 *
 * SECURITY: these are secrets. They are used only in-flight to authenticate
 * outbound requests — they must never be written into findings, evidence, the
 * persisted report, or logs. The engine treats them as write-only.
 */
export interface ScanAuth {
  /** Extra request headers, e.g. `{ Authorization: "Bearer …" }`. */
  headers?: Record<string, string>;
  /** Raw Cookie header value, e.g. `"session=abc; theme=dark"`. */
  cookies?: string;
  /**
   * URL substrings the crawler must never follow — logout-avoidance. Matched
   * anywhere in the absolute URL; defaults (logout/signout/…) are always added.
   */
  excludeUrlPatterns?: string[];
  /**
   * Automated form-login. When present, the engine performs the login once
   * before crawling and merges the captured session into the auth above.
   */
  login?: FormLogin;
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
  /** Credentials for an authenticated scan (never persisted; see {@link ScanAuth}). */
  auth?: ScanAuth;
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

/**
 * A single injectable request surface discovered by the crawler: a URL plus the
 * method and parameter names an active tester (ZAP/Nuclei) would fuzz.
 */
export interface Endpoint {
  /** Absolute, normalized URL (query string preserved for GET params). */
  url: string;
  method: 'GET' | 'POST';
  /** Names of query- and body-parameters observed for this endpoint. */
  params: string[];
  /** How the endpoint was discovered. */
  source: 'seed' | 'link' | 'form' | 'xhr' | 'sitemap';
  /** Response content-type when known (e.g. `text/html`, `application/json`). */
  contentType?: string;
}

/** An HTML form discovered during the crawl. */
export interface DiscoveredForm {
  /** Absolute action URL the form submits to. */
  action: string;
  method: 'GET' | 'POST';
  /** Names of the form's input/select/textarea controls. */
  inputs: string[];
  /** URL of the page the form was found on. */
  foundOn: string;
  /** True when a CSRF-token-looking hidden field is present. */
  hasCsrfToken: boolean;
}

/**
 * The shared attack-surface map produced once per scan by the crawler and
 * consumed by later modules (passive coverage checks now; active ZAP/Nuclei
 * modules in Phase B). Mirrors the single-fetch {@link PageSnapshot} pattern:
 * built lazily and cached so the crawl happens at most once.
 */
export interface AttackSurface {
  /** Deduplicated injectable endpoints, in discovery order. */
  endpoints: Endpoint[];
  /** Forms discovered across crawled pages. */
  forms: DiscoveredForm[];
  /** In-scope hosts encountered (the seed host plus same-site subdomains). */
  discoveredHosts: string[];
  /** URLs that were in-links but out of scope (off-site / blocked). */
  offScopeUrls: string[];
  /** Number of pages actually fetched/rendered. */
  crawledCount: number;
  /** True if a page/depth cap stopped the crawl before exhaustion. */
  truncated: boolean;
  /** True when a real browser rendered pages; false for the HTTP-only fallback. */
  renderedWithBrowser: boolean;
}

/** Shared context passed to every module. */
export interface ScanContext {
  target: URL;
  options: Required<Pick<ScanOptions, 'authorized' | 'timeoutMs'>> & ScanOptions;
  now: Date;
  log: (msg: string) => void;
  /**
   * Report intra-module progress (0..1) for long-running modules (active DAST).
   * Best-effort and optional: modules that finish quickly need not call it, and
   * the fraction is clamped. `note` is a short human label (e.g. "40% · 20/50").
   */
  progress(fraction: number, note?: string): void;
  /** Cached homepage fetch; first caller triggers the network request. */
  getPage(): Promise<PageSnapshot>;
  /**
   * Cached attack-surface crawl; first caller triggers the crawl. Shared by all
   * modules so the site is crawled at most once per scan.
   */
  getSurface(): Promise<AttackSurface>;
  /**
   * Generic fetch helper honoring the scan timeout. When the scan carries
   * {@link ScanAuth}, auth headers/cookies are injected automatically.
   */
  fetch(url: string, init?: RequestInit): Promise<Response>;
  /**
   * Authenticated-scan credentials, if any. Active modules read this to pass
   * auth to their engines (Nuclei `-H`, ZAP replacer). Write-only — never copy
   * into findings or logs.
   */
  auth?: ScanAuth;
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
    /** Duplicate findings collapsed by the finding-quality pass. */
    mergedDuplicates?: number;
  };
}
