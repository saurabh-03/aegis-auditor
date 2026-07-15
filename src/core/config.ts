/** Runtime configuration, environment-driven with safe defaults. */

import type { NucleiSeverity } from '../integrations/nuclei.js';

export const ENGINE_VERSION = '0.1.0';

export interface AppConfig {
  host: string;
  port: number;
  /** Default per-request network timeout in ms. */
  defaultTimeoutMs: number;
  /** User-Agent used for all outbound requests. */
  userAgent: string;
  /** Max scans allowed per window per client (simple in-memory rate limit). */
  rateLimit: { windowMs: number; max: number };
  /** Dependency CVE intelligence source. */
  cve: {
    /** 'local' = offline dataset only; 'osv' = OSV.dev only; 'both' = OSV + local, deduped. */
    source: 'local' | 'osv' | 'both';
    /** Per-package OSV request timeout. */
    timeoutMs: number;
  };
  /** Headless-browser lab metrics (Core Web Vitals + resource waterfall). */
  browser: {
    /** When false, the web-vitals module is skipped entirely. */
    enabled: boolean;
    /** Page-load timeout for the browser run. */
    timeoutMs: number;
    /** 'mobile' | 'desktop' form factor for the emulated viewport. */
    formFactor: 'mobile' | 'desktop';
  };
  /** Attack-surface crawler (feeds the spider module and, later, active DAST). */
  crawl: {
    /** Max pages fetched/rendered per scan. */
    maxPages: number;
    /** Max link depth from the seed. */
    maxDepth: number;
    /** Render pages in a real browser (needs Puppeteer; HTTP fallback otherwise). */
    renderJs: boolean;
    /** Honor robots.txt Disallow rules while crawling. */
    respectRobots: boolean;
  };
  /** Nuclei active-DAST integration (authorization-gated; optional binary). */
  nuclei: {
    /** Binary name/path (`NUCLEI_BIN`); the adapter degrades if it's absent. */
    binaryPath: string;
    /** Severity floor sent to Nuclei's `-severity` filter. */
    severities: NucleiSeverity[];
    /** Requests-per-second cap. */
    rateLimit: number;
    /** Hard kill timeout for the whole Nuclei run. */
    timeoutMs: number;
    /** Cap on endpoints handed to Nuclei per scan (bounds run time). */
    maxTargets: number;
  };
  /** Recurring-scan scheduler. */
  scheduler: {
    enabled: boolean;
    /** How often to poll for due schedules. */
    intervalMs: number;
  };
  /** Hardening for public/internet-facing deployments. */
  security: {
    /** Reject scans of private/reserved/internal targets (SSRF guard). */
    blockPrivateTargets: boolean;
    /** Require a signed-in user (or API key) for the quick /api/scan endpoint. */
    requireAuthForScan: boolean;
  };
}

/** Env flag helper: truthy unless explicitly off. */
function flag(name: string, defaultOn: boolean): boolean {
  const raw = process.env[name];
  if (raw === undefined) return defaultOn;
  return !['off', 'false', '0', 'no'].includes(raw.toLowerCase());
}

function cveSource(): AppConfig['cve']['source'] {
  const v = (process.env.CVE_SOURCE ?? 'both').toLowerCase();
  return v === 'local' || v === 'osv' || v === 'both' ? v : 'both';
}

/** Parse NUCLEI_SEVERITIES (comma list); default medium and up to keep noise down. */
function nucleiSeverities(): NucleiSeverity[] {
  const valid: NucleiSeverity[] = ['info', 'low', 'medium', 'high', 'critical', 'unknown'];
  const raw = (process.env.NUCLEI_SEVERITIES ?? 'medium,high,critical')
    .split(',')
    .map((s) => s.trim().toLowerCase())
    .filter((s): s is NucleiSeverity => (valid as string[]).includes(s));
  return raw.length ? raw : ['medium', 'high', 'critical'];
}

/** Browser metrics are attempted unless explicitly disabled. If Puppeteer is not
 *  installed the module degrades to an info finding — so 'auto' is safe. */
function browserEnabled(): boolean {
  const v = (process.env.BROWSER_METRICS ?? 'auto').toLowerCase();
  return !(v === 'off' || v === 'false' || v === '0' || v === 'no');
}

function int(name: string, fallback: number): number {
  const raw = process.env[name];
  if (!raw) return fallback;
  const n = Number.parseInt(raw, 10);
  return Number.isFinite(n) ? n : fallback;
}

export const config: AppConfig = {
  host: process.env.HOST ?? '0.0.0.0',
  port: int('PORT', 4000),
  defaultTimeoutMs: int('SCAN_TIMEOUT_MS', 12_000),
  userAgent:
    process.env.USER_AGENT ??
    'AegisAuditor/0.1 (+https://example.com/aegis; defensive-security-scanner)',
  rateLimit: {
    windowMs: int('RATE_LIMIT_WINDOW_MS', 60_000),
    max: int('RATE_LIMIT_MAX', 20),
  },
  cve: {
    source: cveSource(),
    timeoutMs: int('CVE_TIMEOUT_MS', 6_000),
  },
  browser: {
    enabled: browserEnabled(),
    timeoutMs: int('BROWSER_TIMEOUT_MS', 30_000),
    formFactor: (process.env.BROWSER_FORM_FACTOR ?? 'desktop') === 'mobile' ? 'mobile' : 'desktop',
  },
  crawl: {
    maxPages: int('CRAWL_MAX_PAGES', 25),
    maxDepth: int('CRAWL_MAX_DEPTH', 3),
    // Reuse the browser engine unless it's explicitly turned off; degrades to
    // an HTTP-only crawl when Puppeteer isn't installed.
    renderJs: browserEnabled(),
    respectRobots: flag('CRAWL_RESPECT_ROBOTS', true),
  },
  nuclei: {
    binaryPath: process.env.NUCLEI_BIN ?? 'nuclei',
    severities: nucleiSeverities(),
    rateLimit: int('NUCLEI_RATE_LIMIT', 150),
    timeoutMs: int('NUCLEI_TIMEOUT_MS', 180_000),
    maxTargets: int('NUCLEI_MAX_TARGETS', 50),
  },
  security: {
    // Safe by default: block internal targets. Set ALLOW_PRIVATE_TARGETS=1 for
    // local development if you need to scan localhost / a LAN host.
    blockPrivateTargets: !flag('ALLOW_PRIVATE_TARGETS', false),
    requireAuthForScan: flag('REQUIRE_AUTH_FOR_SCAN', false),
  },
  scheduler: {
    enabled: !['off', 'false', '0', 'no'].includes((process.env.SCHEDULER_ENABLED ?? 'on').toLowerCase()),
    intervalMs: int('SCHEDULER_INTERVAL_MS', 60_000),
  },
};
