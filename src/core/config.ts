/** Runtime configuration, environment-driven with safe defaults. */

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
}

function cveSource(): AppConfig['cve']['source'] {
  const v = (process.env.CVE_SOURCE ?? 'both').toLowerCase();
  return v === 'local' || v === 'osv' || v === 'both' ? v : 'both';
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
};
