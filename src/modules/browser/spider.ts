/**
 * Attack-surface crawler.
 *
 * Walks a site breadth-first and returns the {@link AttackSurface} that later
 * modules consume: the deduplicated set of injectable endpoints (URLs + params),
 * the forms, and the in/out-of-scope host split.
 *
 * Two engines, one contract:
 *   - Browser engine (Puppeteer, optional dependency) renders each page so
 *     JavaScript-built links, SPA routes, and XHR/fetch calls are discovered.
 *     Imported through a string specifier so the project builds WITHOUT it —
 *     exactly like `measure.ts`.
 *   - HTTP fallback (always available) fetches raw HTML and extracts <a>/<form>
 *     with regex. No JS execution, so it sees fewer routes, but a crawl still
 *     happens headless-free.
 *
 * Safety is non-negotiable and lives here, not in the caller:
 *   - EVERY discovered URL is re-checked with the SSRF guard before it is
 *     fetched. The seed is asserted once by the scanner, but a crawler follows
 *     links to new hosts, so each must be re-verified or the SSRF hole reopens.
 *   - Scope is limited to the seed's registrable domain (+ subdomains).
 *   - Page and depth caps bound the work; URL-pattern dedup collapses
 *     `/user/1`, `/user/2`, … into one representative endpoint.
 *   - robots.txt Disallow rules are honored when `respectRobots` is set.
 */

import { config } from '../../core/config.js';
import { assertPublicHost, BlockedTargetError } from '../../core/ssrf.js';
import { timedFetch } from '../../core/http.js';
import type { AttackSurface, DiscoveredForm, Endpoint } from '../../core/types.js';

export interface CrawlOptions {
  maxPages: number;
  maxDepth: number;
  /** Attempt real-browser rendering (falls back to HTTP if Puppeteer absent). */
  renderJs: boolean;
  respectRobots: boolean;
  timeoutMs: number;
  /** Auth headers (incl. Cookie) sent on every request in an authed crawl. */
  authHeaders?: Record<string, string>;
  /** Extra URL substrings to never follow (logout-avoidance). */
  excludeUrlPatterns?: string[];
  log?: (msg: string) => void;
}

/**
 * URL substrings never crawled in an authenticated scan: following them would
 * destroy the very session we're testing with. Always applied on top of any
 * caller-supplied patterns.
 */
const DEFAULT_EXCLUDES = ['logout', 'signout', 'sign-out', 'log-out', 'deleteaccount', 'delete-account'];

/** True if `url` contains any exclude substring (case-insensitive). */
export function isExcluded(url: string, extra: string[] = []): boolean {
  const u = url.toLowerCase();
  return [...DEFAULT_EXCLUDES, ...extra.map((p) => p.toLowerCase())].some((p) => p && u.includes(p));
}

interface QueueItem {
  url: string;
  depth: number;
}

/** Raw extraction result from one page, engine-independent. */
interface PageExtract {
  links: string[];
  forms: Array<{ action: string; method: string; inputs: string[]; hasCsrfToken: boolean }>;
  xhr: string[];
  contentType?: string;
}

const CSRF_HINT = /csrf|xsrf|_token|authenticity_token|__requestverificationtoken/i;

/** Public entry point. Always resolves (never throws) — a failed crawl still
 *  yields a surface containing at least the seed. */
export async function crawlSurface(seed: URL, opts: CrawlOptions): Promise<AttackSurface> {
  const log = opts.log ?? (() => {});
  const scope = registrableDomain(seed.hostname);
  const excludes = opts.excludeUrlPatterns ?? [];
  const authHeaders = opts.authHeaders ?? {};

  const endpoints = new Map<string, Endpoint>();
  const forms: DiscoveredForm[] = [];
  const discoveredHosts = new Set<string>();
  const offScope = new Set<string>();

  // Seed is always endpoint #1.
  addEndpoint(endpoints, seed.toString(), 'GET', 'seed');
  discoveredHosts.add(seed.hostname);

  const disallow = opts.respectRobots ? await loadDisallow(seed, opts.timeoutMs).catch(() => []) : [];

  const seen = new Set<string>([patternKey(seed.toString())]);
  const queue: QueueItem[] = [{ url: seed.toString(), depth: 0 }];
  let crawled = 0;
  let truncated = false;

  // Try to bring up a browser once; fall back to HTTP for the whole crawl.
  const browser = opts.renderJs ? await launchBrowser().catch(() => null) : null;
  const renderedWithBrowser = Boolean(browser);
  if (opts.renderJs && !browser) log('Browser engine unavailable — crawling with HTTP fallback (no JS routes).');

  try {
    while (queue.length > 0) {
      if (crawled >= opts.maxPages) {
        truncated = true;
        break;
      }
      const item = queue.shift() as QueueItem;
      const current = new URL(item.url);

      // SSRF re-check on every fetch. Skip (do not throw) on block so one bad
      // link can't abort an otherwise-legitimate crawl.
      try {
        await assertPublicHost(current.hostname, opts.timeoutMs);
      } catch (err) {
        if (err instanceof BlockedTargetError) {
          offScope.add(current.toString());
          continue;
        }
        throw err;
      }

      if (opts.respectRobots && isDisallowed(current.pathname, disallow)) continue;

      const extract = browser
        ? await extractWithBrowser(browser, item.url, opts.timeoutMs, authHeaders).catch(() => null)
        : await extractWithHttp(item.url, opts.timeoutMs, authHeaders).catch(() => null);
      crawled++;
      if (!extract) continue;

      // Record forms (with absolute action URLs).
      for (const f of extract.forms) {
        const action = safeResolve(f.action, item.url) ?? item.url;
        forms.push({
          action,
          method: f.method === 'POST' ? 'POST' : 'GET',
          inputs: f.inputs.slice(0, 40),
          foundOn: item.url,
          hasCsrfToken: f.hasCsrfToken,
        });
        // A form is also an injectable endpoint.
        addEndpoint(endpoints, action, f.method === 'POST' ? 'POST' : 'GET', 'form', f.inputs);
      }

      // XHR/fetch targets are endpoints but not crawl frontier (usually data).
      for (const x of extract.xhr) {
        const abs = safeResolve(x, item.url);
        if (!abs) continue;
        const u = new URL(abs);
        if (registrableDomain(u.hostname) === scope) addEndpoint(endpoints, abs, 'GET', 'xhr');
      }

      // Links: record scope split, enqueue in-scope unseen ones.
      for (const href of extract.links) {
        const abs = safeResolve(href, item.url);
        if (!abs) continue;
        let u: URL;
        try {
          u = new URL(abs);
        } catch {
          continue;
        }
        if (u.protocol !== 'http:' && u.protocol !== 'https:') continue;

        if (registrableDomain(u.hostname) !== scope) {
          offScope.add(abs);
          continue;
        }
        // Logout-avoidance: never record or follow session-destroying URLs.
        if (isExcluded(abs, excludes)) continue;
        discoveredHosts.add(u.hostname);
        addEndpoint(endpoints, abs, 'GET', 'link');

        const key = patternKey(abs);
        if (!seen.has(key) && item.depth < opts.maxDepth) {
          seen.add(key);
          queue.push({ url: abs, depth: item.depth + 1 });
        }
      }
    }
  } finally {
    if (browser) await closeBrowser(browser);
  }

  log(`Crawl complete: ${crawled} page(s), ${endpoints.size} endpoint(s), ${forms.length} form(s).`);

  return {
    endpoints: [...endpoints.values()],
    forms,
    discoveredHosts: [...discoveredHosts],
    offScopeUrls: [...offScope].slice(0, 100),
    crawledCount: crawled,
    truncated,
    renderedWithBrowser,
  };
}

// ---------------------------------------------------------------------------
// Endpoint bookkeeping
// ---------------------------------------------------------------------------

/** Merge an endpoint into the map, unioning param names and preferring the
 *  more specific source. Keyed by method + pattern so `/p?id=1` and `/p?id=2`
 *  collapse but keep the union of their params. */
function addEndpoint(
  map: Map<string, Endpoint>,
  rawUrl: string,
  method: 'GET' | 'POST',
  source: Endpoint['source'],
  bodyParams: string[] = [],
): void {
  let u: URL;
  try {
    u = new URL(rawUrl);
  } catch {
    return;
  }
  const queryParams = [...u.searchParams.keys()];
  const params = unique([...queryParams, ...bodyParams]);
  const key = `${method} ${patternKey(rawUrl)}`;

  const existing = map.get(key);
  if (existing) {
    existing.params = unique([...existing.params, ...params]);
    // 'seed'/'form'/'xhr' are more informative than a plain 'link'.
    if (existing.source === 'link' && source !== 'link') existing.source = source;
    return;
  }
  map.set(key, { url: rawUrl, method, params, source });
}

/**
 * Collapse a URL to a dedup key: host + path with numeric / UUID / hex-ish
 * segments replaced by placeholders, plus the sorted set of query-param NAMES
 * (values ignored). Keeps `/user/1?tab=a` ≡ `/user/2?tab=b`.
 */
function patternKey(rawUrl: string): string {
  let u: URL;
  try {
    u = new URL(rawUrl);
  } catch {
    return rawUrl;
  }
  const path = u.pathname
    .split('/')
    .map((seg) => {
      if (/^\d+$/.test(seg)) return ':num';
      if (/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(seg)) return ':uuid';
      if (/^[0-9a-f]{12,}$/i.test(seg)) return ':hex';
      return seg;
    })
    .join('/');
  const paramNames = [...u.searchParams.keys()].sort().join(',');
  return `${u.host}${path}${paramNames ? `?${paramNames}` : ''}`;
}

// ---------------------------------------------------------------------------
// Scope
// ---------------------------------------------------------------------------

/**
 * Approximate registrable domain (eTLD+1) as the last two labels. This is a
 * deliberate simplification: multi-part public suffixes (e.g. `co.uk`) will
 * over-scope to the SLD. Good enough for scope-limiting a crawl without pulling
 * in a public-suffix-list dependency; documented so it can be upgraded later.
 */
function registrableDomain(hostname: string): string {
  const host = hostname.replace(/^\[|\]$/g, '').toLowerCase();
  if (require_isIp(host)) return host;
  const labels = host.split('.');
  if (labels.length <= 2) return host;
  return labels.slice(-2).join('.');
}

function require_isIp(host: string): boolean {
  return /^\d{1,3}(\.\d{1,3}){3}$/.test(host) || host.includes(':');
}

// ---------------------------------------------------------------------------
// robots.txt
// ---------------------------------------------------------------------------

async function loadDisallow(seed: URL, timeoutMs: number): Promise<string[]> {
  const res = await timedFetch(`${seed.origin}/robots.txt`, timeoutMs).catch(() => null);
  if (!res || res.status !== 200) return [];
  const text = await res.text().catch(() => '');
  // Honor the wildcard user-agent group only (simple, conservative).
  const lines = text.split(/\r?\n/);
  const rules: string[] = [];
  let active = false;
  for (const line of lines) {
    const ua = /^\s*User-agent:\s*(.+)$/i.exec(line);
    if (ua) {
      active = (ua[1] ?? '').trim() === '*';
      continue;
    }
    const dis = /^\s*Disallow:\s*(\S+)/i.exec(line);
    if (dis && active && dis[1]) rules.push(dis[1]);
  }
  return rules;
}

function isDisallowed(pathname: string, disallow: string[]): boolean {
  return disallow.some((rule) => rule !== '/' && pathname.startsWith(rule));
}

// ---------------------------------------------------------------------------
// HTTP fallback extraction
// ---------------------------------------------------------------------------

async function extractWithHttp(
  url: string,
  timeoutMs: number,
  authHeaders: Record<string, string> = {},
): Promise<PageExtract | null> {
  const res = await timedFetch(url, timeoutMs, { redirect: 'follow', headers: authHeaders }).catch(() => null);
  if (!res) return null;
  const contentType = res.headers.get('content-type') ?? undefined;
  if (contentType && !/text\/html|application\/xhtml/i.test(contentType)) {
    await res.arrayBuffer().catch(() => undefined);
    return { links: [], forms: [], xhr: [], contentType };
  }
  const html = await res.text().catch(() => '');
  return { ...extractFromHtml(html), contentType };
}

/** Regex extraction of links and forms from raw HTML (no JS). */
export function extractFromHtml(html: string): Omit<PageExtract, 'contentType'> {
  const links = [...html.matchAll(/<a\b[^>]*\bhref\s*=\s*["']([^"']+)["']/gi)]
    .map((m) => (m[1] ?? '').trim())
    .filter((h) => h && !h.startsWith('#') && !/^(javascript|mailto|tel):/i.test(h));

  const forms: PageExtract['forms'] = [];
  for (const fm of html.matchAll(/<form\b([^>]*)>([\s\S]*?)<\/form>/gi)) {
    const attrs = fm[1] ?? '';
    const inner = fm[2] ?? '';
    const action = /\baction\s*=\s*["']([^"']*)["']/i.exec(attrs)?.[1] ?? '';
    const method = (/\bmethod\s*=\s*["']([^"']*)["']/i.exec(attrs)?.[1] ?? 'GET').toUpperCase();
    const inputs: string[] = [];
    let hasCsrfToken = false;
    for (const inp of inner.matchAll(/<(?:input|select|textarea)\b[^>]*\bname\s*=\s*["']([^"']+)["'][^>]*>/gi)) {
      const name = inp[1] ?? '';
      if (name) inputs.push(name);
      if (CSRF_HINT.test(name)) hasCsrfToken = true;
    }
    forms.push({ action, method, inputs: unique(inputs), hasCsrfToken });
  }
  return { links: unique(links), forms, xhr: [] };
}

// ---------------------------------------------------------------------------
// Browser engine (optional Puppeteer)
// ---------------------------------------------------------------------------

async function launchBrowser(): Promise<any | null> {
  const specifier: string = 'puppeteer';
  let puppeteer: any;
  try {
    const mod: any = await import(specifier);
    puppeteer = mod.default ?? mod;
  } catch {
    return null;
  }
  try {
    return await puppeteer.launch({
      headless: true,
      args: ['--no-sandbox', '--disable-setuid-sandbox', '--disable-dev-shm-usage'],
    });
  } catch {
    return null;
  }
}

async function closeBrowser(browser: any): Promise<void> {
  try {
    await browser.close();
  } catch {
    /* ignore */
  }
}

async function extractWithBrowser(
  browser: any,
  url: string,
  timeoutMs: number,
  authHeaders: Record<string, string> = {},
): Promise<PageExtract | null> {
  const page = await browser.newPage();
  const xhr = new Set<string>();
  try {
    await page.setUserAgent(config.userAgent);
    if (Object.keys(authHeaders).length > 0) {
      // Sends Authorization/Cookie/etc. on every request the page makes.
      await page.setExtraHTTPHeaders(authHeaders).catch(() => {});
    }
    page.on('request', (req: any) => {
      try {
        const type = req.resourceType();
        if (type === 'xhr' || type === 'fetch') xhr.add(req.url());
      } catch {
        /* ignore */
      }
    });
    await page.goto(url, { waitUntil: 'networkidle2', timeout: timeoutMs });
    const dom = (await page.evaluate(EXTRACT_IN_PAGE)) as Omit<PageExtract, 'xhr' | 'contentType'>;
    return { links: dom.links, forms: dom.forms, xhr: [...xhr] };
  } catch {
    return null;
  } finally {
    try {
      await page.close();
    } catch {
      /* ignore */
    }
  }
}

/** Runs inside the page: pull links + forms from the live (post-JS) DOM. */
const EXTRACT_IN_PAGE = `(() => {
  const csrf = /csrf|xsrf|_token|authenticity_token|__requestverificationtoken/i;
  const links = Array.from(document.querySelectorAll('a[href]'))
    .map((a) => a.getAttribute('href') || '')
    .filter((h) => h && !h.startsWith('#') && !/^(javascript|mailto|tel):/i.test(h));
  const forms = Array.from(document.querySelectorAll('form')).map((f) => {
    const controls = Array.from(f.querySelectorAll('input[name],select[name],textarea[name]'));
    const inputs = controls.map((c) => c.getAttribute('name')).filter(Boolean);
    return {
      action: f.getAttribute('action') || '',
      method: (f.getAttribute('method') || 'GET').toUpperCase(),
      inputs,
      hasCsrfToken: inputs.some((n) => csrf.test(n)),
    };
  });
  return { links: Array.from(new Set(links)), forms };
})()`;

// ---------------------------------------------------------------------------
// small utils
// ---------------------------------------------------------------------------

function safeResolve(href: string, base: string): string | null {
  try {
    return new URL(href, base).toString();
  } catch {
    return null;
  }
}

function unique<T>(arr: T[]): T[] {
  return [...new Set(arr)];
}
