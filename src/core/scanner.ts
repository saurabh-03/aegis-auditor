/**
 * Scan orchestrator.
 *
 * Responsibilities:
 *  - Build a shared {@link ScanContext} (single cached homepage fetch).
 *  - Select eligible modules, enforcing the passive/active authorization gate.
 *  - Run modules with isolation (one module's failure never aborts the scan).
 *  - Aggregate findings, compute scores, and assemble the {@link AuditReport}.
 */

import { ENGINE_VERSION, config } from './config.js';
import { fetchPage, timedFetch } from './http.js';
import { crawlSurface } from '../modules/browser/spider.js';
import { scoreAll, sortFindings } from './scoring.js';
import { assertPublicHost } from './ssrf.js';
import type {
  AttackSurface,
  AuditReport,
  ModuleResult,
  PageSnapshot,
  ScanContext,
  ScanModule,
  ScanOptions,
} from './types.js';

export interface ScanEvents {
  onModuleStart?: (module: ScanModule) => void;
  onModuleFinish?: (result: ModuleResult) => void;
  /** Intra-module progress for long-running modules; fraction is 0..1. */
  onModuleProgress?: (module: ScanModule, fraction: number, note?: string) => void;
  onLog?: (msg: string) => void;
}

function selectModules(
  all: ScanModule[],
  options: ScanOptions,
): { eligible: ScanModule[]; skippedActive: ScanModule[] } {
  const only = options.only?.length ? new Set(options.only) : null;
  const skip = new Set(options.skip ?? []);
  const skippedActive: ScanModule[] = [];

  const eligible = all.filter((m) => {
    if (only && !only.has(m.name)) return false;
    if (skip.has(m.name)) return false;
    if (m.mode === 'active') {
      // Active modules require BOTH explicit authorization and opt-in.
      if (!options.authorized || !options.includeActive) {
        skippedActive.push(m);
        return false;
      }
    }
    return true;
  });

  return { eligible, skippedActive };
}

export async function runScan(
  target: URL,
  modules: ScanModule[],
  options: ScanOptions,
  events: ScanEvents = {},
): Promise<AuditReport> {
  const startedAt = Date.now();
  const timeoutMs = options.timeoutMs ?? config.defaultTimeoutMs;
  const log = (msg: string) => events.onLog?.(msg);

  // SSRF guard: never let a scan reach private/internal/metadata addresses.
  await assertPublicHost(target.hostname, timeoutMs);

  // Single homepage fetch shared across modules.
  let pagePromise: Promise<PageSnapshot> | null = null;
  const getPage = () => {
    if (!pagePromise) {
      log(`Fetching ${target.toString()} …`);
      pagePromise = fetchPage(target.toString(), timeoutMs);
    }
    return pagePromise;
  };

  // Single attack-surface crawl shared across modules (built on first request).
  let surfacePromise: Promise<AttackSurface> | null = null;
  const getSurface = () => {
    if (!surfacePromise) {
      log(`Crawling ${target.toString()} …`);
      surfacePromise = crawlSurface(target, {
        maxPages: config.crawl.maxPages,
        maxDepth: config.crawl.maxDepth,
        renderJs: config.crawl.renderJs,
        respectRobots: config.crawl.respectRobots,
        timeoutMs,
        log,
      });
    }
    return surfacePromise;
  };

  const ctx: ScanContext = {
    target,
    now: new Date(),
    options: { ...options, authorized: options.authorized, timeoutMs },
    log,
    // Base no-op; each module gets a progress fn bound to its own name below.
    progress: () => {},
    getPage,
    getSurface,
    fetch: (url, init) => timedFetch(url, timeoutMs, init),
  };

  const { eligible, skippedActive } = selectModules(modules, options);
  for (const m of skippedActive) {
    log(`Skipping active module "${m.name}" (authorization/opt-in not granted).`);
  }

  // Run modules concurrently but isolated.
  const results = await Promise.all(
    eligible.map(async (m): Promise<ModuleResult> => {
      events.onModuleStart?.(m);
      const t0 = performance.now();
      // Per-module context: progress is bound to this module's name. Everything
      // else (getPage/getSurface/fetch) is shared via the base ctx closures.
      const mctx: ScanContext = {
        ...ctx,
        progress: (fraction, note) => {
          const clamped = Math.max(0, Math.min(1, Number.isFinite(fraction) ? fraction : 0));
          events.onModuleProgress?.(m, clamped, note);
        },
      };
      try {
        const r = await m.run(mctx);
        events.onModuleFinish?.(r);
        return r;
      } catch (err) {
        const result: ModuleResult = {
          module: m.name,
          category: m.category,
          ok: false,
          error: err instanceof Error ? err.message : String(err),
          findings: [],
          durationMs: Math.round(performance.now() - t0),
        };
        events.onModuleFinish?.(result);
        return result;
      }
    }),
  );

  const findings = sortFindings(results.flatMap((r) => r.findings));
  const { categories, overall } = scoreAll(findings);

  const data: Record<string, Record<string, unknown> | undefined> = {};
  for (const r of results) if (r.data) data[r.module] = r.data;

  const report: AuditReport = {
    target: target.toString(),
    scannedAt: new Date(startedAt).toISOString(),
    durationMs: Date.now() - startedAt,
    authorized: Boolean(options.authorized && options.includeActive),
    overall,
    categories,
    findings,
    modules: results.map((r) => ({
      module: r.module,
      category: r.category,
      ok: r.ok,
      ...(r.error ? { error: r.error } : {}),
      durationMs: r.durationMs,
    })),
    data,
    meta: {
      engineVersion: ENGINE_VERSION,
      passiveOnly: !(options.authorized && options.includeActive),
    },
  };

  return report;
}
