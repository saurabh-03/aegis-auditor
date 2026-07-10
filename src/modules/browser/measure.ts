/**
 * Headless-browser lab metrics via Puppeteer (optional dependency).
 *
 * Puppeteer is imported dynamically through a string specifier so the project
 * typechecks and installs WITHOUT it — enabling browser metrics is opt-in
 * (`npm install puppeteer`). Every failure path (not installed, no Chromium,
 * launch/navigation error) returns null, so a scan degrades gracefully to an
 * info finding rather than failing.
 *
 * Metrics collected are real lab measurements:
 *   - LCP  (Largest Contentful Paint)   via PerformanceObserver
 *   - CLS  (Cumulative Layout Shift)     summed non-input layout shifts
 *   - FCP  (First Contentful Paint)      paint timing
 *   - TBT  (Total Blocking Time)         long-task blocking beyond 50ms — the
 *          lab-side proxy for interactivity/INP (same approach Lighthouse uses)
 *   - TTFB (navigation responseStart)
 *   - a per-resource waterfall from the Resource Timing API
 */

import { config } from '../../core/config.js';

export interface ResourceTiming {
  name: string;
  type: string;
  start: number;
  duration: number;
  size: number;
}

export interface LabMetrics {
  lcp: number; // ms
  cls: number; // unitless
  fcp: number; // ms
  tbt: number; // ms
  ttfb: number; // ms
  load: number; // ms
  resources: ResourceTiming[];
}

/** Injected before any page script runs; wires up the observers. */
const OBSERVER_SETUP = `
(() => {
  const v = { lcp: 0, cls: 0, fcp: 0, tbt: 0 };
  window.__aegisVitals = v;
  const obs = (type, cb) => { try { new PerformanceObserver(cb).observe({ type, buffered: true }); } catch (e) {} };
  obs('largest-contentful-paint', (l) => { const es = l.getEntries(); const last = es[es.length - 1]; if (last) v.lcp = last.startTime; });
  obs('layout-shift', (l) => { for (const e of l.getEntries()) { if (!e.hadRecentInput) v.cls += e.value; } });
  obs('paint', (l) => { for (const e of l.getEntries()) { if (e.name === 'first-contentful-paint') v.fcp = e.startTime; } });
  obs('longtask', (l) => { for (const e of l.getEntries()) { v.tbt += Math.max(0, e.duration - 50); } });
})();
`;

/** Read collected metrics + resource timings out of the page. */
const READ_METRICS = `
(() => {
  const v = window.__aegisVitals || { lcp: 0, cls: 0, fcp: 0, tbt: 0 };
  const nav = performance.getEntriesByType('navigation')[0];
  const resources = performance.getEntriesByType('resource').map((r) => ({
    name: r.name,
    type: r.initiatorType || 'other',
    start: Math.round(r.startTime),
    duration: Math.round(r.duration),
    size: Math.round(r.transferSize || 0),
  }));
  return {
    lcp: Math.round(v.lcp),
    cls: Math.round(v.cls * 1000) / 1000,
    fcp: Math.round(v.fcp),
    tbt: Math.round(v.tbt),
    ttfb: nav ? Math.round(nav.responseStart) : 0,
    load: nav ? Math.round(nav.loadEventEnd) : 0,
    resources,
  };
})();
`;

/** Returns lab metrics, or null if the browser path is unavailable/failed. */
export async function measureLabMetrics(url: string): Promise<LabMetrics | null> {
  // String-typed specifier prevents TS from resolving the optional module.
  const specifier: string = 'puppeteer';
  let puppeteer: any;
  try {
    const mod: any = await import(specifier);
    puppeteer = mod.default ?? mod;
  } catch {
    return null; // Puppeteer not installed — feature is opt-in.
  }

  let browser: any;
  try {
    browser = await puppeteer.launch({
      headless: true,
      args: ['--no-sandbox', '--disable-setuid-sandbox', '--disable-dev-shm-usage'],
    });
  } catch {
    return null; // No Chromium available / launch failed.
  }

  try {
    const page = await browser.newPage();
    if (config.browser.formFactor === 'mobile') {
      await page.setViewport({ width: 390, height: 844, isMobile: true, deviceScaleFactor: 2 });
    } else {
      await page.setViewport({ width: 1366, height: 768, deviceScaleFactor: 1 });
    }
    await page.setUserAgent(config.userAgent);
    await page.evaluateOnNewDocument(OBSERVER_SETUP);
    await page.goto(url, { waitUntil: 'networkidle2', timeout: config.browser.timeoutMs });
    // Let late LCP candidates and layout shifts settle.
    await new Promise((r) => setTimeout(r, 1200));
    const metrics = (await page.evaluate(READ_METRICS)) as LabMetrics;
    // Keep the waterfall bounded: earliest 60 resources by start time.
    metrics.resources = (metrics.resources || []).sort((a, b) => a.start - b.start).slice(0, 60);
    return metrics;
  } catch {
    return null; // Navigation timeout or eval error.
  } finally {
    try {
      await browser.close();
    } catch {
      /* ignore */
    }
  }
}
