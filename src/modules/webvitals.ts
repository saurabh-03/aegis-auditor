/**
 * Module 8b — Lab Core Web Vitals (headless browser).
 *
 * Complements the passive `performance` module with real, measured LCP / CLS /
 * TBT / FCP from a headless Chromium run, plus a per-resource waterfall. Opt-in:
 * requires Puppeteer (`npm install puppeteer`). Without it, this module emits a
 * single info finding explaining how to enable lab metrics and contributes
 * nothing to the score.
 */

import { config } from '../core/config.js';
import { finding, pass } from '../core/finding.js';
import type { Finding, FindingStatus, ModuleResult, ScanContext, ScanModule } from '../core/types.js';
import { measureLabMetrics } from './browser/measure.js';

const MODULE = 'webvitals';

type Band = 'good' | 'ni' | 'poor';
function band(value: number, good: number, poor: number): Band {
  return value < good ? 'good' : value < poor ? 'ni' : 'poor';
}
const STATUS: Record<Band, FindingStatus> = { good: 'pass', ni: 'warn', poor: 'fail' };
const SEVERITY: Record<Band, Finding['severity']> = { good: 'info', ni: 'low', poor: 'medium' };

interface MetricSpec {
  id: string;
  name: string;
  good: number;
  poor: number;
  unit: 's' | 'ms' | '';
  whyItMatters: string;
  remediation: string;
  reference: string;
}

const SPECS: Record<'lcp' | 'cls' | 'tbt' | 'fcp', MetricSpec> = {
  lcp: {
    id: 'webvitals.lcp',
    name: 'Largest Contentful Paint',
    good: 2500,
    poor: 4000,
    unit: 's',
    whyItMatters:
      'LCP marks when the main content becomes visible. Slow LCP means users stare at a blank or half-loaded page and are more likely to leave.',
    remediation:
      'Optimize the LCP element: preload the hero image/font, serve modern formats, remove render-blocking CSS/JS, and improve server/edge response time.',
    reference: 'https://web.dev/articles/lcp',
  },
  cls: {
    id: 'webvitals.cls',
    name: 'Cumulative Layout Shift',
    good: 0.1,
    poor: 0.25,
    unit: '',
    whyItMatters:
      'CLS measures unexpected layout movement. High CLS makes users tap the wrong thing and feels broken and untrustworthy.',
    remediation:
      'Set explicit width/height (or aspect-ratio) on images and embeds, reserve space for ads/banners, and avoid inserting content above existing content.',
    reference: 'https://web.dev/articles/cls',
  },
  tbt: {
    id: 'webvitals.tbt',
    name: 'Total Blocking Time',
    good: 200,
    poor: 600,
    unit: 'ms',
    whyItMatters:
      'TBT sums the time the main thread was blocked by long tasks — the lab proxy for INP/responsiveness. High TBT means taps and clicks feel laggy.',
    remediation:
      'Break up long JavaScript tasks, code-split and defer non-critical JS, remove unused scripts, and move heavy work off the main thread (web workers).',
    reference: 'https://web.dev/articles/tbt',
  },
  fcp: {
    id: 'webvitals.fcp',
    name: 'First Contentful Paint',
    good: 1800,
    poor: 3000,
    unit: 'ms',
    whyItMatters:
      'FCP is when the first content appears — the first signal to the user that the page is working.',
    remediation:
      'Reduce render-blocking resources, improve TTFB with caching/CDN, and inline critical CSS.',
    reference: 'https://web.dev/articles/fcp',
  },
};

function fmt(value: number, unit: MetricSpec['unit']): string {
  if (unit === 's') return `${(value / 1000).toFixed(2)} s`;
  if (unit === 'ms') return `${Math.round(value)} ms`;
  return value.toFixed(3);
}

function metricFinding(spec: MetricSpec, value: number): Finding {
  const b = band(value, spec.good, spec.poor);
  if (b === 'good') {
    return pass(MODULE, 'performance', `${spec.id}.ok`, `${spec.name} is good (${fmt(value, spec.unit)})`, spec.whyItMatters, {
      value,
    });
  }
  const goodStr = fmt(spec.good, spec.unit);
  return finding({
    id: spec.id,
    module: MODULE,
    category: 'performance',
    title: `${spec.name} ${b === 'poor' ? 'is poor' : 'needs improvement'} (${fmt(value, spec.unit)})`,
    severity: SEVERITY[b],
    status: STATUS[b],
    risk: 'Degraded loading/interactivity experience that hurts engagement, conversion, and SEO.',
    whyItMatters: spec.whyItMatters,
    technical: `Measured ${spec.name} was ${fmt(value, spec.unit)} in a headless ${config.browser.formFactor} run. "Good" is below ${goodStr}; "poor" is at or above ${fmt(spec.poor, spec.unit)}.`,
    businessImpact:
      'Core Web Vitals are a Google ranking signal and correlate with bounce rate. Poor scores cost organic traffic and conversions.',
    probability: 'high',
    remediation: spec.remediation,
    estimatedFixTime: b === 'poor' ? '1-5 days' : '0.5-2 days',
    references: [spec.reference, 'https://web.dev/articles/vitals'],
    evidence: { value, good: spec.good, poor: spec.poor },
  });
}

export const webVitalsModule: ScanModule = {
  name: MODULE,
  title: 'Core Web Vitals (lab)',
  category: 'performance',
  mode: 'passive',
  description: 'Measures real lab LCP/CLS/TBT/FCP and a resource waterfall using a headless browser (opt-in).',
  async run(ctx: ScanContext): Promise<ModuleResult> {
    const t0 = performance.now();

    if (!config.browser.enabled) {
      return {
        module: MODULE,
        category: 'performance',
        ok: true,
        durationMs: Math.round(performance.now() - t0),
        findings: [pass(MODULE, 'performance', 'webvitals.disabled', 'Lab metrics disabled', 'Browser metrics are turned off (BROWSER_METRICS=off).')],
      };
    }

    // In a split deployment (AEGIS_ROLE=api) the browser run belongs on the
    // worker node, not the API process. The synchronous /api/scan path runs
    // inline in the API and defers lab metrics; async scans process on workers
    // (AEGIS_ROLE unset or "worker") where the browser launch is appropriate.
    if (process.env.AEGIS_ROLE === 'api') {
      return {
        module: MODULE,
        category: 'performance',
        ok: true,
        durationMs: Math.round(performance.now() - t0),
        findings: [pass(MODULE, 'performance', 'webvitals.deferred', 'Lab metrics run on the worker', 'This API node defers the headless-browser run to the scan worker (AEGIS_ROLE=worker); async scans include lab Core Web Vitals.')],
      };
    }

    const metrics = await measureLabMetrics(ctx.target.toString());

    if (!metrics) {
      return {
        module: MODULE,
        category: 'performance',
        ok: true,
        durationMs: Math.round(performance.now() - t0),
        findings: [
          finding({
            id: 'webvitals.unavailable',
            module: MODULE,
            category: 'performance',
            title: 'Lab Core Web Vitals not collected',
            severity: 'info',
            status: 'info',
            risk: 'Without a browser run, LCP/CLS/INP are estimated from HTML heuristics only (see the Performance module).',
            whyItMatters:
              'Field-accurate Core Web Vitals require actually rendering the page. This module needs a headless browser, which is an optional dependency.',
            technical:
              'Puppeteer/Chromium was not available (or the run timed out). Install it to enable lab metrics: `npm install puppeteer`. Then re-run the scan. Control it with BROWSER_METRICS / BROWSER_FORM_FACTOR / BROWSER_TIMEOUT_MS.',
            businessImpact: 'Performance reporting is heuristic-only until lab metrics are enabled.',
            probability: 'low',
            remediation: 'Run `npm install puppeteer` on the scanning host, then re-scan.',
            estimatedFixTime: '10 minutes',
            references: ['https://pptr.dev/', 'https://web.dev/articles/vitals'],
          }),
        ],
      };
    }

    const findings: Finding[] = [
      metricFinding(SPECS.lcp, metrics.lcp),
      metricFinding(SPECS.cls, metrics.cls),
      metricFinding(SPECS.tbt, metrics.tbt),
      metricFinding(SPECS.fcp, metrics.fcp),
    ];

    return {
      module: MODULE,
      category: 'performance',
      ok: true,
      findings,
      durationMs: Math.round(performance.now() - t0),
      data: {
        formFactor: config.browser.formFactor,
        lcp: metrics.lcp,
        cls: metrics.cls,
        fcp: metrics.fcp,
        tbt: metrics.tbt,
        ttfb: metrics.ttfb,
        load: metrics.load,
        resources: metrics.resources,
      },
    };
  },
};
