/**
 * Attack-surface module (passive).
 *
 * Triggers the shared crawl via `ctx.getSurface()` and turns the resulting map
 * into (a) a few passive findings — crawl coverage, forms missing CSRF tokens,
 * off-scope link leakage — and (b) structured `data` the report UI renders as a
 * site-map inspector. The heavy lifting lives in `browser/spider.ts`; this file
 * is the thin ScanModule adapter.
 *
 * This module is intentionally PASSIVE: it only fetches/renders pages the way a
 * search-engine crawler would. The endpoints it discovers become the seed list
 * for the Phase-B active DAST modules (ZAP/Nuclei), which stay authorization-
 * gated behind `mode: 'active'`.
 */

import { finding, pass } from '../core/finding.js';
import type { Finding, ModuleResult, ScanContext, ScanModule } from '../core/types.js';

const MODULE = 'spider';

export const spiderModule: ScanModule = {
  name: MODULE,
  title: 'Attack Surface Crawler',
  category: 'infrastructure',
  mode: 'passive',
  description:
    'Crawls the site (browser-rendered when available) to map endpoints, parameters, and forms — the injectable surface later checks build on.',
  async run(ctx: ScanContext): Promise<ModuleResult> {
    const t0 = performance.now();
    const findings: Finding[] = [];

    const surface = await ctx.getSurface();

    const formCount = surface.forms.length;
    const paramEndpoints = surface.endpoints.filter((e) => e.params.length > 0).length;

    // Coverage summary (always a pass — informational baseline).
    findings.push(
      pass(
        MODULE,
        'infrastructure',
        'spider.coverage',
        'Attack surface mapped',
        `Crawled ${surface.crawledCount} page(s): ${surface.endpoints.length} endpoint(s), ${paramEndpoints} with parameters, ${formCount} form(s).` +
          (surface.renderedWithBrowser ? ' Pages were browser-rendered.' : ' HTTP-only crawl (install Puppeteer for JS routes).'),
        {
          crawledCount: surface.crawledCount,
          endpointCount: surface.endpoints.length,
          formCount,
          truncated: surface.truncated,
        },
      ),
    );

    // Forms without an anti-CSRF token are a real security signal.
    const unprotected = surface.forms.filter((f) => f.method === 'POST' && !f.hasCsrfToken);
    if (unprotected.length > 0) {
      findings.push(
        finding({
          id: 'spider.forms.no-csrf-token',
          module: MODULE,
          category: 'security',
          title: `${unprotected.length} POST form(s) without a visible CSRF token`,
          severity: 'medium',
          status: 'warn',
          risk: 'State-changing forms without an anti-CSRF token may be forgeable by a malicious cross-origin page.',
          whyItMatters:
            'A POST form that changes state (login, settings, purchase) needs an unpredictable per-request token, or an attacker can trick a logged-in user into submitting it from another site (CSRF).',
          technical: `Forms with method=POST and no hidden token field matching /csrf|xsrf|_token/: ${unprotected
            .slice(0, 5)
            .map((f) => f.action)
            .join(', ')}${unprotected.length > 5 ? ' …' : ''}. Note: SameSite cookies or framework-level tokens set via headers are not visible to a passive crawl, so confirm before acting.`,
          businessImpact: 'Account takeover or unauthorized state changes performed as the victim.',
          probability: 'medium',
          owasp: ['A01:2021-Broken Access Control'],
          remediation:
            'Include a per-session/per-request CSRF token in state-changing forms and validate it server-side; set SameSite=Lax/Strict on session cookies as defense in depth.',
          estimatedFixTime: '2-4 hours',
          references: ['https://owasp.org/www-community/attacks/csrf'],
          evidence: { actions: unprotected.slice(0, 10).map((f) => f.action) },
        }),
      );
    } else if (formCount > 0) {
      findings.push(
        pass(
          MODULE,
          'security',
          'spider.forms.csrf-ok',
          'POST forms carry anti-CSRF tokens',
          `All ${formCount} discovered form(s) either use GET or include a token-looking hidden field.`,
        ),
      );
    }

    // Note (not a failure) when the crawl was capped — coverage is partial.
    if (surface.truncated) {
      findings.push(
        finding({
          id: 'spider.truncated',
          module: MODULE,
          category: 'infrastructure',
          title: 'Crawl reached its page/depth limit',
          severity: 'info',
          status: 'info',
          risk: 'Only part of the site was mapped, so later checks may miss some pages.',
          whyItMatters:
            'The crawler stopped at its configured page/depth cap. For a full audit of a large site, raise CRAWL_MAX_PAGES / CRAWL_MAX_DEPTH.',
          technical: `Crawl stopped after ${surface.crawledCount} pages (cap reached). Increase limits for deeper coverage.`,
          businessImpact: 'Reduced coverage on large sites; no direct risk.',
          probability: 'low',
          remediation: 'Increase CRAWL_MAX_PAGES and/or CRAWL_MAX_DEPTH if fuller coverage is required.',
          estimatedFixTime: '5 minutes',
          references: [],
        }),
      );
    }

    const data: Record<string, unknown> = {
      crawledCount: surface.crawledCount,
      truncated: surface.truncated,
      renderedWithBrowser: surface.renderedWithBrowser,
      discoveredHosts: surface.discoveredHosts,
      endpoints: surface.endpoints.slice(0, 200),
      forms: surface.forms.slice(0, 100),
      offScopeCount: surface.offScopeUrls.length,
    };

    return {
      module: MODULE,
      category: 'infrastructure',
      ok: true,
      findings,
      durationMs: Math.round(performance.now() - t0),
      data,
    };
  },
};
