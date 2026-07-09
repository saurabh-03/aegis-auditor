/**
 * Module 8 — Performance analysis (passive, HTML/resource-based).
 *
 * This computes real, measurable signals from the delivered HTML and response:
 * render-blocking resources, document weight, resource counts, TTFB, and
 * missing optimizations. It does NOT run a browser, so lab Core Web Vitals
 * (LCP/CLS/INP) require the headless-Chrome worker (see docs/MODULES.md); those
 * fields are surfaced there. This module focuses on what can be proven passively.
 *
 * TODO(aegis:cwv): add a headless-Chrome worker module (own package, own queue)
 * that produces real lab Core Web Vitals and a per-resource waterfall, then emit
 * that data for the (currently deliberately absent) waterfall inspector panel.
 */

import { finding, pass } from '../core/finding.js';
import type { Finding, ModuleResult, ScanContext, ScanModule } from '../core/types.js';

const MODULE = 'performance';

function count(re: RegExp, s: string): number {
  return (s.match(re) ?? []).length;
}

export const performanceModule: ScanModule = {
  name: MODULE,
  title: 'Performance Analysis',
  category: 'performance',
  mode: 'passive',
  description: 'Analyzes render-blocking resources, document weight, TTFB, and resource counts.',
  async run(ctx: ScanContext): Promise<ModuleResult> {
    const t0 = performance.now();
    const page = await ctx.getPage();
    const body = page.body;
    const findings: Finding[] = [];

    const docBytes = Buffer.byteLength(body, 'utf8');
    const scripts = count(/<script\b[^>]*\bsrc=/gi, body);
    const inlineScripts = count(/<script\b(?![^>]*\bsrc=)[^>]*>/gi, body);
    const stylesheets = count(/<link\b[^>]*rel=["']stylesheet["'][^>]*>/gi, body);
    // Render-blocking: stylesheets in <head> and synchronous head scripts (no async/defer/module).
    const head = /<head[\s\S]*?<\/head>/i.exec(body)?.[0] ?? '';
    const blockingScripts = count(/<script\b(?![^>]*\b(?:async|defer|type=["']module["']))[^>]*\bsrc=/gi, head);
    const blockingStyles = count(/<link\b[^>]*rel=["']stylesheet["']/gi, head);

    // 1) Document weight
    if (docBytes > 150_000) {
      findings.push(
        finding({
          id: 'perf.large-document',
          module: MODULE,
          category: 'performance',
          title: `Large HTML document (${Math.round(docBytes / 1024)} KB)`,
          severity: docBytes > 400_000 ? 'medium' : 'low',
          status: docBytes > 400_000 ? 'fail' : 'warn',
          risk: 'A heavy HTML payload delays first paint and Time to Interactive, especially on mobile.',
          whyItMatters:
            'Large documents take longer to download and parse before anything renders. Often this is server-rendered data or inlined markup that could be streamed, paginated, or code-split.',
          technical: `The delivered HTML is ${Math.round(docBytes / 1024)} KB (uncompressed). Investigate inlined data, oversized markup, and opportunities to stream or lazy-load below-the-fold content.`,
          businessImpact: 'Slower loads, worse Core Web Vitals (LCP), and measurable conversion loss on slow connections.',
          probability: 'medium',
          remediation: 'Reduce inlined data, paginate/stream content, and code-split. Ensure compression is enabled.',
          estimatedFixTime: '0.5-2 days',
          references: ['https://web.dev/articles/lcp'],
          evidence: { docBytes },
        }),
      );
    }

    // 2) Render-blocking resources
    if (blockingScripts + blockingStyles > 3) {
      findings.push(
        finding({
          id: 'perf.render-blocking',
          module: MODULE,
          category: 'performance',
          title: `${blockingScripts + blockingStyles} render-blocking resources in <head>`,
          severity: 'medium',
          status: 'fail',
          risk: 'Render-blocking scripts and stylesheets delay first paint until they download and execute.',
          whyItMatters:
            `Found ${blockingStyles} blocking stylesheet(s) and ${blockingScripts} synchronous head script(s). The browser cannot paint until these resolve, directly hurting First Contentful Paint and LCP.`,
          technical:
            'Add async/defer (or type="module") to non-critical scripts, inline critical CSS and load the rest with media/onload tricks, and move scripts to the end of <body> where possible.',
          businessImpact: 'Slower perceived load, higher bounce, weaker SEO (Core Web Vitals ranking signal).',
          probability: 'high',
          remediation: 'Defer non-critical JS, inline critical CSS, and lazy-load the rest.',
          estimatedFixTime: '0.5-1 day',
          exampleCode: '<script src="/app.js" defer></script>\n<link rel="preload" href="/critical.css" as="style" onload="this.rel=\'stylesheet\'">',
          references: ['https://web.dev/articles/render-blocking-resources'],
          evidence: { blockingScripts, blockingStyles },
        }),
      );
    } else {
      findings.push(pass(MODULE, 'performance', 'perf.render-blocking.ok', 'Few render-blocking resources', `${blockingScripts} blocking head scripts, ${blockingStyles} head stylesheets.`, { blockingScripts, blockingStyles }));
    }

    // 3) Excessive resource requests
    const totalRefs = scripts + stylesheets + count(/<img\b/gi, body);
    if (totalRefs > 60) {
      findings.push(
        finding({
          id: 'perf.many-requests',
          module: MODULE,
          category: 'performance',
          title: `High number of resource references (~${totalRefs})`,
          severity: 'low',
          status: 'warn',
          risk: 'Many separate requests add connection and scheduling overhead.',
          whyItMatters: `The homepage references roughly ${totalRefs} scripts/styles/images. Even over HTTP/2, high request counts add overhead and contention.`,
          technical: 'Bundle/split intelligently, defer offscreen images, and audit third-party tags. Consider HTTP/2/3 and preconnect for critical origins.',
          businessImpact: 'Slower loads and more third-party risk.',
          probability: 'medium',
          remediation: 'Reduce and defer non-critical requests; consolidate third-party scripts.',
          estimatedFixTime: '0.5-2 days',
          references: ['https://web.dev/articles/fewer-requests'],
          evidence: { scripts, stylesheets, totalRefs },
        }),
      );
    }

    // 4) Preconnect/preload hints for cross-origin resources
    const selfHost = (() => {
      try {
        return new URL(page.finalUrl).host;
      } catch {
        return '';
      }
    })();
    const externalHosts = [...body.matchAll(/(?:src|href)=["']https?:\/\/([a-z0-9.-]+)/gi)]
      .map((m) => m[1])
      .filter((h): h is string => Boolean(h) && h !== selfHost);
    const usesThirdParty = externalHosts.length > 0;
    const hasPreconnect = /<link\b[^>]*rel=["']preconnect["']/i.test(body);
    if (usesThirdParty && !hasPreconnect) {
      findings.push(
        finding({
          id: 'perf.no-preconnect',
          module: MODULE,
          category: 'performance',
          title: 'Cross-origin resources without preconnect hints',
          severity: 'low',
          status: 'warn',
          risk: 'Each new cross-origin connection pays DNS + TCP + TLS latency on the critical path.',
          whyItMatters: 'The page loads scripts/styles from third-party origins but declares no <link rel="preconnect">. Preconnecting warms the connection before the resource is needed.',
          technical: 'Add rel="preconnect" (and dns-prefetch fallback) for critical third-party origins such as font, CDN, and analytics hosts.',
          businessImpact: 'Small but real latency win on first load.',
          probability: 'low',
          remediation: 'Add preconnect hints for critical cross-origin hosts.',
          estimatedFixTime: '30 minutes',
          exampleCode: '<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>\n<link rel="dns-prefetch" href="https://fonts.gstatic.com">',
          references: ['https://web.dev/articles/preconnect-and-dns-prefetch'],
        }),
      );
    }

    // 5) TTFB (from the shared page latency)
    if (page.latencyMs > 600) {
      findings.push(
        finding({
          id: 'perf.slow-ttfb',
          module: MODULE,
          category: 'performance',
          title: `Slow Time to First Byte (~${page.latencyMs} ms)`,
          severity: page.latencyMs > 1200 ? 'medium' : 'low',
          status: page.latencyMs > 1200 ? 'fail' : 'warn',
          risk: 'A slow server response delays everything downstream — nothing can render until the first byte arrives.',
          whyItMatters: `The document TTFB was about ${page.latencyMs} ms. High TTFB usually means slow origin compute, missing caching, or no edge/CDN.`,
          technical: 'Add edge caching/CDN, cache expensive origin work, optimize database queries, and enable keep-alive/HTTP/2.',
          businessImpact: 'Directly worsens LCP and conversion; a Core Web Vitals ranking factor.',
          probability: 'high',
          remediation: 'Introduce caching/CDN and profile slow origin paths.',
          estimatedFixTime: '1-5 days',
          references: ['https://web.dev/articles/ttfb'],
          evidence: { ttfbMs: page.latencyMs },
        }),
      );
    } else {
      findings.push(pass(MODULE, 'performance', 'perf.ttfb.ok', `Healthy TTFB (~${page.latencyMs} ms)`, 'The server responded promptly.', { ttfbMs: page.latencyMs }));
    }

    return {
      module: MODULE,
      category: 'performance',
      ok: true,
      findings,
      durationMs: Math.round(performance.now() - t0),
      data: { docBytes, scripts, inlineScripts, stylesheets, blockingScripts, blockingStyles, ttfbMs: page.latencyMs },
    };
  },
};
