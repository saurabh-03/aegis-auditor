/**
 * Modules 20 & 21 — Infrastructure & Scalability assessment.
 *
 * This is an *architectural* assessment based on observable delivery signals
 * (CDN, caching, compression, connection reuse, response-time consistency).
 * It is explicitly NOT a load-capacity measurement.
 */

import { finding, pass } from '../core/finding.js';
import type { Finding, ModuleResult, ScanContext, ScanModule } from '../core/types.js';

const MODULE = 'scalability';

const CDN_HEADER_HINTS: Array<[string, RegExp]> = [
  ['server', /cloudflare|cloudfront|fastly|akamai|vercel|netlify/i],
  ['x-cache', /.+/i],
  ['cf-cache-status', /.+/i],
  ['x-served-by', /.+/i],
  ['x-amz-cf-id', /.+/i],
];

export const scalabilityModule: ScanModule = {
  name: MODULE,
  title: 'Scalability Assessment',
  category: 'scalability',
  mode: 'passive',
  description: 'Estimates scaling readiness from CDN, caching, compression, and latency consistency.',
  async run(ctx: ScanContext): Promise<ModuleResult> {
    const t0 = performance.now();
    const page = await ctx.getPage();
    const h = page.headers;
    const findings: Finding[] = [];

    // CDN presence
    const cdnHit = CDN_HEADER_HINTS.find(([name, re]) => re.test(h[name] ?? ''));
    if (!cdnHit) {
      findings.push(
        finding({
          id: 'scale.no-cdn',
          module: MODULE,
          category: 'scalability',
          title: 'No CDN detected',
          severity: 'medium',
          status: 'fail',
          risk: 'Serving directly from origin limits geographic reach and absorbs all traffic spikes at the origin.',
          whyItMatters: 'A CDN caches and serves content from edge locations near users, cutting latency and shielding the origin from load spikes and some DDoS traffic.',
          technical: 'No CDN/edge-cache signature was found in response headers. Front the site with a CDN and cache static assets aggressively.',
          businessImpact: 'Higher latency for distant users, poorer resilience under load, and greater origin cost.',
          probability: 'high',
          remediation: 'Adopt a CDN (Cloudflare, CloudFront, Fastly, etc.) and cache static assets at the edge.',
          estimatedFixTime: '0.5-2 days',
          references: ['https://web.dev/articles/content-delivery-networks'],
        }),
      );
    } else {
      findings.push(pass(MODULE, 'scalability', 'scale.cdn.ok', 'CDN/edge caching detected', `Signature via "${cdnHit[0]}" header.`, { header: cdnHit[0], value: h[cdnHit[0]] }));
    }

    // Connection reuse / keep-alive
    const connection = (h['connection'] ?? '').toLowerCase();
    if (connection === 'close') {
      findings.push(
        finding({
          id: 'scale.no-keepalive',
          module: MODULE,
          category: 'scalability',
          title: 'Connection: close (no keep-alive)',
          severity: 'low',
          status: 'warn',
          risk: 'Forcing new TCP/TLS connections per request wastes CPU and adds latency at scale.',
          whyItMatters: 'Keep-alive / connection reuse amortizes the expensive TLS handshake across many requests, improving throughput under load.',
          technical: 'The origin returned Connection: close. Enable HTTP keep-alive (and prefer HTTP/2+ which multiplexes over one connection).',
          businessImpact: 'Lower throughput and higher latency as traffic grows.',
          probability: 'medium',
          remediation: 'Enable keep-alive and HTTP/2/3.',
          estimatedFixTime: '1-2 hours',
          references: ['https://developer.mozilla.org/docs/Web/HTTP/Connection_management_in_HTTP_1.x'],
        }),
      );
    }

    // Latency consistency probe (3 lightweight HEAD-ish GETs).
    const samples: number[] = [page.latencyMs];
    for (let i = 0; i < 2; i++) {
      const s = performance.now();
      const r = await ctx.fetch(ctx.target.toString(), { method: 'GET' }).catch(() => null);
      if (r) {
        await r.arrayBuffer().catch(() => undefined);
        samples.push(Math.round(performance.now() - s));
      }
    }
    const avg = Math.round(samples.reduce((a, b) => a + b, 0) / samples.length);
    const spread = Math.max(...samples) - Math.min(...samples);

    if (avg > 800) {
      findings.push(
        finding({
          id: 'scale.slow-ttfb',
          module: MODULE,
          category: 'performance',
          title: `High response latency (~${avg}ms average)`,
          severity: 'medium',
          status: 'fail',
          risk: 'Slow server responses degrade user experience and Core Web Vitals.',
          whyItMatters: 'A high average response time suggests limited server capacity, no edge caching, or heavy origin work per request — all of which worsen under load.',
          technical: `Sampled latencies: ${samples.join(', ')}ms (avg ${avg}ms). Investigate origin compute, database queries, and caching.`,
          businessImpact: 'Lower conversion, worse SEO, and reduced headroom for traffic growth.',
          probability: 'high',
          remediation: 'Add caching, optimize origin work, and use a CDN. Profile slow endpoints.',
          estimatedFixTime: '1-5 days',
          references: ['https://web.dev/articles/ttfb'],
          evidence: { samples, avg },
        }),
      );
    } else {
      findings.push(pass(MODULE, 'performance', 'scale.ttfb.ok', `Response latency healthy (~${avg}ms)`, `Samples: ${samples.join(', ')}ms.`, { samples, avg }));
    }

    if (spread > 600) {
      findings.push(
        finding({
          id: 'scale.latency-variance',
          module: MODULE,
          category: 'scalability',
          title: `Inconsistent response times (±${spread}ms spread)`,
          severity: 'low',
          status: 'warn',
          risk: 'High variance suggests cold caches, autoscaling churn, or contended resources.',
          whyItMatters: 'Inconsistent latency often points to missing warm caches or under-provisioned capacity that will worsen during traffic spikes.',
          technical: `Latency spread across samples was ${spread}ms (${samples.join(', ')}ms). Investigate cache-hit ratios and capacity headroom.`,
          businessImpact: 'Unpredictable UX and risk of tail-latency spikes under load.',
          probability: 'medium',
          remediation: 'Improve cache-hit ratios, pre-warm caches, and validate autoscaling policies.',
          estimatedFixTime: '1-3 days',
          references: ['https://web.dev/articles/ttfb'],
          evidence: { samples, spread },
        }),
      );
    }

    return {
      module: MODULE,
      category: 'scalability',
      ok: true,
      findings,
      durationMs: Math.round(performance.now() - t0),
      data: { cdn: cdnHit?.[0] ?? null, connection, samples, avgLatencyMs: avg, spreadMs: spread },
    };
  },
};
