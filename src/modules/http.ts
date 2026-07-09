/** Module 7 — HTTP delivery analysis (compression, caching, redirects, encoding). */

import { finding, pass } from '../core/finding.js';
import type { Finding, ModuleResult, ScanContext, ScanModule } from '../core/types.js';

const MODULE = 'http';

export const httpModule: ScanModule = {
  name: MODULE,
  title: 'HTTP Analysis',
  category: 'performance',
  mode: 'passive',
  description: 'Checks compression, caching, redirects, ETag, and content encoding.',
  async run(ctx: ScanContext): Promise<ModuleResult> {
    const t0 = performance.now();
    const page = await ctx.getPage();
    const h = page.headers;
    const findings: Finding[] = [];

    // Compression
    const encoding = h['content-encoding'];
    const isHtml = (h['content-type'] ?? '').includes('text/html');
    if (isHtml && !encoding) {
      findings.push(
        finding({
          id: 'http.no-compression',
          module: MODULE,
          category: 'performance',
          title: 'Text response served without compression',
          severity: 'medium',
          status: 'fail',
          risk: 'Uncompressed HTML/CSS/JS inflates transfer size and slows first paint.',
          whyItMatters:
            'Compression (Brotli/Gzip) typically shrinks text assets by 70-85%. Skipping it wastes bandwidth and directly worsens load time, especially on mobile.',
          technical: 'No Content-Encoding header was returned for a text/html response. Enable Brotli (preferred) with Gzip fallback at the origin or CDN.',
          businessImpact: 'Higher bounce rates, worse Core Web Vitals, higher bandwidth cost, lower SEO ranking.',
          probability: 'high',
          remediation: 'Enable Brotli/Gzip for text MIME types.',
          estimatedFixTime: '30 minutes',
          exampleCode: '# nginx\nbrotli on;\nbrotli_types text/html text/css application/javascript application/json;\ngzip on;\ngzip_types text/plain text/css application/javascript application/json;',
          references: ['https://web.dev/articles/reduce-network-payloads-using-text-compression'],
          evidence: { contentType: h['content-type'] },
        }),
      );
    } else if (encoding) {
      const good = /br|gzip|zstd/i.test(encoding);
      findings.push(
        good
          ? pass(MODULE, 'performance', 'http.compression.ok', `Compression enabled (${encoding})`, `Responses are compressed with ${encoding}.`, { encoding })
          : finding({
              id: 'http.weak-compression',
              module: MODULE,
              category: 'performance',
              title: `Suboptimal compression (${encoding})`,
              severity: 'low',
              status: 'warn',
              risk: 'A weaker/older compression algorithm leaves performance on the table.',
              whyItMatters: 'Brotli generally beats Gzip on text assets. Prefer br with a gzip fallback.',
              technical: `Observed Content-Encoding: ${encoding}. Consider adding Brotli.`,
              businessImpact: 'Marginally slower loads and higher bandwidth.',
              probability: 'medium',
              remediation: 'Add Brotli support alongside the current encoding.',
              estimatedFixTime: '30 minutes',
              references: ['https://web.dev/articles/reduce-network-payloads-using-text-compression'],
              evidence: { encoding },
            }),
      );
    }

    // Caching
    const cacheControl = h['cache-control'];
    const etag = h['etag'];
    const lastMod = h['last-modified'];
    if (!cacheControl && !etag && !lastMod) {
      findings.push(
        finding({
          id: 'http.no-caching',
          module: MODULE,
          category: 'performance',
          title: 'No caching directives present',
          severity: 'low',
          status: 'warn',
          risk: 'Missing cache metadata forces revalidation or refetching, hurting repeat-visit performance.',
          whyItMatters: 'Cache-Control, ETag, and Last-Modified let browsers and CDNs avoid re-downloading unchanged resources.',
          technical: 'No Cache-Control, ETag, or Last-Modified header was returned. Define an explicit caching strategy per asset type.',
          businessImpact: 'Slower repeat visits and higher origin load / cost.',
          probability: 'medium',
          remediation: 'Add Cache-Control (immutable, long max-age for fingerprinted assets; short/validated for HTML).',
          estimatedFixTime: '1-2 hours',
          exampleCode: 'Cache-Control: public, max-age=31536000, immutable   # for hashed static assets\nCache-Control: no-cache                              # for HTML documents',
          references: ['https://web.dev/articles/http-cache'],
        }),
      );
    } else {
      findings.push(pass(MODULE, 'performance', 'http.caching.ok', 'Caching directives present', `Cache-Control="${cacheControl ?? '—'}", ETag=${etag ? 'yes' : 'no'}.`, { cacheControl, etag: !!etag }));
    }

    // Redirects
    if (page.redirects.length > 2) {
      findings.push(
        finding({
          id: 'http.redirect-chain',
          module: MODULE,
          category: 'performance',
          title: `Long redirect chain (${page.redirects.length} hops)`,
          severity: 'low',
          status: 'warn',
          risk: 'Each redirect adds a full round-trip before content loads.',
          whyItMatters: 'Chained redirects (e.g. http→https→www→trailing-slash) compound latency, especially on high-RTT mobile networks.',
          technical: `Redirect chain: ${page.redirects.map((r) => `${r.status} ${r.url}`).join(' → ')}`,
          businessImpact: 'Slower TTFB and first paint; small SEO penalty.',
          probability: 'medium',
          remediation: 'Collapse to a single redirect to the canonical URL.',
          estimatedFixTime: '30 minutes',
          references: ['https://web.dev/articles/redirects'],
          evidence: { redirects: page.redirects },
        }),
      );
    }

    // Plaintext HTTP → HTTPS enforcement
    if (ctx.target.protocol === 'http:' && !page.redirects.some((r) => r.location.startsWith('https:'))) {
      findings.push(
        finding({
          id: 'http.no-https-redirect',
          module: MODULE,
          category: 'security',
          title: 'HTTP not redirected to HTTPS',
          severity: 'high',
          status: 'fail',
          risk: 'Content is served over plaintext, exposing users to interception and tampering.',
          whyItMatters: 'All modern sites must force HTTPS. Serving HTTP allows man-in-the-middle attacks and breaks HSTS.',
          technical: 'The HTTP endpoint did not 301/302 to an https:// URL.',
          businessImpact: 'Data interception, browser "Not Secure" warnings, SEO and trust damage.',
          probability: 'high',
          owasp: ['A02:2021-Cryptographic Failures'],
          remediation: 'Redirect all HTTP traffic to HTTPS and add HSTS.',
          estimatedFixTime: '30 minutes',
          exampleCode: '# nginx\nserver { listen 80; server_name _; return 301 https://$host$request_uri; }',
          references: ['https://web.dev/articles/why-https-matters'],
        }),
      );
    }

    return {
      module: MODULE,
      category: 'performance',
      ok: true,
      findings,
      durationMs: Math.round(performance.now() - t0),
      data: { encoding, cacheControl, etag, redirects: page.redirects, latencyMs: page.latencyMs },
    };
  },
};
