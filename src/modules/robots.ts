/** Modules 11 & 12 — robots.txt and sitemap.xml analysis (passive). */

import { finding, pass } from '../core/finding.js';
import type { Finding, ModuleResult, ScanContext, ScanModule } from '../core/types.js';

const MODULE = 'robots';

/** Disallowed paths that hint at sensitive areas worth reviewing (not fetched). */
const SENSITIVE_HINTS = /admin|login|wp-admin|backup|\.git|\.env|config|staging|internal|private|api\/v/i;

export const robotsModule: ScanModule = {
  name: MODULE,
  title: 'Robots & Sitemap',
  category: 'seo',
  mode: 'passive',
  description: 'Reads robots.txt and sitemap.xml for crawlability and inadvertent disclosure.',
  async run(ctx: ScanContext): Promise<ModuleResult> {
    const t0 = performance.now();
    const origin = ctx.target.origin;
    const findings: Finding[] = [];
    const data: Record<string, unknown> = {};

    // robots.txt
    const robotsRes = await ctx.fetch(`${origin}/robots.txt`).catch(() => null);
    if (robotsRes && robotsRes.status === 200) {
      const robots = await robotsRes.text().catch(() => '');
      data.robots = robots.slice(0, 4000);
      const disallows = [...robots.matchAll(/^\s*Disallow:\s*(\S+)/gim)].map((m) => m[1] ?? '');
      const sensitive = disallows.filter((p) => SENSITIVE_HINTS.test(p));

      findings.push(pass(MODULE, 'seo', 'robots.present', 'robots.txt is present', `${disallows.length} Disallow rule(s) found.`, { disallows }));

      if (sensitive.length > 0) {
        findings.push(
          finding({
            id: 'robots.sensitive',
            module: MODULE,
            category: 'security',
            title: 'robots.txt discloses sensitive-looking paths',
            severity: 'low',
            status: 'warn',
            risk: 'Disallowed paths in robots.txt are a public roadmap to admin/backup/internal areas.',
            whyItMatters:
              'robots.txt is world-readable. Listing sensitive paths there tells attackers exactly where to look — the file controls crawlers, not access.',
            technical: `Sensitive-looking Disallow entries: ${sensitive.join(', ')}. robots.txt does not restrict access; protect these paths with real authentication/authorization.`,
            businessImpact: 'Reconnaissance shortcut for attackers targeting privileged areas.',
            probability: 'medium',
            owasp: ['A01:2021-Broken Access Control', 'A05:2021-Security Misconfiguration'],
            remediation: 'Avoid listing sensitive paths in robots.txt; enforce authentication and, if needed, use meta noindex or auth-gated routes.',
            estimatedFixTime: '1 hour',
            references: ['https://developers.google.com/search/docs/crawling-indexing/robots/intro'],
            evidence: { sensitive },
          }),
        );
      }

      if (!/Sitemap:/i.test(robots)) {
        findings.push(
          finding({
            id: 'robots.no-sitemap-ref',
            module: MODULE,
            category: 'seo',
            title: 'robots.txt does not reference a sitemap',
            severity: 'info',
            status: 'warn',
            risk: 'Search engines may discover fewer of your URLs.',
            whyItMatters: 'A Sitemap: directive helps crawlers find all indexable pages efficiently.',
            technical: 'Add a Sitemap: line pointing to your sitemap.xml.',
            businessImpact: 'Slower/less complete indexing.',
            probability: 'low',
            remediation: 'Add "Sitemap: https://<domain>/sitemap.xml" to robots.txt.',
            estimatedFixTime: '5 minutes',
            references: ['https://developers.google.com/search/docs/crawling-indexing/sitemaps/build-sitemap'],
          }),
        );
      }
    } else {
      findings.push(
        finding({
          id: 'robots.missing',
          module: MODULE,
          category: 'seo',
          title: 'No robots.txt found',
          severity: 'info',
          status: 'warn',
          risk: 'Crawlers have no explicit guidance; not harmful but a missed best practice.',
          whyItMatters: 'A robots.txt lets you steer crawler behavior and point to your sitemap.',
          technical: `GET ${origin}/robots.txt did not return 200.`,
          businessImpact: 'Minor SEO/control gap.',
          probability: 'low',
          remediation: 'Add a robots.txt (even a permissive one) and reference your sitemap.',
          estimatedFixTime: '15 minutes',
          references: ['https://developers.google.com/search/docs/crawling-indexing/robots/intro'],
        }),
      );
    }

    // sitemap.xml
    const sitemapRes = await ctx.fetch(`${origin}/sitemap.xml`).catch(() => null);
    if (sitemapRes && sitemapRes.status === 200) {
      const xml = await sitemapRes.text().catch(() => '');
      const urls = [...xml.matchAll(/<loc>\s*([^<\s]+)\s*<\/loc>/gi)].map((m) => m[1] ?? '');
      data.sitemapUrlCount = urls.length;
      const staging = urls.filter((u) => /staging|dev\.|test\.|\.local|preprod/i.test(u));
      findings.push(pass(MODULE, 'seo', 'robots.sitemap.present', 'sitemap.xml is present', `${urls.length} URL(s) listed.`, { count: urls.length }));

      if (staging.length > 0) {
        findings.push(
          finding({
            id: 'robots.sitemap.staging',
            module: MODULE,
            category: 'security',
            title: 'Sitemap exposes staging/development URLs',
            severity: 'medium',
            status: 'fail',
            risk: 'Non-production environments are often less hardened and may leak data.',
            whyItMatters: 'Publishing staging/dev URLs in a public sitemap invites attackers to probe environments that frequently have weaker auth, debug modes, or real data.',
            technical: `Non-production URLs in sitemap: ${staging.slice(0, 5).join(', ')}${staging.length > 5 ? ' …' : ''}. Remove them and restrict those environments.`,
            businessImpact: 'Data exposure and an easier path to production via a weaker environment.',
            probability: 'medium',
            owasp: ['A05:2021-Security Misconfiguration'],
            remediation: 'Exclude non-production hosts from public sitemaps and gate those environments behind auth/IP allow-lists.',
            estimatedFixTime: '1-2 hours',
            references: ['https://developers.google.com/search/docs/crawling-indexing/sitemaps/overview'],
            evidence: { staging },
          }),
        );
      }
    } else {
      findings.push(
        finding({
          id: 'robots.sitemap.missing',
          module: MODULE,
          category: 'seo',
          title: 'No sitemap.xml found',
          severity: 'info',
          status: 'warn',
          risk: 'Search engines may index your site less completely.',
          whyItMatters: 'A sitemap accelerates and completes indexing of your pages.',
          technical: `GET ${origin}/sitemap.xml did not return 200.`,
          businessImpact: 'Slower/less complete indexing.',
          probability: 'low',
          remediation: 'Generate and publish a sitemap.xml.',
          estimatedFixTime: '1 hour',
          references: ['https://developers.google.com/search/docs/crawling-indexing/sitemaps/build-sitemap'],
        }),
      );
    }

    return { module: MODULE, category: 'seo', ok: true, findings, durationMs: Math.round(performance.now() - t0), data };
  },
};
