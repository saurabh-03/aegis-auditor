/** Modules 22 & 23 — SEO and basic Accessibility signals from homepage HTML. */

import { finding, pass } from '../core/finding.js';
import type { Finding, ModuleResult, ScanContext, ScanModule } from '../core/types.js';

const MODULE = 'seo';

function tag(re: RegExp, html: string): string | null {
  const m = re.exec(html);
  return m ? (m[1] ?? '').trim() : null;
}

export const seoModule: ScanModule = {
  name: MODULE,
  title: 'SEO & Accessibility',
  category: 'seo',
  mode: 'passive',
  description: 'Checks meta/title/canonical/OpenGraph/structured data and basic a11y signals.',
  async run(ctx: ScanContext): Promise<ModuleResult> {
    const t0 = performance.now();
    const { body } = await ctx.getPage();
    const findings: Finding[] = [];

    const title = tag(/<title[^>]*>([^<]*)<\/title>/i, body);
    const description = tag(/<meta[^>]+name=["']description["'][^>]+content=["']([^"']*)["']/i, body);
    const canonical = /<link[^>]+rel=["']canonical["']/i.test(body);
    const ogTitle = /<meta[^>]+property=["']og:title["']/i.test(body);
    const viewport = /<meta[^>]+name=["']viewport["']/i.test(body);
    const structured = /application\/ld\+json/i.test(body);

    // Title
    if (!title) {
      findings.push(seoFail('seo.title.missing', 'Missing <title> tag', 'medium', 'The page has no title, which is critical for search ranking and browser tabs.', 'Add a concise, unique, keyword-relevant <title> (50-60 chars).', '<title>Primary Keyword — Brand</title>'));
    } else if (title.length > 65) {
      findings.push(seoWarn('seo.title.long', 'Title tag is long', `Title is ${title.length} chars and may be truncated in search results.`, 'Shorten the title to ~55-60 characters.'));
    } else {
      findings.push(pass(MODULE, 'seo', 'seo.title.ok', 'Title tag present', title, { title }));
    }

    // Description
    if (!description) {
      findings.push(seoWarn('seo.desc.missing', 'Missing meta description', 'No meta description; search engines will auto-generate snippet text.', 'Add a compelling 120-158 char meta description.'));
    } else {
      findings.push(pass(MODULE, 'seo', 'seo.desc.ok', 'Meta description present', description.slice(0, 120), { description }));
    }

    // Canonical
    if (!canonical) {
      findings.push(seoWarn('seo.canonical.missing', 'No canonical link', 'Without rel=canonical, duplicate-content variants may dilute ranking.', 'Add <link rel="canonical" href="…"> to each page.'));
    } else {
      findings.push(pass(MODULE, 'seo', 'seo.canonical.ok', 'Canonical link present', 'A rel=canonical link was found.'));
    }

    // OpenGraph
    if (!ogTitle) {
      findings.push(seoWarn('seo.og.missing', 'No OpenGraph tags', 'Missing og: tags produce poor link previews on social/chat platforms.', 'Add og:title, og:description, og:image, og:url and Twitter Card tags.'));
    } else {
      findings.push(pass(MODULE, 'seo', 'seo.og.ok', 'OpenGraph tags present', 'Social preview metadata was found.'));
    }

    // Structured data
    if (structured) findings.push(pass(MODULE, 'seo', 'seo.structured.ok', 'Structured data (JSON-LD) present', 'schema.org JSON-LD was found.'));

    // --- Accessibility signals (category: accessibility) ---
    if (!/<html[^>]+lang=/i.test(body)) {
      findings.push(
        finding({
          id: 'a11y.lang.missing',
          module: MODULE,
          category: 'accessibility',
          title: 'Missing lang attribute on <html>',
          severity: 'low',
          status: 'fail',
          risk: 'Screen readers cannot determine the page language, harming pronunciation.',
          whyItMatters: 'The lang attribute tells assistive technology which language to use, affecting pronunciation and translation.',
          technical: 'Add lang to the root element, e.g. <html lang="en">.',
          businessImpact: 'Accessibility non-compliance (WCAG 3.1.1), potential legal exposure.',
          probability: 'medium',
          owasp: [],
          remediation: 'Set <html lang="…"> matching the primary content language.',
          estimatedFixTime: '5 minutes',
          references: ['https://www.w3.org/WAI/WCAG21/Understanding/language-of-page.html'],
        }),
      );
    } else {
      findings.push(pass(MODULE, 'accessibility', 'a11y.lang.ok', 'html lang attribute present', 'The document language is declared.'));
    }

    if (!viewport) {
      findings.push(
        finding({
          id: 'a11y.viewport.missing',
          module: MODULE,
          category: 'accessibility',
          title: 'No responsive viewport meta tag',
          severity: 'low',
          status: 'fail',
          risk: 'The page may not scale on mobile, hurting usability and accessibility.',
          whyItMatters: 'Without a viewport meta, mobile browsers render at desktop width, forcing zoom and pinch — a barrier for many users.',
          technical: 'Add <meta name="viewport" content="width=device-width, initial-scale=1">.',
          businessImpact: 'Poor mobile UX, lower mobile SEO, accessibility gaps.',
          probability: 'medium',
          owasp: [],
          remediation: 'Add the responsive viewport meta tag.',
          estimatedFixTime: '5 minutes',
          references: ['https://web.dev/articles/responsive-web-design-basics'],
        }),
      );
    }

    // Images without alt (rough count)
    const imgs = body.match(/<img\b[^>]*>/gi) ?? [];
    const missingAlt = imgs.filter((t) => !/\balt\s*=/i.test(t)).length;
    if (imgs.length > 0 && missingAlt / imgs.length > 0.3) {
      findings.push(
        finding({
          id: 'a11y.img-alt',
          module: MODULE,
          category: 'accessibility',
          title: `${missingAlt} of ${imgs.length} images missing alt text`,
          severity: 'low',
          status: 'fail',
          risk: 'Images without alt text are invisible to screen-reader users.',
          whyItMatters: 'Alt text conveys image meaning to assistive tech and improves image SEO. Decorative images should use empty alt="".',
          technical: `${missingAlt}/${imgs.length} <img> tags on the homepage lack an alt attribute.`,
          businessImpact: 'WCAG 1.1.1 non-compliance and reduced accessibility.',
          probability: 'medium',
          owasp: [],
          remediation: 'Add descriptive alt text (or alt="" for decorative images).',
          estimatedFixTime: '1-3 hours',
          references: ['https://www.w3.org/WAI/tutorials/images/'],
          evidence: { total: imgs.length, missingAlt },
        }),
      );
    }

    return {
      module: MODULE,
      category: 'seo',
      ok: true,
      findings,
      durationMs: Math.round(performance.now() - t0),
      data: { title, description, canonical, ogTitle, viewport, structured, images: imgs.length, imagesMissingAlt: missingAlt },
    };
  },
};

function seoFail(id: string, title: string, sev: Finding['severity'], technical: string, remediation: string, example?: string): Finding {
  return finding({
    id, module: MODULE, category: 'seo', title, severity: sev, status: 'fail',
    risk: 'Reduced search visibility and click-through.',
    whyItMatters: technical,
    technical,
    businessImpact: 'Lower organic traffic and discoverability.',
    probability: 'medium',
    remediation,
    estimatedFixTime: '15 minutes',
    ...(example ? { exampleCode: example } : {}),
    references: ['https://developers.google.com/search/docs/fundamentals/seo-starter-guide'],
  });
}

function seoWarn(id: string, title: string, technical: string, remediation: string): Finding {
  return finding({
    id, module: MODULE, category: 'seo', title, severity: 'low', status: 'warn',
    risk: 'Suboptimal search/social presentation.',
    whyItMatters: technical,
    technical,
    businessImpact: 'Missed organic traffic and weaker link previews.',
    probability: 'low',
    remediation,
    estimatedFixTime: '15 minutes',
    references: ['https://developers.google.com/search/docs/fundamentals/seo-starter-guide'],
  });
}
