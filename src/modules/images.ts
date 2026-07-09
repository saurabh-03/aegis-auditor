/** Module 9 — Image optimization analysis (passive, from homepage HTML). */

import { finding, pass } from '../core/finding.js';
import type { Finding, ModuleResult, ScanContext, ScanModule } from '../core/types.js';

const MODULE = 'images';

interface ImgInfo {
  tag: string;
  src: string;
  hasDimensions: boolean;
  lazy: boolean;
  ext: string;
}

function parseImgs(body: string): ImgInfo[] {
  const imgs = body.match(/<img\b[^>]*>/gi) ?? [];
  return imgs.map((tag) => {
    const src = /\bsrc=["']([^"']+)["']/i.exec(tag)?.[1] ?? '';
    const ext = (/\.([a-z0-9]{2,5})(?:[?#]|$)/i.exec(src)?.[1] ?? '').toLowerCase();
    return {
      tag,
      src,
      hasDimensions: /\bwidth=/i.test(tag) && /\bheight=/i.test(tag),
      lazy: /\bloading=["']lazy["']/i.test(tag),
      ext,
    };
  });
}

export const imagesModule: ScanModule = {
  name: MODULE,
  title: 'Image Optimization',
  category: 'performance',
  mode: 'passive',
  description: 'Checks image formats, lazy loading, responsive images, and layout-stability hints.',
  async run(ctx: ScanContext): Promise<ModuleResult> {
    const t0 = performance.now();
    const { body } = await ctx.getPage();
    const imgs = parseImgs(body);
    const findings: Finding[] = [];

    if (imgs.length === 0) {
      findings.push(pass(MODULE, 'performance', 'images.none', 'No <img> elements on the homepage', 'Nothing to optimize here (images may be CSS backgrounds or loaded dynamically).'));
      return { module: MODULE, category: 'performance', ok: true, findings, durationMs: Math.round(performance.now() - t0) };
    }

    const legacy = imgs.filter((i) => ['jpg', 'jpeg', 'png', 'gif'].includes(i.ext));
    const modern = imgs.filter((i) => ['webp', 'avif'].includes(i.ext));
    const usesPicture = /<picture\b/i.test(body);
    const missingDims = imgs.filter((i) => !i.hasDimensions).length;
    const notLazy = imgs.filter((i) => !i.lazy).length;
    const hasSrcset = /\bsrcset=/i.test(body);

    // 1) Modern formats
    if (legacy.length > 0 && modern.length === 0 && !usesPicture) {
      findings.push(
        finding({
          id: 'images.legacy-formats',
          module: MODULE,
          category: 'performance',
          title: `${legacy.length} image(s) use legacy formats (no WebP/AVIF)`,
          severity: 'low',
          status: 'warn',
          risk: 'Legacy formats (JPEG/PNG/GIF) are substantially larger than modern equivalents.',
          whyItMatters: 'WebP and AVIF typically cut image bytes 25-50% at equivalent quality. Serving only JPEG/PNG wastes bandwidth and slows LCP for image-led pages.',
          technical: `Detected ${legacy.length} legacy-format image(s) and no WebP/AVIF or <picture> fallbacks. Serve modern formats with a <picture> element or content negotiation.`,
          businessImpact: 'Slower loads and higher CDN/bandwidth cost.',
          probability: 'medium',
          remediation: 'Generate WebP/AVIF and serve via <picture> with legacy fallback, or use an image CDN with automatic format negotiation.',
          estimatedFixTime: '0.5-1 day',
          exampleCode: '<picture>\n  <source srcset="/hero.avif" type="image/avif">\n  <source srcset="/hero.webp" type="image/webp">\n  <img src="/hero.jpg" width="1200" height="630" alt="…">\n</picture>',
          references: ['https://web.dev/articles/serve-images-webp'],
          evidence: { legacy: legacy.length, modern: modern.length },
        }),
      );
    } else if (modern.length > 0 || usesPicture) {
      findings.push(pass(MODULE, 'performance', 'images.modern.ok', 'Modern image formats in use', `WebP/AVIF or <picture> detected.`, { modern: modern.length, usesPicture }));
    }

    // 2) Lazy loading
    if (imgs.length > 4 && notLazy / imgs.length > 0.6) {
      findings.push(
        finding({
          id: 'images.no-lazy',
          module: MODULE,
          category: 'performance',
          title: `${notLazy} of ${imgs.length} images not lazy-loaded`,
          severity: 'low',
          status: 'warn',
          risk: 'Eagerly loading offscreen images competes for bandwidth with above-the-fold content.',
          whyItMatters: 'Native lazy loading (loading="lazy") defers offscreen images so the critical viewport loads first, improving LCP. Keep the LCP/above-the-fold image eager.',
          technical: `${notLazy}/${imgs.length} <img> elements lack loading="lazy". Add it to below-the-fold images (not the hero/LCP image).`,
          businessImpact: 'Slower initial render on image-heavy pages.',
          probability: 'medium',
          remediation: 'Add loading="lazy" to offscreen images; keep the LCP image eager with fetchpriority="high".',
          estimatedFixTime: '1-3 hours',
          exampleCode: '<img src="/below-fold.webp" width="800" height="600" loading="lazy" alt="…">',
          references: ['https://web.dev/articles/browser-level-image-lazy-loading'],
          evidence: { notLazy, total: imgs.length },
        }),
      );
    }

    // 3) Explicit dimensions (CLS)
    if (missingDims / imgs.length > 0.5) {
      findings.push(
        finding({
          id: 'images.no-dimensions',
          module: MODULE,
          category: 'performance',
          title: `${missingDims} of ${imgs.length} images lack width/height`,
          severity: 'low',
          status: 'warn',
          risk: 'Images without intrinsic dimensions cause layout shifts (poor CLS) as they load.',
          whyItMatters: 'Setting width and height (or aspect-ratio) lets the browser reserve space, preventing content from jumping — a direct Cumulative Layout Shift improvement.',
          technical: `${missingDims}/${imgs.length} images have no width/height attributes. Add them (or CSS aspect-ratio) so the browser reserves layout space.`,
          businessImpact: 'Janky loading experience and worse CLS (a Core Web Vitals ranking factor).',
          probability: 'medium',
          remediation: 'Add explicit width/height attributes or a CSS aspect-ratio to every content image.',
          estimatedFixTime: '1-3 hours',
          references: ['https://web.dev/articles/optimize-cls'],
          evidence: { missingDims, total: imgs.length },
        }),
      );
    }

    // 4) Responsive images
    if (imgs.length > 3 && !hasSrcset) {
      findings.push(
        finding({
          id: 'images.no-srcset',
          module: MODULE,
          category: 'performance',
          title: 'No responsive images (srcset) detected',
          severity: 'low',
          status: 'warn',
          risk: 'Serving one large image to all viewports wastes bytes on small screens.',
          whyItMatters: 'srcset/sizes let the browser pick an appropriately sized image per device, saving significant bandwidth on mobile.',
          technical: 'Provide multiple resolutions via srcset with a sizes attribute, or use an image CDN that resizes on the fly.',
          businessImpact: 'Wasted mobile bandwidth and slower mobile LCP.',
          probability: 'low',
          remediation: 'Add srcset/sizes (or an image CDN) for content images.',
          estimatedFixTime: '0.5 day',
          exampleCode: '<img src="/img-800.webp" srcset="/img-400.webp 400w, /img-800.webp 800w, /img-1600.webp 1600w" sizes="(max-width: 600px) 400px, 800px" alt="…">',
          references: ['https://web.dev/articles/serve-responsive-images'],
        }),
      );
    }

    if (findings.length === 0) {
      findings.push(pass(MODULE, 'performance', 'images.ok', 'Images are well optimized', `${imgs.length} images with good format/lazy/dimension hygiene.`, { total: imgs.length }));
    }

    return {
      module: MODULE,
      category: 'performance',
      ok: true,
      findings,
      durationMs: Math.round(performance.now() - t0),
      data: { total: imgs.length, legacy: legacy.length, modern: modern.length, missingDims, notLazy, hasSrcset, usesPicture },
    };
  },
};
