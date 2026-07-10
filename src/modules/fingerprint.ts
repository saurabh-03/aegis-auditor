/** Shared technology fingerprinting used by tech.ts and dependencies.ts. */

import type { PageSnapshot } from '../core/types.js';

export interface Signature {
  name: string;
  category: string;
  header?: [string, RegExp];
  html?: RegExp;
  /** Optional version capture from html/header. */
  versionFrom?: RegExp;
}

export interface DetectedTech {
  name: string;
  category: string;
  version?: string;
}

export const SIGNATURES: Signature[] = [
  { name: 'WordPress', category: 'CMS', html: /wp-content|wp-includes|<meta name="generator" content="WordPress/i, versionFrom: /WordPress\s?([\d.]+)/i },
  { name: 'Drupal', category: 'CMS', html: /Drupal\.settings|sites\/all|<meta name="Generator" content="Drupal/i },
  { name: 'Joomla', category: 'CMS', html: /\/media\/jui\/|Joomla!/i },
  { name: 'Shopify', category: 'E-commerce', html: /cdn\.shopify\.com|Shopify\.theme/i, header: ['x-shopify-stage', /.*/i] },
  { name: 'Next.js', category: 'Framework', html: /\/_next\/static\/|__NEXT_DATA__/i },
  { name: 'Nuxt', category: 'Framework', html: /__NUXT__|\/_nuxt\//i },
  { name: 'React', category: 'Frontend', html: /data-reactroot|react(?:-dom)?(?:\.production)?\.min\.js/i },
  { name: 'Vue.js', category: 'Frontend', html: /data-v-[0-9a-f]{8}|vue(?:\.runtime)?(?:\.min)?\.js/i },
  { name: 'Angular', category: 'Frontend', html: /ng-version="([\d.]+)"|angular(?:\.min)?\.js/i, versionFrom: /ng-version="([\d.]+)"/i },
  { name: 'jQuery', category: 'JS library', html: /jquery[-.]?([\d.]+)?(?:\.min)?\.js/i, versionFrom: /jquery[-.]?([\d.]+)(?:\.min)?\.js/i },
  { name: 'Bootstrap', category: 'CSS framework', html: /bootstrap(?:\.min)?\.(?:css|js)/i, versionFrom: /bootstrap[@/]?v?([\d.]+)/i },
  { name: 'Lodash', category: 'JS library', html: /lodash(?:\.min)?\.js/i, versionFrom: /lodash@?([\d.]+)/i },
  { name: 'Moment.js', category: 'JS library', html: /moment(?:\.min)?\.js/i, versionFrom: /moment@?([\d.]+)/i },
  { name: 'Tailwind CSS', category: 'CSS framework', html: /tailwind(?:css)?(?:\.min)?\.css|--tw-/i },
  { name: 'Cloudflare', category: 'CDN', header: ['server', /cloudflare/i] },
  { name: 'Vercel', category: 'Hosting', header: ['server', /vercel/i] },
  { name: 'Netlify', category: 'Hosting', header: ['x-nf-request-id', /.*/i] },
  { name: 'nginx', category: 'Web server', header: ['server', /nginx/i], versionFrom: /nginx\/([\d.]+)/i },
  { name: 'Apache', category: 'Web server', header: ['server', /apache/i], versionFrom: /Apache\/([\d.]+)/i },
  { name: 'Amazon CloudFront', category: 'CDN', header: ['x-amz-cf-id', /.*/i] },
  { name: 'Fastly', category: 'CDN', header: ['x-served-by', /cache-.*/i] },
  { name: 'PHP', category: 'Language', header: ['x-powered-by', /php/i], versionFrom: /PHP\/([\d.]+)/i },
  { name: 'ASP.NET', category: 'Framework', header: ['x-powered-by', /asp\.net/i] },
  { name: 'Express', category: 'Framework', header: ['x-powered-by', /express/i] },
  { name: 'Google Analytics', category: 'Analytics', html: /googletagmanager\.com\/gtag|google-analytics\.com\/analytics/i },
];

// NOTE(aegis:sca): this homepage fingerprint only sees libraries referenced in
// the HTML. Full-coverage SCA (real lockfile parsing → OSV) is implemented
// separately in src/intel/manifest.ts + matchPackages(), exposed via `npm run
// sca` and POST /api/sca. This function remains the passive, no-input detector.
export function detectTechnologies(page: PageSnapshot): DetectedTech[] {
  const detected: DetectedTech[] = [];
  for (const sig of SIGNATURES) {
    let matched = false;
    let version: string | undefined;

    if (sig.header) {
      const [name, re] = sig.header;
      const v = page.headers[name];
      if (v && re.test(v)) matched = true;
      const vf = sig.versionFrom?.exec(v ?? '');
      if (vf?.[1]) version = vf[1];
    }
    if (!matched && sig.html && sig.html.test(page.body)) matched = true;
    if (matched && !version && sig.versionFrom) {
      const vf = sig.versionFrom.exec(page.body);
      if (vf?.[1]) version = vf[1];
    }
    if (matched) detected.push({ name: sig.name, category: sig.category, ...(version ? { version } : {}) });
  }
  return detected;
}
