/** Central registry of all scanning modules. */

import type { ScanModule } from '../core/types.js';
import { cookiesModule } from './cookies.js';
import { corsModule } from './cors.js';
import { robotsModule } from './robots.js';
import { cspModule } from './csp.js';
import { dependenciesModule } from './dependencies.js';
import { dnsModule } from './dns.js';
import { securityHeadersModule } from './headers.js';
import { httpModule } from './http.js';
import { imagesModule } from './images.js';
import { jsSecurityModule } from './jssecurity.js';
import { performanceModule } from './performance.js';
import { scalabilityModule } from './scalability.js';
import { seoModule } from './seo.js';
import { spiderModule } from './spider.js';
import { sslModule } from './ssl.js';
import { techModule } from './tech.js';
import { webVitalsModule } from './webvitals.js';
import { portsModule } from './active/ports.js';
import { exposureModule } from './active/exposure.js';
import { nucleiModule } from './active/nuclei.js';
import { zapModule } from './active/zap.js';

/** All modules, passive first then active. Order is display-only. */
export const ALL_MODULES: ScanModule[] = [
  sslModule,
  securityHeadersModule,
  cspModule,
  cookiesModule,
  corsModule,
  dnsModule,
  techModule,
  dependenciesModule,
  httpModule,
  performanceModule,
  webVitalsModule,
  imagesModule,
  jsSecurityModule,
  robotsModule,
  spiderModule,
  seoModule,
  scalabilityModule,
  // TODO(aegis:module): register new passive checks here (SRI coverage, mixed
  // content, form-action/mailto leaks, deeper cache analysis). One import above,
  // one entry here — the engine handles the rest. See docs/DEVELOPING.md.
  // Active (authorization-gated):
  portsModule,
  exposureModule,
  nucleiModule,
  zapModule,
];

export const PASSIVE_MODULES = ALL_MODULES.filter((m) => m.mode === 'passive');
export const ACTIVE_MODULES = ALL_MODULES.filter((m) => m.mode === 'active');

export function moduleByName(name: string): ScanModule | undefined {
  return ALL_MODULES.find((m) => m.name === name);
}

/** Lightweight catalog for the UI/docs. */
export function moduleCatalog() {
  return ALL_MODULES.map((m) => ({
    name: m.name,
    title: m.title,
    category: m.category,
    mode: m.mode,
    description: m.description,
  }));
}
