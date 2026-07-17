import { test } from 'node:test';
import assert from 'node:assert/strict';
import { securityHeadersModule } from '../src/modules/headers.js';
import type { PageSnapshot, ScanContext } from '../src/core/types.js';

function ctxWithHeaders(headers: Record<string, string>): ScanContext {
  const page: PageSnapshot = {
    finalUrl: 'https://example.com/',
    status: 200,
    headers,
    setCookie: [],
    body: '<html></html>',
    redirects: [],
    latencyMs: 10,
  };
  return {
    target: new URL('https://example.com/'),
    now: new Date(),
    options: { authorized: false, timeoutMs: 5000 },
    log: () => {},
    getPage: async () => page,
    getSurface: async () => ({
      endpoints: [],
      forms: [],
      discoveredHosts: ['example.com'],
      offScopeUrls: [],
      crawledCount: 0,
      truncated: false,
      renderedWithBrowser: false,
    }),
    fetch: async () => new Response('', { status: 200 }),
  };
}

test('flags missing HSTS and CSP-frame protections', async () => {
  const res = await securityHeadersModule.run(ctxWithHeaders({}));
  const ids = res.findings.map((f) => f.id);
  assert.ok(ids.includes('headers.hsts.missing'));
  assert.ok(ids.includes('headers.xfo.missing'));
  // Every non-pass finding must be self-explaining.
  for (const f of res.findings) {
    if (f.status === 'pass') continue;
    assert.ok(f.risk && f.whyItMatters && f.technical && f.businessImpact && f.remediation);
  }
});

test('passes when strong headers are present', async () => {
  const res = await securityHeadersModule.run(
    ctxWithHeaders({
      'strict-transport-security': 'max-age=31536000; includeSubDomains',
      'x-frame-options': 'DENY',
      'x-content-type-options': 'nosniff',
      'referrer-policy': 'strict-origin-when-cross-origin',
      'permissions-policy': 'geolocation=()',
      'cross-origin-opener-policy': 'same-origin',
    }),
  );
  const failing = res.findings.filter((f) => f.status === 'fail');
  assert.equal(failing.length, 0);
});

test('detects information-disclosure headers', async () => {
  const res = await securityHeadersModule.run(ctxWithHeaders({ 'x-powered-by': 'PHP/8.1.2' }));
  assert.ok(res.findings.some((f) => f.id === 'headers.leak.x-powered-by'));
});
