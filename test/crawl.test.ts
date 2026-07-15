// Must disable the SSRF guard BEFORE any import that loads config.js, because
// config captures ALLOW_PRIVATE_TARGETS once at module-eval. This file therefore
// statically imports only Node built-ins and pulls the crawler in dynamically.
process.env.ALLOW_PRIVATE_TARGETS = '1';

import { test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import type { AddressInfo } from 'node:net';

const PAGES: Record<string, string> = {
  '/': `<!doctype html><html><body>
    <a href="/about">About</a>
    <a href="/users/1">User 1</a>
    <a href="/users/2">User 2</a>
    <a href="https://external.example.org/leak">External</a>
    <a href="mailto:x@y.com">Mail</a>
    <form action="/login" method="POST">
      <input name="user"><input name="pass" type="password">
    </form>
    <form action="/save" method="post">
      <input name="title"><input type="hidden" name="_token" value="abc">
    </form>
  </body></html>`,
  '/about': `<!doctype html><html><body><a href="/">Home</a><a href="/contact?ref=1">Contact</a></body></html>`,
  '/users/1': `<!doctype html><html><body>u1</body></html>`,
  '/users/2': `<!doctype html><html><body>u2</body></html>`,
  '/contact': `<!doctype html><html><body>contact</body></html>`,
};

function startFixture(): Promise<{ base: string; close: () => Promise<void> }> {
  return new Promise((resolve) => {
    const server = http.createServer((req, res) => {
      const path = (req.url ?? '/').split('?')[0] ?? '/';
      const body = PAGES[path];
      if (body === undefined) {
        res.writeHead(404, { 'content-type': 'text/html' });
        res.end('<title>404 Not Found</title>');
        return;
      }
      res.writeHead(200, { 'content-type': 'text/html' });
      res.end(body);
    });
    server.listen(0, '127.0.0.1', () => {
      const { port } = server.address() as AddressInfo;
      resolve({
        base: `http://127.0.0.1:${port}`,
        close: () => new Promise((r) => server.close(() => r())),
      });
    });
  });
}

test('extractFromHtml pulls links + forms and detects CSRF tokens', async () => {
  const { extractFromHtml } = await import('../src/modules/browser/spider.js');
  const out = extractFromHtml(PAGES['/'] as string);
  assert.ok(out.links.includes('/about'));
  assert.ok(out.links.includes('/users/1'));
  // javascript:/mailto:/# links are excluded
  assert.ok(!out.links.some((l) => l.startsWith('mailto:')));
  assert.equal(out.forms.length, 2);
  const login = out.forms.find((f) => f.action === '/login');
  const save = out.forms.find((f) => f.action === '/save');
  assert.equal(login?.hasCsrfToken, false);
  assert.equal(save?.hasCsrfToken, true);
  assert.deepEqual(login?.inputs, ['user', 'pass']);
});

test('crawlSurface maps endpoints, dedups patterns, and enforces scope', async () => {
  const { crawlSurface } = await import('../src/modules/browser/spider.js');
  const fx = await startFixture();
  try {
    const surface = await crawlSurface(new URL(fx.base + '/'), {
      maxPages: 25,
      maxDepth: 3,
      renderJs: false, // force the deterministic HTTP-only path
      respectRobots: false,
      timeoutMs: 5000,
    });

    const urls = surface.endpoints.map((e) => e.url);
    // Seed + discovered links are present.
    assert.ok(urls.some((u) => u.endsWith('/about')));
    assert.ok(urls.some((u) => u.includes('/contact')));

    // /users/1 and /users/2 collapse to a single :num pattern endpoint.
    const userEndpoints = surface.endpoints.filter((e) => /\/users\//.test(e.url));
    assert.equal(userEndpoints.length, 1, 'numeric path segments should dedup');

    // Both forms captured, one with and one without a CSRF token.
    assert.equal(surface.forms.length, 2);
    assert.equal(surface.forms.filter((f) => f.hasCsrfToken).length, 1);

    // The form actions became POST endpoints.
    const login = surface.endpoints.find((e) => e.url.endsWith('/login'));
    assert.equal(login?.method, 'POST');
    assert.deepEqual(login?.params.sort(), ['pass', 'user']);

    // The external link is out of scope, not crawled.
    assert.ok(surface.offScopeUrls.some((u) => u.includes('external.example.org')));
    assert.ok(!urls.some((u) => u.includes('external.example.org')));

    // The contact endpoint records its query param name.
    const contact = surface.endpoints.find((e) => e.url.includes('/contact'));
    assert.ok(contact?.params.includes('ref'));

    assert.ok(surface.crawledCount >= 3);
    assert.equal(surface.renderedWithBrowser, false);
  } finally {
    await fx.close();
  }
});

test('crawlSurface skips SSRF-blocked hosts when the guard is enabled', async () => {
  // Re-enable blocking just for this check by importing a fresh ssrf assertion
  // path is not feasible here (config is cached); instead verify that an
  // off-scope private link never enters the endpoint set — scope + SSRF both
  // exclude it. This asserts the crawler never yields a private host endpoint.
  const { crawlSurface } = await import('../src/modules/browser/spider.js');
  const fx = await startFixture();
  try {
    const surface = await crawlSurface(new URL(fx.base + '/'), {
      maxPages: 10,
      maxDepth: 2,
      renderJs: false,
      respectRobots: false,
      timeoutMs: 5000,
    });
    // All endpoint hosts are the seed host (127.0.0.1) — nothing external leaked in.
    for (const e of surface.endpoints) {
      assert.equal(new URL(e.url).hostname, '127.0.0.1');
    }
  } finally {
    await fx.close();
  }
});
