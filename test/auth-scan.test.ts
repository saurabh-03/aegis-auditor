import { test } from 'node:test';
import assert from 'node:assert/strict';
import { buildAuthHeaders } from '../src/core/http.js';
import { isExcluded } from '../src/modules/browser/spider.js';
import { buildNucleiArgs } from '../src/integrations/nuclei.js';
import { buildReplacerRules } from '../src/integrations/zap.js';
import { runScan } from '../src/core/scanner.js';
import type { ScanContext, ScanModule } from '../src/core/types.js';

test('buildAuthHeaders merges headers and cookies, lowercasing header names', () => {
  const h = buildAuthHeaders({ headers: { Authorization: 'Bearer x', 'X-Env': 'stg' }, cookies: 'sid=1; t=2' });
  assert.equal(h['authorization'], 'Bearer x');
  assert.equal(h['x-env'], 'stg');
  assert.equal(h['cookie'], 'sid=1; t=2');
  assert.deepEqual(buildAuthHeaders(undefined), {});
  assert.deepEqual(buildAuthHeaders({}), {});
});

test('isExcluded catches default logout paths plus caller patterns', () => {
  assert.equal(isExcluded('https://x.com/account/logout'), true);
  assert.equal(isExcluded('https://x.com/user/sign-out'), true);
  assert.equal(isExcluded('https://x.com/dashboard'), false);
  assert.equal(isExcluded('https://x.com/danger', ['/danger']), true);
  assert.equal(isExcluded('https://x.com/safe', ['/danger']), false);
});

test('buildNucleiArgs injects one -H per auth header', () => {
  const args = buildNucleiArgs('/tmp/list.txt', {
    severities: ['high'],
    headers: { Authorization: 'Bearer tok', Cookie: 'sid=abc' },
  });
  // Adjacent -H / value pairs.
  const hIdx = args.indexOf('-H');
  assert.ok(hIdx !== -1);
  assert.ok(args.includes('Authorization: Bearer tok'));
  assert.ok(args.includes('Cookie: sid=abc'));
  // Base flags still present.
  assert.ok(args.includes('-jsonl') && args.includes('-l') && args.includes('/tmp/list.txt'));
});

test('buildReplacerRules produces one REQ_HEADER rule per header', () => {
  const rules = buildReplacerRules({ authorization: 'Bearer tok', cookie: 'sid=abc' });
  assert.equal(rules.length, 2);
  const authRule = rules.find((r) => r.matchString === 'authorization');
  assert.equal(authRule?.matchType, 'REQ_HEADER');
  assert.equal(authRule?.replacement, 'Bearer tok');
  assert.equal(authRule?.enabled, 'true');
  assert.deepEqual(buildReplacerRules({}), []);
});

test('ctx.auth is exposed to modules and credentials never appear in the report', async () => {
  const SECRET = 'Bearer super-secret-token-value';
  let sawAuth = false;

  const probe: ScanModule = {
    name: 'authprobe',
    title: 'p',
    category: 'security',
    mode: 'passive',
    description: 't',
    async run(ctx: ScanContext) {
      // Module can read auth to pass to its engine…
      sawAuth = ctx.auth?.headers?.Authorization === SECRET;
      // …but if a buggy module tried to leak it into a finding, we still assert
      // below that the top-level report shape carries no credentials.
      return { module: 'authprobe', category: 'security', ok: true, findings: [], durationMs: 0 };
    },
  };

  const report = await runScan(
    new URL('http://8.8.8.8/'),
    [probe],
    { authorized: true, includeActive: true, timeoutMs: 1000, auth: { headers: { Authorization: SECRET } } },
  );

  assert.equal(sawAuth, true, 'module should see ctx.auth');
  // The serialized report must not contain the secret anywhere.
  assert.ok(!JSON.stringify(report).includes('super-secret-token-value'), 'report must not leak credentials');
});
