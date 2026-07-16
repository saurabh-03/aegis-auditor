import { test } from 'node:test';
import assert from 'node:assert/strict';
import { splitJobSecret, secretKey } from '../src/queue/secrets.js';
import { formatCookies } from '../src/modules/browser/login.js';
import type { ScanJob } from '../src/queue/types.js';

function job(auth?: unknown): ScanJob {
  return {
    scanId: 's1',
    target: 'https://example.com',
    projectId: 'p1',
    orgId: 'o1',
    userId: 'u1',
    options: { authorized: true, includeActive: true, timeoutMs: 1000, ...(auth ? { auth } : {}) } as ScanJob['options'],
  };
}

test('splitJobSecret removes auth from the persisted job and returns it separately', () => {
  const SECRET = 'session=super-secret-cookie-value';
  const { sanitized, auth } = splitJobSecret(job({ cookies: SECRET }));

  // The sanitized job — the thing that lands in Redis — has no credentials.
  assert.equal(sanitized.options.auth, undefined);
  assert.ok(!JSON.stringify(sanitized).includes('super-secret-cookie-value'), 'sanitized job must not contain the secret');

  // The secret is returned separately for transient stashing.
  assert.equal((auth as { cookies: string }).cookies, SECRET);
});

test('splitJobSecret is a no-op passthrough when there is no auth', () => {
  const j = job();
  const { sanitized, auth } = splitJobSecret(j);
  assert.equal(auth, undefined);
  assert.equal(sanitized.options.auth, undefined);
});

test('splitJobSecret does not mutate the original job', () => {
  const j = job({ headers: { Authorization: 'Bearer x' } });
  splitJobSecret(j);
  assert.ok(j.options.auth, 'original job should still carry auth');
});

test('secretKey is namespaced per scan', () => {
  assert.equal(secretKey('abc'), 'aegis:secret:abc');
});

test('formatCookies renders a Cookie header value from browser cookies', () => {
  const header = formatCookies([
    { name: 'session', value: 'abc' },
    { name: 'role', value: 'admin' },
    { name: '', value: 'skip' },
  ]);
  assert.equal(header, 'session=abc; role=admin');
  assert.equal(formatCookies([]), '');
});
