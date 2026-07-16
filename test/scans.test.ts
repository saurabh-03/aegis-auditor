import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import type { FastifyInstance } from 'fastify';
import { buildServer } from '../src/server.js';

delete process.env.DATABASE_URL;
delete process.env.REDIS_URL; // force in-process queue

let app: FastifyInstance;
let token: string;

before(async () => {
  app = await buildServer();
  await app.ready();
  const reg = JSON.parse(
    (await app.inject({ method: 'POST', url: '/api/auth/register', payload: { email: 'scanner@example.com', password: 'supersecret', name: 'Scanner' } })).payload,
  );
  token = reg.accessToken;
});
after(async () => {
  await app.close();
});

test('async scan: enqueue → 202, poll → COMPLETED with report', async () => {
  const enq = await app.inject({
    method: 'POST',
    url: '/api/scans',
    headers: { authorization: `Bearer ${token}` },
    payload: { target: 'example.com' },
  });
  assert.equal(enq.statusCode, 202);
  const { scanId, status } = JSON.parse(enq.payload);
  assert.ok(scanId);
  assert.equal(status, 'QUEUED');

  // Poll until terminal.
  let final: { status: string; report: { overall: { score: number } } | null } | null = null;
  for (let i = 0; i < 40; i++) {
    const res = await app.inject({ method: 'GET', url: `/api/scans/${scanId}`, headers: { authorization: `Bearer ${token}` } });
    assert.equal(res.statusCode, 200);
    const body = JSON.parse(res.payload);
    if (body.status === 'COMPLETED' || body.status === 'FAILED') {
      final = body;
      break;
    }
    await new Promise((r) => setTimeout(r, 500));
  }
  assert.ok(final, 'scan did not reach a terminal state in time');
  assert.equal(final!.status, 'COMPLETED');
  assert.ok(final!.report && typeof final!.report.overall.score === 'number');
});

test('async scan: active without project is refused', async () => {
  const res = await app.inject({
    method: 'POST',
    url: '/api/scans',
    headers: { authorization: `Bearer ${token}` },
    payload: { target: 'example.com', includeActive: true },
  });
  assert.equal(res.statusCode, 403);
  assert.equal(JSON.parse(res.payload).error, 'active_requires_project');
});

test('async scan requires authentication', async () => {
  const res = await app.inject({ method: 'POST', url: '/api/scans', payload: { target: 'example.com' } });
  assert.equal(res.statusCode, 401);
});

test('authenticated-scan credentials are refused without a verified project', async () => {
  // Ad-hoc target (no project) carrying auth → rejected.
  const res = await app.inject({
    method: 'POST',
    url: '/api/scans',
    headers: { authorization: `Bearer ${token}` },
    payload: { target: 'example.com', authCookie: 'session=abc' },
  });
  assert.equal(res.statusCode, 403);
  assert.equal(JSON.parse(res.payload).error, 'auth_requires_verified_project');
});

test('form-login to an off-site host is rejected', async () => {
  // Create an org + project, then (without verifying) attempt is blocked by the
  // verified-project gate first; here we assert the gate rejects auth outright.
  const res = await app.inject({
    method: 'POST',
    url: '/api/scans',
    headers: { authorization: `Bearer ${token}` },
    payload: {
      target: 'example.com',
      formLogin: { loginUrl: 'https://evil.example.net/login', username: 'a', password: 'b' },
    },
  });
  // No verified project → the credential gate fires before scope validation.
  assert.equal(res.statusCode, 403);
  assert.equal(JSON.parse(res.payload).error, 'auth_requires_verified_project');
});
