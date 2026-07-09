import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import type { FastifyInstance } from 'fastify';
import { buildServer } from '../src/server.js';

// Ensure the in-memory store is used.
delete process.env.DATABASE_URL;

let app: FastifyInstance;

before(async () => {
  app = await buildServer();
  await app.ready();
});
after(async () => {
  await app.close();
});

async function json(res: { payload: string }) {
  return JSON.parse(res.payload);
}

test('register issues tokens and bootstraps a personal org', async () => {
  const res = await app.inject({
    method: 'POST',
    url: '/api/auth/register',
    payload: { email: 'alice@example.com', password: 'supersecret', name: 'Alice' },
  });
  assert.equal(res.statusCode, 201);
  const body = await json(res);
  assert.ok(body.accessToken);
  assert.equal(body.user.email, 'alice@example.com');

  const me = await app.inject({ method: 'GET', url: '/api/auth/me', headers: { authorization: `Bearer ${body.accessToken}` } });
  assert.equal(me.statusCode, 200);
  const meBody = await json(me);
  assert.equal(meBody.organizations.length, 1);
  assert.equal(meBody.organizations[0].role, 'OWNER');
});

test('duplicate email is rejected', async () => {
  const res = await app.inject({ method: 'POST', url: '/api/auth/register', payload: { email: 'alice@example.com', password: 'supersecret' } });
  assert.equal(res.statusCode, 409);
});

test('login rejects wrong password, accepts correct', async () => {
  const bad = await app.inject({ method: 'POST', url: '/api/auth/login', payload: { email: 'alice@example.com', password: 'wrong' } });
  assert.equal(bad.statusCode, 401);
  const good = await app.inject({ method: 'POST', url: '/api/auth/login', payload: { email: 'alice@example.com', password: 'supersecret' } });
  assert.equal(good.statusCode, 200);
});

test('unauthenticated access to /api/orgs is 401', async () => {
  const res = await app.inject({ method: 'GET', url: '/api/orgs' });
  assert.equal(res.statusCode, 401);
});

test('project creation returns an ownership token; active scan blocked until verified', async () => {
  const reg = await json(await app.inject({ method: 'POST', url: '/api/auth/register', payload: { email: 'bob@example.com', password: 'supersecret', name: 'Bob' } }));
  const auth = { authorization: `Bearer ${reg.accessToken}` };
  const orgs = await json(await app.inject({ method: 'GET', url: '/api/orgs', headers: auth }));
  const orgId = orgs.organizations[0].id;

  const proj = await app.inject({ method: 'POST', url: `/api/orgs/${orgId}/projects`, headers: auth, payload: { name: 'My Site', target: 'example.com' } });
  assert.equal(proj.statusCode, 201);
  const projBody = await json(proj);
  assert.match(projBody.verification.token, /^aegis-/);
  const projectId = projBody.project.id;

  // Active scan must be refused because ownership is unverified.
  const active = await app.inject({ method: 'POST', url: `/api/projects/${projectId}/scans`, headers: auth, payload: { includeActive: true } });
  assert.equal(active.statusCode, 403);
  assert.equal((await json(active)).error, 'ownership_unverified');
});

test('public /api/scan refuses active checks', async () => {
  const res = await app.inject({ method: 'POST', url: '/api/scan', payload: { target: 'example.com', includeActive: true } });
  assert.equal(res.statusCode, 403);
  assert.equal((await json(res)).error, 'active_requires_project');
});
