/** Organizations, teams, projects, ownership verification, and project-scoped scans. */

import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';
import { config } from '../core/config.js';
import { normalizeTarget } from '../core/http.js';
import { runScan } from '../core/scanner.js';
import { ALL_MODULES } from '../modules/registry.js';
import { CAN } from '../auth/rbac.js';
import { makeOwnershipToken, verifyOwnership } from '../auth/ownership.js';
import type { Membership, Role, Store } from '../store/types.js';
import { requireAuth } from './authctx.js';

async function loadMembership(
  store: Store,
  req: FastifyRequest,
  reply: FastifyReply,
  orgId: string,
): Promise<{ userId: string; membership: Membership } | null> {
  const auth = requireAuth(req, reply);
  if (!auth) return null;
  const membership = await store.getMembership(auth.userId, orgId);
  if (!membership) {
    reply.code(403).send({ error: 'forbidden', message: 'You are not a member of this organization.' });
    return null;
  }
  return { userId: auth.userId, membership };
}

export function registerTenancyRoutes(app: FastifyInstance, store: Store): void {
  // ----- Organizations -----
  app.get('/api/orgs', async (req, reply) => {
    const auth = requireAuth(req, reply);
    if (!auth) return;
    return reply.send({ organizations: await store.listOrganizationsForUser(auth.userId) });
  });

  app.post<{ Body: { name?: string } }>('/api/orgs', async (req, reply) => {
    const auth = requireAuth(req, reply);
    if (!auth) return;
    const name = req.body?.name?.trim();
    if (!name) return reply.code(400).send({ error: 'missing_name' });
    return reply.code(201).send({ organization: await store.createOrganization(name, auth.userId) });
  });

  app.post<{ Params: { orgId: string }; Body: { email?: string; role?: Role } }>(
    '/api/orgs/:orgId/members',
    async (req, reply) => {
      const ctx = await loadMembership(store, req, reply, req.params.orgId);
      if (!ctx) return;
      if (!CAN.manageOrg(ctx.membership.role)) return reply.code(403).send({ error: 'insufficient_role', message: 'Requires ADMIN or OWNER.' });
      const email = req.body?.email?.trim();
      const role = req.body?.role ?? 'MEMBER';
      if (!email) return reply.code(400).send({ error: 'missing_email' });
      const user = await store.getUserByEmail(email);
      if (!user) return reply.code(404).send({ error: 'user_not_found', message: 'Invite the user to sign up first.' });
      const m = await store.addMember(req.params.orgId, user.id, role);
      return reply.code(201).send({ membership: m });
    },
  );

  // ----- Teams -----
  app.get<{ Params: { orgId: string } }>('/api/orgs/:orgId/teams', async (req, reply) => {
    const ctx = await loadMembership(store, req, reply, req.params.orgId);
    if (!ctx) return;
    return reply.send({ teams: await store.listTeams(req.params.orgId) });
  });

  app.post<{ Params: { orgId: string }; Body: { name?: string } }>('/api/orgs/:orgId/teams', async (req, reply) => {
    const ctx = await loadMembership(store, req, reply, req.params.orgId);
    if (!ctx) return;
    if (!CAN.manageOrg(ctx.membership.role)) return reply.code(403).send({ error: 'insufficient_role' });
    const name = req.body?.name?.trim();
    if (!name) return reply.code(400).send({ error: 'missing_name' });
    return reply.code(201).send({ team: await store.createTeam(req.params.orgId, name) });
  });

  // ----- Projects -----
  app.get<{ Params: { orgId: string } }>('/api/orgs/:orgId/projects', async (req, reply) => {
    const ctx = await loadMembership(store, req, reply, req.params.orgId);
    if (!ctx) return;
    return reply.send({ projects: await store.listProjects(req.params.orgId) });
  });

  app.post<{ Params: { orgId: string }; Body: { name?: string; target?: string } }>(
    '/api/orgs/:orgId/projects',
    async (req, reply) => {
      const ctx = await loadMembership(store, req, reply, req.params.orgId);
      if (!ctx) return;
      if (!CAN.manageProjects(ctx.membership.role)) return reply.code(403).send({ error: 'insufficient_role' });
      const name = req.body?.name?.trim();
      const rawTarget = req.body?.target?.trim();
      if (!name || !rawTarget) return reply.code(400).send({ error: 'missing_fields', message: 'name and target required.' });
      let target: string;
      try {
        target = normalizeTarget(rawTarget).hostname;
      } catch {
        return reply.code(400).send({ error: 'invalid_target' });
      }
      const token = makeOwnershipToken();
      const project = await store.createProject(req.params.orgId, name, target, token);
      return reply.code(201).send({
        project,
        verification: {
          token,
          instructions: {
            dns: `Add a TXT record on ${target}:  aegis-verify=${token}`,
            file: `Serve the token at https://${target}/.well-known/aegis-verify`,
          },
          note: 'Active scans unlock only after verification via POST /api/projects/:id/verify.',
        },
      });
    },
  );

  app.post<{ Params: { projectId: string } }>('/api/projects/:projectId/verify', async (req, reply) => {
    const auth = requireAuth(req, reply);
    if (!auth) return;
    const project = await store.getProject(req.params.projectId);
    if (!project) return reply.code(404).send({ error: 'project_not_found' });
    const membership = await store.getMembership(auth.userId, project.orgId);
    if (!membership) return reply.code(403).send({ error: 'forbidden' });

    const outcome = await verifyOwnership(project.target, project.ownershipToken);
    if (!outcome.verified) return reply.code(400).send({ error: 'verification_failed', detail: outcome.detail });
    const updated = await store.markProjectVerified(project.id);
    return reply.send({ project: updated, method: outcome.method, detail: outcome.detail });
  });

  // ----- Project-scoped scans (persisted; active requires verification) -----
  app.post<{ Params: { projectId: string }; Body: { includeActive?: boolean; only?: string[]; skip?: string[] } }>(
    '/api/projects/:projectId/scans',
    async (req, reply) => {
      const auth = requireAuth(req, reply);
      if (!auth) return;
      const project = await store.getProject(req.params.projectId);
      if (!project) return reply.code(404).send({ error: 'project_not_found' });
      const membership = await store.getMembership(auth.userId, project.orgId);
      if (!membership) return reply.code(403).send({ error: 'forbidden' });
      if (!CAN.manageProjects(membership.role)) return reply.code(403).send({ error: 'insufficient_role' });

      const includeActive = Boolean(req.body?.includeActive);
      if (includeActive && !project.verifiedAt) {
        return reply.code(403).send({
          error: 'ownership_unverified',
          message: 'Active scans require verified project ownership. Run POST /api/projects/:id/verify first.',
        });
      }

      const target = normalizeTarget(project.target);
      const report = await runScan(target, ALL_MODULES, {
        authorized: includeActive, // verified ownership is the authorization
        includeActive,
        ...(req.body?.only ? { only: req.body.only } : {}),
        ...(req.body?.skip ? { skip: req.body.skip } : {}),
        timeoutMs: config.defaultTimeoutMs,
      });

      const rec = await store.saveScan({
        projectId: project.id,
        orgId: project.orgId,
        userId: auth.userId,
        target: report.target,
        status: 'COMPLETED',
        authorized: includeActive,
        overall: report.overall.score,
        grade: report.overall.grade,
        report,
      });
      return reply.send({ scanId: rec.id, report });
    },
  );

  app.get<{ Params: { projectId: string } }>('/api/projects/:projectId/history', async (req, reply) => {
    const auth = requireAuth(req, reply);
    if (!auth) return;
    const project = await store.getProject(req.params.projectId);
    if (!project) return reply.code(404).send({ error: 'project_not_found' });
    const membership = await store.getMembership(auth.userId, project.orgId);
    if (!membership) return reply.code(403).send({ error: 'forbidden' });
    // Match the stored report.target (full normalized URL), not just the hostname.
    const history = await store.scanHistoryForTarget(normalizeTarget(project.target).toString(), project.orgId);
    return reply.send({ projectId: project.id, target: project.target, history });
  });

  app.get<{ Params: { orgId: string }; Querystring: { limit?: string; offset?: string } }>(
    '/api/orgs/:orgId/scans',
    async (req, reply) => {
      const ctx = await loadMembership(store, req, reply, req.params.orgId);
      if (!ctx) return;
      const result = await store.listScans({
        orgId: req.params.orgId,
        limit: Number(req.query.limit ?? 50),
        offset: Number(req.query.offset ?? 0),
      });
      // Strip full report bodies from the list view.
      return reply.send({
        total: result.total,
        items: result.items.map((s) => ({ id: s.id, target: s.target, overall: s.overall, grade: s.grade, createdAt: s.createdAt, authorized: s.authorized })),
      });
    },
  );
}
