/**
 * Scheduled scans, regression diffs, and notifications.
 *   POST   /api/projects/:projectId/schedules
 *   GET    /api/projects/:projectId/schedules
 *   PATCH  /api/schedules/:id
 *   DELETE /api/schedules/:id
 *   GET    /api/scans/:id/diff              regression diff vs previous project scan
 *   GET    /api/orgs/:orgId/notifications
 *   POST   /api/notifications/:id/read
 */

import type { FastifyInstance } from 'fastify';
import { assessRegression, diffReports } from '../core/diff.js';
import { CAN } from '../auth/rbac.js';
import type { Cadence, Store } from '../store/types.js';
import { requireAuth } from './authctx.js';

const CADENCES: Cadence[] = ['daily', 'weekly', 'monthly'];

interface CreateScheduleBody {
  cadence?: Cadence;
  includeActive?: boolean;
  webhookUrl?: string | null;
}

interface PatchScheduleBody {
  cadence?: Cadence;
  enabled?: boolean;
  includeActive?: boolean;
  webhookUrl?: string | null;
}

export function registerScheduleRoutes(app: FastifyInstance, store: Store): void {
  // Create a schedule for a project.
  app.post<{ Params: { projectId: string }; Body: CreateScheduleBody }>(
    '/api/projects/:projectId/schedules',
    async (req, reply) => {
      const auth = requireAuth(req, reply);
      if (!auth) return;
      const project = await store.getProject(req.params.projectId);
      if (!project) return reply.code(404).send({ error: 'project_not_found' });
      const membership = await store.getMembership(auth.userId, project.orgId);
      if (!membership || !CAN.manageProjects(membership.role)) return reply.code(403).send({ error: 'forbidden' });

      const body = req.body ?? {};
      const cadence = body.cadence ?? 'weekly';
      if (!CADENCES.includes(cadence)) return reply.code(400).send({ error: 'invalid_cadence', message: `cadence must be one of ${CADENCES.join(', ')}` });

      const schedule = await store.createSchedule({
        projectId: project.id,
        orgId: project.orgId,
        cadence,
        includeActive: Boolean(body.includeActive),
        webhookUrl: body.webhookUrl ?? null,
      });
      return reply.code(201).send(schedule);
    },
  );

  // List schedules for a project.
  app.get<{ Params: { projectId: string } }>('/api/projects/:projectId/schedules', async (req, reply) => {
    const auth = requireAuth(req, reply);
    if (!auth) return;
    const project = await store.getProject(req.params.projectId);
    if (!project) return reply.code(404).send({ error: 'project_not_found' });
    if (!(await store.getMembership(auth.userId, project.orgId))) return reply.code(403).send({ error: 'forbidden' });
    return reply.send({ schedules: await store.listSchedules({ projectId: project.id }) });
  });

  // Update a schedule (enable/disable, cadence, webhook).
  app.patch<{ Params: { id: string }; Body: PatchScheduleBody }>('/api/schedules/:id', async (req, reply) => {
    const auth = requireAuth(req, reply);
    if (!auth) return;
    const schedule = await store.getSchedule(req.params.id);
    if (!schedule) return reply.code(404).send({ error: 'not_found' });
    const membership = await store.getMembership(auth.userId, schedule.orgId);
    if (!membership || !CAN.manageProjects(membership.role)) return reply.code(403).send({ error: 'forbidden' });

    const body = req.body ?? {};
    if (body.cadence && !CADENCES.includes(body.cadence)) return reply.code(400).send({ error: 'invalid_cadence' });
    const updated = await store.updateSchedule(req.params.id, {
      ...(body.cadence !== undefined ? { cadence: body.cadence } : {}),
      ...(body.enabled !== undefined ? { enabled: body.enabled } : {}),
      ...(body.includeActive !== undefined ? { includeActive: body.includeActive } : {}),
      ...(body.webhookUrl !== undefined ? { webhookUrl: body.webhookUrl } : {}),
    });
    return reply.send(updated);
  });

  // Delete a schedule.
  app.delete<{ Params: { id: string } }>('/api/schedules/:id', async (req, reply) => {
    const auth = requireAuth(req, reply);
    if (!auth) return;
    const schedule = await store.getSchedule(req.params.id);
    if (!schedule) return reply.code(404).send({ error: 'not_found' });
    const membership = await store.getMembership(auth.userId, schedule.orgId);
    if (!membership || !CAN.manageProjects(membership.role)) return reply.code(403).send({ error: 'forbidden' });
    await store.deleteSchedule(req.params.id);
    return reply.code(204).send();
  });

  // Regression diff for a scan vs the previous scan of its project.
  app.get<{ Params: { id: string } }>('/api/scans/:id/diff', async (req, reply) => {
    const auth = requireAuth(req, reply);
    if (!auth) return;
    const scan = await store.getScan(req.params.id);
    if (!scan || !scan.report) return reply.code(404).send({ error: 'not_found' });
    if (scan.orgId && !(await store.getMembership(auth.userId, scan.orgId))) return reply.code(403).send({ error: 'forbidden' });
    if (!scan.projectId) return reply.send({ diff: null, regression: { isRegression: false, level: 'none', reasons: [] } });

    const prev = await store.previousScanForProject(scan.projectId, scan.id);
    const diff = diffReports(prev?.report ?? null, scan.report);
    return reply.send({ diff, regression: assessRegression(diff), baselineScanId: prev?.id ?? null });
  });

  // List notifications for an org.
  app.get<{ Params: { orgId: string }; Querystring: { unread?: string; limit?: string } }>(
    '/api/orgs/:orgId/notifications',
    async (req, reply) => {
      const auth = requireAuth(req, reply);
      if (!auth) return;
      if (!(await store.getMembership(auth.userId, req.params.orgId))) return reply.code(403).send({ error: 'forbidden' });
      const q = req.query;
      const notifications = await store.listNotifications(req.params.orgId, {
        limit: Number(q.limit ?? 50),
        unreadOnly: q.unread === 'true' || q.unread === '1',
      });
      return reply.send({ notifications });
    },
  );

  // Mark a notification read.
  app.post<{ Params: { id: string } }>('/api/notifications/:id/read', async (req, reply) => {
    const auth = requireAuth(req, reply);
    if (!auth) return;
    await store.markNotificationRead(req.params.id);
    return reply.send({ ok: true });
  });
}
