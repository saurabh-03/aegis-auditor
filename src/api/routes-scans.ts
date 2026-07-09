/**
 * Asynchronous scan API (Phase 2).
 *   POST /api/scans                enqueue a scan → 202 { scanId }
 *   GET  /api/scans/:id            status + result
 *   GET  /api/scans/:id/stream     WebSocket live progress
 *
 * Scans may be ad-hoc (target only, passive) or project-scoped (projectId).
 * Active checks require a verified project — identical gate to the sync endpoint.
 */

import type { FastifyInstance } from 'fastify';
import { config } from '../core/config.js';
import { normalizeTarget } from '../core/http.js';
import { CAN } from '../auth/rbac.js';
import type { Queue } from '../queue/types.js';
import type { ScanRecord, Store } from '../store/types.js';
import { getAuth, requireAuth } from './authctx.js';

interface EnqueueBody {
  target?: string;
  projectId?: string;
  includeActive?: boolean;
  only?: string[];
  skip?: string[];
}

/** Can `userId` read this scan? Owner (ad-hoc) or org member (project scan). */
async function canRead(store: Store, scan: ScanRecord, userId: string | null): Promise<boolean> {
  if (scan.orgId) return userId ? Boolean(await store.getMembership(userId, scan.orgId)) : false;
  if (scan.userId) return scan.userId === userId;
  return true; // public ad-hoc scan (created via /api/scan)
}

export function registerScanRoutes(app: FastifyInstance, store: Store, queue: Queue): void {
  app.post<{ Body: EnqueueBody }>('/api/scans', async (req, reply) => {
    const auth = requireAuth(req, reply);
    if (!auth) return;
    const body = req.body ?? {};

    let target: string;
    let projectId: string | null = null;
    let orgId: string | null = null;
    let includeActive = Boolean(body.includeActive);

    if (body.projectId) {
      const project = await store.getProject(body.projectId);
      if (!project) return reply.code(404).send({ error: 'project_not_found' });
      const membership = await store.getMembership(auth.userId, project.orgId);
      if (!membership) return reply.code(403).send({ error: 'forbidden' });
      if (!CAN.manageProjects(membership.role)) return reply.code(403).send({ error: 'insufficient_role' });
      if (includeActive && !project.verifiedAt) {
        return reply.code(403).send({ error: 'ownership_unverified', message: 'Verify project ownership before active scans.' });
      }
      target = project.target;
      projectId = project.id;
      orgId = project.orgId;
    } else {
      if (!body.target) return reply.code(400).send({ error: 'missing_target' });
      if (includeActive) {
        return reply.code(403).send({ error: 'active_requires_project', message: 'Active checks require a verified project.' });
      }
      try {
        target = normalizeTarget(body.target).toString();
      } catch {
        return reply.code(400).send({ error: 'invalid_target' });
      }
      includeActive = false;
    }

    const rec = await store.saveScan({
      projectId,
      orgId,
      userId: auth.userId,
      target,
      status: 'QUEUED',
      authorized: includeActive,
      overall: null,
      grade: null,
      report: null,
    });

    await queue.enqueue({
      scanId: rec.id,
      target,
      projectId,
      orgId,
      userId: auth.userId,
      options: {
        authorized: includeActive,
        includeActive,
        ...(body.only ? { only: body.only } : {}),
        ...(body.skip ? { skip: body.skip } : {}),
        timeoutMs: config.defaultTimeoutMs,
      },
    });

    return reply.code(202).send({ scanId: rec.id, status: 'QUEUED', stream: `/api/scans/${rec.id}/stream` });
  });

  app.get<{ Params: { id: string } }>('/api/scans/:id', async (req, reply) => {
    const auth = requireAuth(req, reply);
    if (!auth) return;
    const scan = await store.getScan(req.params.id);
    if (!scan) return reply.code(404).send({ error: 'not_found' });
    if (!(await canRead(store, scan, auth.userId))) return reply.code(403).send({ error: 'forbidden' });
    return reply.send({
      scanId: scan.id,
      status: scan.status,
      target: scan.target,
      overall: scan.overall,
      grade: scan.grade,
      createdAt: scan.createdAt,
      report: scan.status === 'COMPLETED' ? scan.report : null,
    });
  });

  // WebSocket live progress. Auth via ?token= (browsers can't set WS headers).
  app.get<{ Params: { id: string }; Querystring: { token?: string } }>(
    '/api/scans/:id/stream',
    { websocket: true },
    async (socket, req) => {
      const scanId = req.params.id;
      // Authenticate: Bearer header or ?token= query.
      let userId: string | null = getAuth(req)?.userId ?? null;
      if (!userId && req.query.token) {
        const { verifyJwt } = await import('../auth/jwt.js');
        const r = verifyJwt(req.query.token);
        if (r.valid && r.claims?.typ === 'access') userId = r.claims.sub;
      }

      const scan = await store.getScan(scanId);
      if (!scan) {
        socket.send(JSON.stringify({ type: 'error', error: 'not_found' }));
        socket.close();
        return;
      }
      if (!(await canRead(store, scan, userId))) {
        socket.send(JSON.stringify({ type: 'error', error: 'forbidden' }));
        socket.close();
        return;
      }

      // Send current status immediately, then stream updates.
      socket.send(JSON.stringify({ type: 'status', status: scan.status, scanId }));
      if (scan.status === 'COMPLETED' || scan.status === 'FAILED') {
        socket.close();
        return;
      }

      const unsubscribe = queue.subscribe(scanId, (event) => {
        if (socket.readyState === socket.OPEN) socket.send(JSON.stringify(event));
        if (event.type === 'completed' || event.type === 'failed') {
          setTimeout(() => socket.close(), 50);
        }
      });
      socket.on('close', unsubscribe);
    },
  );
}
