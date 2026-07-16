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
import type { ScanAuth } from '../core/types.js';
import { getAuth, requireAuthAsync } from './authctx.js';

interface FormLoginBody {
  loginUrl?: string;
  username?: string;
  password?: string;
  usernameSelector?: string;
  passwordSelector?: string;
  submitSelector?: string;
}

interface EnqueueBody {
  target?: string;
  projectId?: string;
  includeActive?: boolean;
  only?: string[];
  skip?: string[];
  /** Authenticated-scan credentials. Requires a verified project. */
  authHeaders?: Record<string, string>;
  authCookie?: string;
  excludeUrlPatterns?: string[];
  formLogin?: FormLoginBody;
}

const MAX_AUTH_HEADERS = 20;
const MAX_AUTH_VALUE_LEN = 8192;
const MAX_COOKIE_LEN = 16384;

/** True if `body` carries any authenticated-scan credential/config. */
function bodyHasAuth(b: EnqueueBody): boolean {
  return Boolean(
    (b.authHeaders && Object.keys(b.authHeaders).length) ||
      b.authCookie ||
      (b.excludeUrlPatterns && b.excludeUrlPatterns.length) ||
      b.formLogin,
  );
}

/** Same registrable domain (last two labels) — bounds where the password is sent. */
function sameSite(a: string, b: string): boolean {
  const reg = (h: string) => h.toLowerCase().split('.').slice(-2).join('.');
  return reg(a) === reg(b);
}

/**
 * Validate + assemble {@link ScanAuth} from the request body. Returns an error
 * string (client message) when invalid. `targetHost` bounds where form-login
 * credentials may be submitted.
 */
function buildScanAuth(b: EnqueueBody, targetHost: string): { auth?: ScanAuth; error?: string } {
  const auth: ScanAuth = {};

  if (b.authHeaders) {
    const entries = Object.entries(b.authHeaders);
    if (entries.length > MAX_AUTH_HEADERS) return { error: `too_many_headers (max ${MAX_AUTH_HEADERS})` };
    const headers: Record<string, string> = {};
    for (const [k, v] of entries) {
      if (!k || typeof v !== 'string') return { error: 'invalid_header' };
      if (k.length > 256 || v.length > MAX_AUTH_VALUE_LEN) return { error: 'header_too_long' };
      headers[k] = v;
    }
    if (Object.keys(headers).length) auth.headers = headers;
  }

  if (b.authCookie) {
    if (typeof b.authCookie !== 'string' || b.authCookie.length > MAX_COOKIE_LEN) return { error: 'invalid_cookie' };
    auth.cookies = b.authCookie;
  }

  if (b.excludeUrlPatterns) {
    if (!Array.isArray(b.excludeUrlPatterns)) return { error: 'invalid_exclude' };
    const pats = b.excludeUrlPatterns.filter((p) => typeof p === 'string' && p).slice(0, 50);
    if (pats.length) auth.excludeUrlPatterns = pats;
  }

  if (b.formLogin) {
    const fl = b.formLogin;
    if (!fl.loginUrl || !fl.username || !fl.password) return { error: 'form_login_incomplete' };
    let loginUrl: URL;
    try {
      loginUrl = new URL(fl.loginUrl);
    } catch {
      return { error: 'invalid_login_url' };
    }
    if (loginUrl.protocol !== 'http:' && loginUrl.protocol !== 'https:') return { error: 'invalid_login_url' };
    // Never let the password be POSTed to an unrelated host.
    if (!sameSite(loginUrl.hostname, targetHost)) return { error: 'login_url_off_site' };
    auth.login = {
      loginUrl: loginUrl.toString(),
      username: fl.username,
      password: fl.password,
      ...(fl.usernameSelector ? { usernameSelector: fl.usernameSelector } : {}),
      ...(fl.passwordSelector ? { passwordSelector: fl.passwordSelector } : {}),
      ...(fl.submitSelector ? { submitSelector: fl.submitSelector } : {}),
    };
  }

  return Object.keys(auth).length ? { auth } : {};
}

/** Can `userId` read this scan? Owner (ad-hoc) or org member (project scan). */
async function canRead(store: Store, scan: ScanRecord, userId: string | null): Promise<boolean> {
  if (scan.orgId) return userId ? Boolean(await store.getMembership(userId, scan.orgId)) : false;
  if (scan.userId) return scan.userId === userId;
  return true; // public ad-hoc scan (created via /api/scan)
}

export function registerScanRoutes(app: FastifyInstance, store: Store, queue: Queue): void {
  app.post<{ Body: EnqueueBody }>('/api/scans', async (req, reply) => {
    const auth = await requireAuthAsync(req, reply, store);
    if (!auth) return;
    const body = req.body ?? {};

    let target: string;
    let projectId: string | null = null;
    let orgId: string | null = null;
    let includeActive = Boolean(body.includeActive);
    let verifiedProject = false;

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
      verifiedProject = Boolean(project.verifiedAt);
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

    // Authenticated-scan credentials require a project with VERIFIED ownership:
    // we only send someone's session/password to a target they've proven they
    // control. Secrets never touch the store; the queue keeps them out of Redis.
    let scanAuth: ScanAuth | undefined;
    if (bodyHasAuth(body)) {
      if (!projectId || !verifiedProject) {
        return reply.code(403).send({
          error: 'auth_requires_verified_project',
          message: 'Authenticated scans require a project with verified ownership.',
        });
      }
      const built = buildScanAuth(body, new URL(target).hostname);
      if (built.error) return reply.code(400).send({ error: 'invalid_auth', message: built.error });
      scanAuth = built.auth;
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
        ...(scanAuth ? { auth: scanAuth } : {}),
        timeoutMs: config.defaultTimeoutMs,
      },
    });

    return reply.code(202).send({ scanId: rec.id, status: 'QUEUED', stream: `/api/scans/${rec.id}/stream` });
  });

  app.get<{ Params: { id: string } }>('/api/scans/:id', async (req, reply) => {
    const auth = await requireAuthAsync(req, reply, store);
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
