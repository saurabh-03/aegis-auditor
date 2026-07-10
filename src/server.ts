/**
 * Aegis Auditor — HTTP API + static dashboard host (Fastify).
 *
 * Public (unauthenticated) surface:
 *   GET  /health
 *   GET  /api/modules
 *   POST /api/scan                   ad-hoc PASSIVE scan (active is refused here)
 *   GET  /api/reports/:id            fetch a scan by id (share-by-id)
 *   GET  /api/reports/:id/report.md|csv
 *
 * Authenticated surface (see routes-auth.ts, routes-tenancy.ts):
 *   /api/auth/*        register, login, refresh, me, OAuth
 *   /api/orgs/*        orgs, members, teams, projects, org scans
 *   /api/projects/*    ownership verify, project-scoped scans, history
 *
 * Storage: MemoryStore by default; PrismaStore when DATABASE_URL is set.
 */

import { fileURLToPath } from 'node:url';
import path from 'node:path';
import Fastify from 'fastify';
import cors from '@fastify/cors';
import fastifyStatic from '@fastify/static';
import websocket from '@fastify/websocket';
import { config } from './core/config.js';
import { normalizeTarget } from './core/http.js';
import { runScan } from './core/scanner.js';
import type { ScanOptions } from './core/types.js';
import { ALL_MODULES, moduleCatalog } from './modules/registry.js';
import { toMarkdown } from './report/markdown.js';
import { toCsv } from './report/csv.js';
import { renderHtmlReport, PERSONAS, type Persona } from './report/html.js';
import { renderPdf, PdfUnavailableError } from './report/pdf.js';
import { getAdvisor, generateTickets } from './ai/index.js';
import { rateLimit } from './api/ratelimit.js';
import { getStore } from './store/index.js';
import { getQueue } from './queue/index.js';
import { registerAuthRoutes } from './api/routes-auth.js';
import { registerTenancyRoutes } from './api/routes-tenancy.js';
import { registerScanRoutes } from './api/routes-scans.js';
import { registerScaRoutes } from './api/routes-sca.js';
import { registerScheduleRoutes } from './api/routes-schedules.js';
import { registerKeyRoutes } from './api/routes-keys.js';
import { registerWebhookRoutes } from './api/routes-webhooks.js';
import { Scheduler } from './schedule/scheduler.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

interface ScanBody {
  target?: string;
  includeActive?: boolean;
  only?: string[];
  skip?: string[];
}

export async function buildServer() {
  const app = Fastify({ logger: { level: process.env.LOG_LEVEL ?? 'info' } });
  await app.register(cors, { origin: true });
  await app.register(websocket);
  await app.register(fastifyStatic, { root: path.join(__dirname, '..', 'public'), prefix: '/' });

  const store = await getStore();
  const queue = await getQueue(store);
  app.log.info(`Store backend: ${store.kind} · Queue backend: ${queue.kind}`);

  registerAuthRoutes(app, store);
  registerTenancyRoutes(app, store);
  registerScanRoutes(app, store, queue);
  registerScaRoutes(app);
  registerScheduleRoutes(app, store);
  registerKeyRoutes(app, store);
  registerWebhookRoutes(app, store);

  // Recurring-scan scheduler runs on the API node (not worker-only processes).
  if (config.scheduler.enabled && process.env.AEGIS_ROLE !== 'worker') {
    const scheduler = new Scheduler(store, queue);
    scheduler.start();
    app.addHook('onClose', async () => scheduler.stop());
    app.log.info(`Scheduler enabled (every ${config.scheduler.intervalMs}ms)`);
  }

  app.get('/health', async () => ({ status: 'ok', engine: '0.1.0', store: store.kind, queue: queue.kind, uptime: process.uptime() }));
  app.get('/api/modules', async () => ({ modules: moduleCatalog() }));

  // Public ad-hoc PASSIVE scan. Active scans must go through a verified project.
  app.post<{ Body: ScanBody }>('/api/scan', async (req, reply) => {
    const rl = rateLimit(req.ip || 'unknown');
    reply.header('x-ratelimit-remaining', String(rl.remaining));
    if (!rl.ok) return reply.code(429).send({ error: 'rate_limited', resetAt: rl.resetAt });

    const body = req.body ?? {};
    if (!body.target || typeof body.target !== 'string') {
      return reply.code(400).send({ error: 'missing_target', message: 'Provide a "target" hostname or URL.' });
    }
    if (body.includeActive) {
      return reply.code(403).send({
        error: 'active_requires_project',
        message:
          'Active/intrusive checks are only available on a verified project. Create a project, verify ownership, then POST /api/projects/:id/scans.',
      });
    }

    let target: URL;
    try {
      target = normalizeTarget(body.target);
    } catch (err) {
      return reply.code(400).send({ error: 'invalid_target', message: (err as Error).message });
    }

    const options: ScanOptions = {
      authorized: false,
      includeActive: false,
      ...(body.only ? { only: body.only } : {}),
      ...(body.skip ? { skip: body.skip } : {}),
      timeoutMs: config.defaultTimeoutMs,
    };

    const report = await runScan(target, ALL_MODULES, options, { onLog: (m) => req.log.debug(m) });
    const rec = await store.saveScan({
      projectId: null,
      orgId: null,
      userId: null,
      target: report.target,
      status: 'COMPLETED',
      authorized: false,
      overall: report.overall.score,
      grade: report.overall.grade,
      report,
    });
    return reply.send({ id: rec.id, report });
  });

  app.get<{ Params: { id: string } }>('/api/reports/:id', async (req, reply) => {
    const rec = await store.getScan(req.params.id);
    if (!rec || !rec.report) return reply.code(404).send({ error: 'not_found' });
    return rec.report;
  });

  app.get<{ Params: { id: string } }>('/api/reports/:id/report.md', async (req, reply) => {
    const rec = await store.getScan(req.params.id);
    if (!rec || !rec.report) return reply.code(404).send({ error: 'not_found' });
    reply.header('content-type', 'text/markdown; charset=utf-8');
    return toMarkdown(rec.report);
  });

  app.get<{ Params: { id: string } }>('/api/reports/:id/report.csv', async (req, reply) => {
    const rec = await store.getScan(req.params.id);
    if (!rec || !rec.report) return reply.code(404).send({ error: 'not_found' });
    reply.header('content-type', 'text/csv; charset=utf-8');
    reply.header('content-disposition', `attachment; filename="aegis-${req.params.id}.csv"`);
    return toCsv(rec.report);
  });

  // Persona HTML report (executive | security | compliance | developer).
  app.get<{ Params: { id: string }; Querystring: { persona?: string } }>('/api/reports/:id/report.html', async (req, reply) => {
    const rec = await store.getScan(req.params.id);
    if (!rec || !rec.report) return reply.code(404).send({ error: 'not_found' });
    const persona = (PERSONAS as string[]).includes(req.query.persona ?? '') ? (req.query.persona as Persona) : 'executive';
    reply.header('content-type', 'text/html; charset=utf-8');
    return renderHtmlReport(rec.report, persona);
  });

  // Persona PDF report (requires Puppeteer; 501 with guidance when unavailable).
  app.get<{ Params: { id: string }; Querystring: { persona?: string } }>('/api/reports/:id/report.pdf', async (req, reply) => {
    const rec = await store.getScan(req.params.id);
    if (!rec || !rec.report) return reply.code(404).send({ error: 'not_found' });
    const persona = (PERSONAS as string[]).includes(req.query.persona ?? '') ? (req.query.persona as Persona) : 'executive';
    try {
      const pdf = await renderPdf(renderHtmlReport(rec.report, persona));
      reply.header('content-type', 'application/pdf');
      reply.header('content-disposition', `attachment; filename="aegis-${persona}-${req.params.id}.pdf"`);
      return reply.send(pdf);
    } catch (err) {
      if (err instanceof PdfUnavailableError) return reply.code(501).send({ error: 'pdf_unavailable', message: err.message });
      req.log.error(err);
      return reply.code(500).send({ error: 'pdf_failed' });
    }
  });

  // AI Security Advisor: executive summary, prioritized actions, checklist, grouping.
  app.get<{ Params: { id: string } }>('/api/reports/:id/advisor', async (req, reply) => {
    const rec = await store.getScan(req.params.id);
    if (!rec || !rec.report) return reply.code(404).send({ error: 'not_found' });
    const advisor = getAdvisor();
    return reply.send(await advisor.advise(rec.report));
  });

  // Ticket export for issue trackers.
  app.get<{ Params: { id: string }; Querystring: { format?: string } }>(
    '/api/reports/:id/tickets',
    async (req, reply) => {
      const rec = await store.getScan(req.params.id);
      if (!rec || !rec.report) return reply.code(404).send({ error: 'not_found' });
      const format = req.query.format === 'jira' ? 'jira' : 'github';
      return reply.send({ format, tickets: generateTickets(rec.report, format) });
    },
  );

  return app;
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  buildServer()
    .then((app) => app.listen({ host: config.host, port: config.port }))
    .then((addr) => console.log(`Aegis Auditor listening on ${addr}`))
    .catch((err) => {
      console.error(err);
      process.exit(1);
    });
}
