/**
 * Org-level webhook management.
 *   POST   /api/orgs/:orgId/webhooks   { url, events? }  → returns signing secret ONCE
 *   GET    /api/orgs/:orgId/webhooks
 *   DELETE /api/webhooks/:id
 *   POST   /api/webhooks/:id/test      send a signed test ping
 *
 * Deliveries are POSTed with an `x-aegis-signature: sha256=<hmac>` header the
 * receiver verifies with the secret. Managing webhooks requires ADMIN+.
 */

import { randomBytes } from 'node:crypto';
import type { FastifyInstance } from 'fastify';
import { CAN } from '../auth/rbac.js';
import { fireWebhook } from '../schedule/alerts.js';
import type { Store, WebhookEvent } from '../store/types.js';
import { requireAuth } from './authctx.js';

const VALID_EVENTS: WebhookEvent[] = ['regression', 'scan_complete'];

export function registerWebhookRoutes(app: FastifyInstance, store: Store): void {
  app.post<{ Params: { orgId: string }; Body: { url?: string; events?: string[] } }>('/api/orgs/:orgId/webhooks', async (req, reply) => {
    const auth = requireAuth(req, reply);
    if (!auth) return;
    const membership = await store.getMembership(auth.userId, req.params.orgId);
    if (!membership || !CAN.manageOrg(membership.role)) return reply.code(403).send({ error: 'forbidden' });

    const url = (req.body?.url ?? '').trim();
    const isHttps = /^https:\/\//i.test(url);
    const isLocal = /^http:\/\/(localhost|127\.0\.0\.1)(:\d+)?(\/|$)/i.test(url);
    if (!isHttps && !isLocal) {
      return reply.code(400).send({ error: 'invalid_url', message: 'Webhook URL must be https:// (http is allowed only for localhost).' });
    }
    const events = (req.body?.events ?? ['regression']).filter((e): e is WebhookEvent => VALID_EVENTS.includes(e as WebhookEvent));
    if (events.length === 0) return reply.code(400).send({ error: 'invalid_events', message: `events must include one of ${VALID_EVENTS.join(', ')}` });

    const secret = 'whsec_' + randomBytes(24).toString('base64url');
    const webhook = await store.createWebhook({ orgId: req.params.orgId, url, events, secret });
    return reply.code(201).send({ webhook, secret }); // secret shown once
  });

  app.get<{ Params: { orgId: string } }>('/api/orgs/:orgId/webhooks', async (req, reply) => {
    const auth = requireAuth(req, reply);
    if (!auth) return;
    const membership = await store.getMembership(auth.userId, req.params.orgId);
    if (!membership || !CAN.manageOrg(membership.role)) return reply.code(403).send({ error: 'forbidden' });
    return reply.send({ webhooks: await store.listWebhooks(req.params.orgId) });
  });

  app.delete<{ Params: { id: string } }>('/api/webhooks/:id', async (req, reply) => {
    const auth = requireAuth(req, reply);
    if (!auth) return;
    const wh = await store.getWebhook(req.params.id);
    if (!wh) return reply.code(404).send({ error: 'not_found' });
    const membership = await store.getMembership(auth.userId, wh.orgId);
    if (!membership || !CAN.manageOrg(membership.role)) return reply.code(403).send({ error: 'forbidden' });
    await store.deleteWebhook(req.params.id);
    return reply.code(204).send();
  });

  app.post<{ Params: { id: string } }>('/api/webhooks/:id/test', async (req, reply) => {
    const auth = requireAuth(req, reply);
    if (!auth) return;
    const wh = await store.getWebhook(req.params.id);
    if (!wh) return reply.code(404).send({ error: 'not_found' });
    const membership = await store.getMembership(auth.userId, wh.orgId);
    if (!membership || !CAN.manageOrg(membership.role)) return reply.code(403).send({ error: 'forbidden' });
    const hooks = await store.webhooksForEvent(wh.orgId, wh.events[0] ?? 'regression');
    const full = hooks.find((h) => h.id === wh.id);
    await fireWebhook(wh.url, { event: 'test', message: 'Aegis webhook test ping', at: new Date().toISOString() }, full?.secret);
    return reply.send({ ok: true, delivered: wh.url });
  });
}
