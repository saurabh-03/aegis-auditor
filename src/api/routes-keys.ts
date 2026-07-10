/**
 * API key management (authenticated with a user session; keys manage keys is
 * not allowed). Keys are org-scoped and act on behalf of their creator.
 *   POST   /api/orgs/:orgId/keys   { name }   → returns the plaintext key ONCE
 *   GET    /api/orgs/:orgId/keys              → list (no secrets)
 *   DELETE /api/keys/:id                       → revoke
 *
 * Managing keys requires ADMIN+ (CAN.manageOrg).
 */

import type { FastifyInstance } from 'fastify';
import { generateApiKey } from '../auth/apikey.js';
import { CAN } from '../auth/rbac.js';
import type { Store } from '../store/types.js';
import { requireAuth } from './authctx.js';

export function registerKeyRoutes(app: FastifyInstance, store: Store): void {
  // Create a key — plaintext is returned exactly once.
  app.post<{ Params: { orgId: string }; Body: { name?: string } }>('/api/orgs/:orgId/keys', async (req, reply) => {
    const auth = requireAuth(req, reply);
    if (!auth) return;
    // API keys must be created with a user session, never with another key.
    if (auth.via === 'apikey') return reply.code(403).send({ error: 'session_required', message: 'Create API keys from a signed-in session.' });
    const membership = await store.getMembership(auth.userId, req.params.orgId);
    if (!membership || !CAN.manageOrg(membership.role)) return reply.code(403).send({ error: 'forbidden', message: 'Admin role required to manage API keys.' });

    const name = (req.body?.name ?? '').trim() || 'API key';
    const gen = generateApiKey();
    const key = await store.createApiKey({
      orgId: req.params.orgId,
      userId: auth.userId,
      name,
      hashedKey: gen.hashedKey,
      keyPrefix: gen.keyPrefix,
    });
    // `key` (plaintext) is shown once; the client must store it now.
    return reply.code(201).send({ apiKey: key, key: gen.plaintext });
  });

  // List keys (metadata only — never the secret).
  app.get<{ Params: { orgId: string } }>('/api/orgs/:orgId/keys', async (req, reply) => {
    const auth = requireAuth(req, reply);
    if (!auth) return;
    const membership = await store.getMembership(auth.userId, req.params.orgId);
    if (!membership || !CAN.manageOrg(membership.role)) return reply.code(403).send({ error: 'forbidden' });
    return reply.send({ keys: await store.listApiKeys(req.params.orgId) });
  });

  // Revoke a key.
  app.delete<{ Params: { id: string } }>('/api/keys/:id', async (req, reply) => {
    const auth = requireAuth(req, reply);
    if (!auth) return;
    const key = await store.getApiKey(req.params.id);
    if (!key) return reply.code(404).send({ error: 'not_found' });
    const membership = await store.getMembership(auth.userId, key.orgId);
    if (!membership || !CAN.manageOrg(membership.role)) return reply.code(403).send({ error: 'forbidden' });
    await store.revokeApiKey(req.params.id);
    return reply.code(204).send();
  });
}
