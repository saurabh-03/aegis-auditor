/** Request-auth helpers: authenticate a request via Bearer token or API key. */

import type { FastifyReply, FastifyRequest } from 'fastify';
import { verifyJwt } from '../auth/jwt.js';
import { hashApiKey, looksLikeApiKey } from '../auth/apikey.js';
import type { Store } from '../store/types.js';

export interface AuthedUser {
  userId: string;
  /** How the request authenticated. */
  via?: 'jwt' | 'apikey';
}

/** Returns the authenticated userId from a Bearer access token, or null. */
export function getAuth(req: FastifyRequest): AuthedUser | null {
  const header = req.headers.authorization;
  if (!header || !header.startsWith('Bearer ')) return null;
  const token = header.slice(7).trim();
  const result = verifyJwt(token);
  if (!result.valid || !result.claims || result.claims.typ !== 'access') return null;
  return { userId: result.claims.sub, via: 'jwt' };
}

/** Sends 401 and returns null when unauthenticated; otherwise returns the user. */
export function requireAuth(req: FastifyRequest, reply: FastifyReply): AuthedUser | null {
  const auth = getAuth(req);
  if (!auth) {
    reply.code(401).send({ error: 'unauthorized', message: 'Provide a valid Bearer access token.' });
    return null;
  }
  return auth;
}

/**
 * Authenticate via Bearer token OR `X-Api-Key` header (async — API keys require
 * a store lookup). A valid, non-revoked key authenticates as its creator so
 * existing org-membership checks apply unchanged; last-used is updated.
 */
export async function resolveAuth(req: FastifyRequest, store: Store): Promise<AuthedUser | null> {
  const bearer = getAuth(req);
  if (bearer) return bearer;

  const raw = req.headers['x-api-key'];
  const key = Array.isArray(raw) ? raw[0] : raw;
  if (key && looksLikeApiKey(key)) {
    const rec = await store.getApiKeyByHash(hashApiKey(key));
    if (rec && !rec.revokedAt) {
      void store.touchApiKey(rec.id);
      return { userId: rec.userId, via: 'apikey' };
    }
  }
  return null;
}

/** Async variant of requireAuth that also accepts API keys. */
export async function requireAuthAsync(
  req: FastifyRequest,
  reply: FastifyReply,
  store: Store,
): Promise<AuthedUser | null> {
  const auth = await resolveAuth(req, store);
  if (!auth) {
    reply.code(401).send({ error: 'unauthorized', message: 'Provide a valid Bearer access token or X-Api-Key.' });
    return null;
  }
  return auth;
}
