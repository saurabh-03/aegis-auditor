/** Request-auth helpers: extract and require an authenticated user from a Bearer token. */

import type { FastifyReply, FastifyRequest } from 'fastify';
import { verifyJwt } from '../auth/jwt.js';

export interface AuthedUser {
  userId: string;
}

/** Returns the authenticated userId, or null if no/invalid access token. */
export function getAuth(req: FastifyRequest): AuthedUser | null {
  const header = req.headers.authorization;
  if (!header || !header.startsWith('Bearer ')) return null;
  const token = header.slice(7).trim();
  const result = verifyJwt(token);
  if (!result.valid || !result.claims || result.claims.typ !== 'access') return null;
  return { userId: result.claims.sub };
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
