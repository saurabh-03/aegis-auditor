/** Authentication routes: email/password + Google/GitHub OAuth. */

import { randomBytes } from 'node:crypto';
import type { FastifyInstance } from 'fastify';
import { ACCESS_TTL, REFRESH_TTL, signJwt, verifyJwt } from '../auth/jwt.js';
import { hashPassword, verifyPassword } from '../auth/password.js';
import type { Store, User } from '../store/types.js';
import { getAuth } from './authctx.js';

interface Credentials {
  email?: string;
  password?: string;
  name?: string;
}

function issueTokens(user: User) {
  return {
    accessToken: signJwt({ sub: user.id, typ: 'access' }, ACCESS_TTL),
    refreshToken: signJwt({ sub: user.id, typ: 'refresh' }, REFRESH_TTL),
    expiresIn: ACCESS_TTL,
  };
}

function publicUser(u: User) {
  return { id: u.id, email: u.email, name: u.name };
}

const EMAIL_RE = /^[^@\s]+@[^@\s]+\.[^@\s]+$/;

export function registerAuthRoutes(app: FastifyInstance, store: Store): void {
  app.post<{ Body: Credentials }>('/api/auth/register', async (req, reply) => {
    const { email, password, name } = req.body ?? {};
    if (!email || !EMAIL_RE.test(email)) return reply.code(400).send({ error: 'invalid_email' });
    if (!password || password.length < 8) return reply.code(400).send({ error: 'weak_password', message: 'Minimum 8 characters.' });
    if (await store.getUserByEmail(email)) return reply.code(409).send({ error: 'email_taken' });

    const user = await store.createUser({ email, name: name ?? null, passwordHash: await hashPassword(password) });
    // Bootstrap a personal organization so the user can create projects immediately.
    await store.createOrganization(`${name ?? email.split('@')[0]}'s Org`, user.id);
    return reply.code(201).send({ user: publicUser(user), ...issueTokens(user) });
  });

  app.post<{ Body: Credentials }>('/api/auth/login', async (req, reply) => {
    const { email, password } = req.body ?? {};
    if (!email || !password) return reply.code(400).send({ error: 'missing_credentials' });
    const user = await store.getUserByEmail(email);
    if (!user || !user.passwordHash || !(await verifyPassword(password, user.passwordHash))) {
      return reply.code(401).send({ error: 'invalid_credentials' });
    }
    return reply.send({ user: publicUser(user), ...issueTokens(user) });
  });

  app.post<{ Body: { refreshToken?: string } }>('/api/auth/refresh', async (req, reply) => {
    const token = req.body?.refreshToken;
    if (!token) return reply.code(400).send({ error: 'missing_refresh_token' });
    const result = verifyJwt(token);
    if (!result.valid || !result.claims || result.claims.typ !== 'refresh') {
      return reply.code(401).send({ error: 'invalid_refresh_token', reason: result.reason });
    }
    const user = await store.getUserById(result.claims.sub);
    if (!user) return reply.code(401).send({ error: 'invalid_refresh_token' });
    return reply.send(issueTokens(user));
  });

  app.get('/api/auth/me', async (req, reply) => {
    const auth = getAuth(req);
    if (!auth) return reply.code(401).send({ error: 'unauthorized' });
    const user = await store.getUserById(auth.userId);
    if (!user) return reply.code(401).send({ error: 'unauthorized' });
    const orgs = await store.listOrganizationsForUser(user.id);
    return reply.send({ user: publicUser(user), organizations: orgs });
  });

  // ---------- OAuth (Google / GitHub) ----------
  // Requires provider client id/secret in env. Real flow; untestable without creds.
  const oauthStates = new Map<string, number>(); // state -> expiry ts

  const providers = {
    google: {
      authorize: 'https://accounts.google.com/o/oauth2/v2/auth',
      token: 'https://oauth2.googleapis.com/token',
      userinfo: 'https://openidconnect.googleapis.com/v1/userinfo',
      scope: 'openid email profile',
      idEnv: 'GOOGLE_CLIENT_ID',
      secretEnv: 'GOOGLE_CLIENT_SECRET',
    },
    github: {
      authorize: 'https://github.com/login/oauth/authorize',
      token: 'https://github.com/login/oauth/access_token',
      userinfo: 'https://api.github.com/user',
      scope: 'read:user user:email',
      idEnv: 'GITHUB_CLIENT_ID',
      secretEnv: 'GITHUB_CLIENT_SECRET',
    },
  } as const;

  app.get<{ Params: { provider: string } }>('/api/auth/oauth/:provider', async (req, reply) => {
    const p = providers[req.params.provider as keyof typeof providers];
    if (!p) return reply.code(404).send({ error: 'unknown_provider' });
    const clientId = process.env[p.idEnv];
    if (!clientId) return reply.code(501).send({ error: 'not_configured', message: `Set ${p.idEnv}/${p.secretEnv}.` });

    const state = randomBytes(16).toString('hex');
    oauthStates.set(state, Date.now() + 10 * 60_000);
    const redirectUri = `${req.protocol}://${req.headers.host}/api/auth/oauth/${req.params.provider}/callback`;
    const url = new URL(p.authorize);
    url.searchParams.set('client_id', clientId);
    url.searchParams.set('redirect_uri', redirectUri);
    url.searchParams.set('scope', p.scope);
    url.searchParams.set('response_type', 'code');
    url.searchParams.set('state', state);
    return reply.redirect(url.toString());
  });

  app.get<{ Params: { provider: string }; Querystring: { code?: string; state?: string } }>(
    '/api/auth/oauth/:provider/callback',
    async (req, reply) => {
      const p = providers[req.params.provider as keyof typeof providers];
      if (!p) return reply.code(404).send({ error: 'unknown_provider' });
      const { code, state } = req.query;
      if (!code || !state || !oauthStates.has(state)) return reply.code(400).send({ error: 'invalid_state' });
      oauthStates.delete(state);

      const clientId = process.env[p.idEnv];
      const clientSecret = process.env[p.secretEnv];
      if (!clientId || !clientSecret) return reply.code(501).send({ error: 'not_configured' });
      const redirectUri = `${req.protocol}://${req.headers.host}/api/auth/oauth/${req.params.provider}/callback`;

      // Exchange code for an access token.
      const tokenRes = await fetch(p.token, {
        method: 'POST',
        headers: { 'content-type': 'application/x-www-form-urlencoded', accept: 'application/json' },
        body: new URLSearchParams({ client_id: clientId, client_secret: clientSecret, code, redirect_uri: redirectUri, grant_type: 'authorization_code' }),
      });
      const tokenJson = (await tokenRes.json()) as { access_token?: string };
      if (!tokenJson.access_token) return reply.code(401).send({ error: 'oauth_exchange_failed' });

      // Fetch profile.
      const profRes = await fetch(p.userinfo, {
        headers: { authorization: `Bearer ${tokenJson.access_token}`, accept: 'application/json', 'user-agent': 'AegisAuditor' },
      });
      const profile = (await profRes.json()) as { sub?: string; id?: number; email?: string; name?: string; login?: string };
      const providerUserId = String(profile.sub ?? profile.id ?? '');
      const email = profile.email ?? `${profile.login ?? providerUserId}@users.noreply.${req.params.provider}.com`;
      if (!providerUserId) return reply.code(401).send({ error: 'oauth_no_identity' });

      let user = await store.getUserByOAuth(req.params.provider, providerUserId);
      if (!user) {
        user = (await store.getUserByEmail(email)) ?? (await store.createUser({ email, name: profile.name ?? profile.login ?? null }));
        await store.linkOAuth({ provider: req.params.provider as 'google' | 'github', providerUserId, userId: user.id });
        if ((await store.listOrganizationsForUser(user.id)).length === 0) {
          await store.createOrganization(`${profile.name ?? email.split('@')[0]}'s Org`, user.id);
        }
      }
      return reply.send({ user: publicUser(user), ...issueTokens(user) });
    },
  );
}
