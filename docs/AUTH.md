# Authentication & Authorization

## Tokens

- **Access token** — HS256 JWT, 15-minute TTL, `{ sub: userId, typ: "access" }`. Sent as
  `Authorization: Bearer <token>`.
- **Refresh token** — HS256 JWT, 30-day TTL, `typ: "refresh"`. Exchanged at
  `POST /api/auth/refresh` for a new access token.
- Signed with `JWT_SECRET` (set it in production — the dev default is insecure).
- Implemented dependency-free with Node `crypto` (`src/auth/jwt.ts`). Swap for a vetted
  library if you need RS256/asymmetric keys.

Passwords are hashed with Node `scrypt` (salt-per-password, constant-time compare;
`src/auth/password.ts`).

## Email/password flow

```
POST /api/auth/register {email,password,name}
  → creates user, bootstraps a personal Organization (role OWNER)
  → 201 { user, accessToken, refreshToken }

POST /api/auth/login {email,password}      → 200 { user, accessToken, refreshToken }
POST /api/auth/refresh {refreshToken}      → 200 { accessToken, refreshToken }
GET  /api/auth/me           (Bearer)       → { user, organizations:[{...,role}] }
```

## OAuth (Google / GitHub)

```
GET /api/auth/oauth/:provider            → 302 redirect to provider consent
GET /api/auth/oauth/:provider/callback   → exchanges code, upserts user,
                                           links OAuthAccount, issues tokens
```

State is CSRF-protected with a random, short-lived `state` value. Requires
`GOOGLE_CLIENT_ID`/`GOOGLE_CLIENT_SECRET` or `GITHUB_CLIENT_ID`/`GITHUB_CLIENT_SECRET`;
absent creds return `501 not_configured`.

## Authorization (RBAC)

Roles are ordered `VIEWER < MEMBER < ADMIN < OWNER` (`src/auth/rbac.ts`).

| Capability | Minimum role |
|------------|--------------|
| Read scans/reports | VIEWER |
| Create projects, run project scans | MEMBER |
| Invite members, create teams | ADMIN |
| (org creation makes the creator) | OWNER |

Every org-scoped route resolves the caller's `Membership` and enforces the required role;
non-members get `403`.

## Active-scan authorization gate

Active (intrusive) scans are gated by **verified project ownership**, not just a checkbox:

1. Create a project → receive an `ownershipToken`.
2. Prove control by publishing the token (`src/auth/ownership.ts`):
   - **DNS**: `TXT aegis-verify=<token>` on the target, or
   - **File**: serve `<token>` at `https://<target>/.well-known/aegis-verify`.
3. `POST /api/projects/:id/verify` flips `verifiedAt`.
4. Only then does `POST /api/projects/:id/scans { includeActive: true }` run active modules.

The public `POST /api/scan` endpoint refuses active checks entirely
(`403 active_requires_project`) — see [SECURITY.md](SECURITY.md).
