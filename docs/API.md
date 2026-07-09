# API Specification

Base URL (dev): `http://localhost:4000`

All request/response bodies are JSON unless noted. The MVP endpoints below are
**implemented**; endpoints marked _(planned)_ are part of the documented target and
map to the Prisma schema in [`../prisma/schema.prisma`](../prisma/schema.prisma).

## Conventions

- **Auth** _(planned)_: `Authorization: Bearer <jwt>` or `X-Api-Key: <key>`.
- **Rate limiting** _(implemented)_: fixed window per IP; `X-RateLimit-Remaining` header;
  `429 { error: "rate_limited", resetAt }` when exceeded.
- **Errors**: `{ "error": "<code>", "message"?: "<human text>" }` with an appropriate status.
- **Pagination** _(implemented on list endpoints)_: `?limit=&offset=`.

---

## Implemented endpoints

### `GET /health`
Liveness probe. → `200 { status: "ok", engine, uptime }`

### `GET /api/modules`
Lists the module catalog.
```json
{ "modules": [ { "name": "ssl", "title": "SSL / TLS Analysis", "category": "security", "mode": "passive", "description": "…" } ] }
```

### `POST /api/scan`
Runs an ad-hoc **passive** audit and returns the full report. Active checks are refused here
(they require a verified project — see below).

Request:
```json
{
  "target": "example.com",
  "only": ["ssl","csp"],      // optional module allow-list
  "skip": ["cors"]            // optional module deny-list
}
```

Responses:
- `200 { id, report }` — see the `AuditReport` shape in `src/core/types.ts`.
- `400 { error: "missing_target" | "invalid_target" }`
- `403 { error: "active_requires_project" }` — `includeActive` requested on the public endpoint.
- `429 { error: "rate_limited", resetAt }`

### `GET /api/reports?limit=&offset=`
Recent stored reports. → `{ total, items: [{ id, createdAt, target, score }] }`

### `GET /api/reports/:id`
Full stored `AuditReport` JSON. `404` if unknown.

### `GET /api/reports/:id/report.md`
Markdown export (`text/markdown`).

### `GET /api/reports/:id/report.csv`
CSV export (`text/csv`, attachment) — one row per finding.

### `GET /api/reports/:id/advisor`
AI Security Advisor output: `{ provider, model?, executiveSummary, prioritizedActions[],
remediationChecklist[], groups[] }`. Uses Claude when `ANTHROPIC_API_KEY` is set, else the
deterministic local advisor.

### `GET /api/reports/:id/tickets?format=github|jira`
Generates issue-tracker tickets from actionable findings:
`{ format, tickets: [{ title, body, labels[], severity }] }`.

### `GET /api/history?target=example.com`
Score history for a target (for trend charts).
→ `{ target, history: [{ id, createdAt, score }] }`

---

## Auth & multi-tenancy endpoints (implemented)

Full details in [AUTH.md](AUTH.md). All non-auth routes require `Authorization: Bearer <access>`.

```
POST   /api/auth/register              email+password signup → { user, accessToken, refreshToken }
POST   /api/auth/login                 → { user, accessToken, refreshToken }
POST   /api/auth/refresh               rotate refresh → { accessToken, refreshToken }
GET    /api/auth/me                    caller profile + organizations
GET    /api/auth/oauth/:provider       start Google/GitHub OAuth (302)
GET    /api/auth/oauth/:provider/callback   OAuth callback → tokens

GET    /api/orgs                       list caller's orgs
POST   /api/orgs                       create org (caller becomes OWNER)
POST   /api/orgs/:orgId/members        add member (ADMIN+)          {email, role}
GET    /api/orgs/:orgId/teams          list teams
POST   /api/orgs/:orgId/teams          create team (ADMIN+)         {name}
GET    /api/orgs/:orgId/projects       list projects
POST   /api/orgs/:orgId/projects       create project (MEMBER+)     {name, target}
                                       → { project, verification: { token, instructions } }
GET    /api/orgs/:orgId/scans          org scan history (paginated)

POST   /api/projects/:id/verify        verify ownership (DNS TXT / .well-known)
POST   /api/projects/:id/scans         run scan SYNCHRONOUSLY (MEMBER+); active requires ownership
                                       {includeActive?, only?, skip?} → { scanId, report }
GET    /api/projects/:id/history       score history for trend charts
```

## Async scans & live progress (implemented — Phase 2)

Scans run on a queue (`InProcessQueue` by default, `BullMqQueue` when `REDIS_URL` is set).

```
POST /api/scans                        enqueue a scan → 202 { scanId, status, stream }
  body: { target } | { projectId }, optional { includeActive, only, skip }
  - target-only: passive; active is refused (needs a verified project)
  - projectId: MEMBER+ membership; active requires verified ownership

GET  /api/scans/:id                    { status: QUEUED|RUNNING|COMPLETED|FAILED, report? }
                                       (report present once COMPLETED; access-controlled)

WS   /api/scans/:id/stream?token=<jwt> live progress events (browsers pass the access
                                       token via query since WS can't set headers)
```

Progress event shape (`src/queue/types.ts`):
```json
{ "scanId":"…", "type":"module", "module":"ssl", "moduleOk":true, "progress":0.5, "at":"…" }
```
`type` is one of `queued | running | module | completed | failed`; `completed` carries
`overall` and `grade`.

## Planned endpoints (target state)

```
GET    /api/scans/:id/report.pdf       PDF export                            (Phase 4)
POST   /api/keys                       create API key (shown once)           (Phase 5)
DELETE /api/keys/:id                   revoke                                (Phase 5)
POST   /api/webhooks                   register webhook (events)             (Phase 5)
```

### Webhook payload (planned)
```json
{
  "event": "scan.completed",
  "scanId": "…",
  "orgId": "…",
  "overall": 83,
  "grade": "B",
  "critical": 0, "high": 2,
  "reportUrl": "https://app/…",
  "signature": "sha256=…"   // HMAC of body with webhook secret
}
```

## Integration exports (planned)

- **Jira**: `POST /api/scans/:id/export/jira` → creates issues per finding (severity → priority).
- **GitHub**: `POST /api/scans/:id/export/github` → opens issues with remediation + example code.
