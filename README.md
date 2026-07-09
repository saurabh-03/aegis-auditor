# Aegis Auditor

**Enterprise website security & scalability auditor — defensive, explain-everything, passive-by-default.**

Aegis analyzes a website and produces a professional audit across seven categories
(Security, Performance, Infrastructure, Scalability, SEO, Accessibility, Maintainability),
with an overall score out of 100. Every finding is **self-explaining**: severity, risk,
why it matters, technical detail, business impact, probability, OWASP/CVE mapping,
remediation, estimated fix time, example code, and references.

> This is **not** an exploitation tool. It performs no attacks and ships no offensive
> payloads. Intrusive ("active") checks run **only after explicit authorization** that
> you own or are permitted to test the target.

---

## What's in this repository

This repo contains a **working MVP core** plus the **full enterprise architecture** as
documentation. The MVP runs today; the docs describe how it scales to the complete
SaaS platform described in [`docs/ROADMAP.md`](docs/ROADMAP.md).

### Implemented and runnable now

- **Scanning engine** (`src/core`) — orchestrator, shared context, scoring, reporting.
- **15 passive modules** + **2 active (gated) modules** (`src/modules`) including performance,
  image optimization, and **dependency CVE intelligence** — see [`docs/MODULES.md`](docs/MODULES.md).
- **AI Security Advisor** (`src/ai`) — executive summary, prioritized actions, remediation
  checklist, OWASP grouping, and GitHub/Jira ticket export. Uses Claude when `ANTHROPIC_API_KEY`
  is set; deterministic local advisor otherwise.
- **Auth & multi-tenancy** (`src/auth`, `src/store`) — JWT (access+refresh) + Google/GitHub
  OAuth, password hashing (scrypt), organizations, teams, RBAC, projects with **verified
  ownership** gating active scans. See [`docs/AUTH.md`](docs/AUTH.md).
- **Persistence** (`src/store`) — `Store` interface with a `MemoryStore` (default) and a
  `PrismaStore` (PostgreSQL, activated by `DATABASE_URL`). See [`docs/DATABASE.md`](docs/DATABASE.md).
- **Async scans & live progress** (`src/queue`) — `POST /api/scans` → `202 { scanId }`,
  `WS /api/scans/:id/stream` streams per-module progress. `InProcessQueue` by default;
  `BullMqQueue` + standalone workers when `REDIS_URL` is set.
- **REST API** (`src/server.ts`) — public passive scan, auth, orgs/teams/projects,
  project-scoped scans, history, exports, rate limiting.
- **CLI** (`src/cli.ts`) — terminal scans with colorized output and md/json/csv export.
- **Next.js frontend** (`web/`) — App Router + TypeScript + Tailwind + Framer Motion:
  landing quick-scan, auth (login/register), dashboard with projects + ownership verification,
  **live async scans over WebSocket** with an animated progress bar, rich report views with the
  AI advisor panel, and Markdown/CSV/GitHub/Jira exports.
- **Legacy static dashboard** (`public/`) — dependency-free dark-mode SPA served by the API
  for quick passive scans (no build step).
- **Report exports** — Markdown, CSV, JSON, GitHub/Jira tickets.

### Designed (documented, ready to build out)

Next.js frontend, dependency-CVE intelligence, Lighthouse-grade performance module,
LLM advisor, PDF export, API keys/webhooks, K8s.
See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) and [`docs/ROADMAP.md`](docs/ROADMAP.md).

---

## Quickstart

```bash
npm install

# CLI — passive scan (safe against any site)
npm run scan -- example.com
npm run scan -- example.com --format md > report.md

# CLI — active scan (owner/authorized targets ONLY)
npm run scan -- your-own-site.com --active --authorized

# API + legacy static dashboard
npm run dev            # http://localhost:4000

# Next.js frontend (separate terminal; proxies /api → :4000)
cd web && npm install && npm run dev   # http://localhost:3200
```

Open <http://localhost:4000> for the built-in dashboard, or <http://localhost:3200> for the
full Next.js app (auth, projects, live scans). The Next app proxies HTTP `/api/*` to the
backend and streams scan progress over a WebSocket to the backend origin
(`NEXT_PUBLIC_WS_ORIGIN`, default `ws://localhost:4000`).

By default the API uses an in-memory store — no database required. To persist with
PostgreSQL, set `DATABASE_URL` and run migrations (see [`docs/DATABASE.md`](docs/DATABASE.md)).

### Authenticated flow (curl)

```bash
# register → returns accessToken
curl -sX POST localhost:4000/api/auth/register -H 'content-type: application/json' \
  -d '{"email":"you@example.com","password":"supersecret","name":"You"}'

# create a project, verify ownership (DNS TXT / .well-known), then run active scans
#   POST /api/orgs/:orgId/projects   → { verification: { token, instructions } }
#   POST /api/projects/:id/verify
#   POST /api/projects/:id/scans     { "includeActive": true }
```

### Example (real output)

```
Overall Score: 83/100 (B)

  security         █████████░░░░░░░░░░░░  46  F
  performance      ████████████████████ 100  A+
  infrastructure   ████████████████████ 100  A+
  ...
  2 high  1 medium  9 low  17 passing
```

---

## Safety & responsible use

- **Passive by default.** Header/TLS/DNS/HTML analysis uses ordinary, non-intrusive requests.
- **Active checks are gated.** Port scanning and sensitive-file/admin discovery require both
  `authorized: true` and an explicit opt-in; the UI shows a confirmation dialog first.
- **No exploitation.** Aegis reports *evidence of misconfiguration*, never runs exploits,
  and never claims a vulnerability without observed evidence.
- **Rate limited & logged.** The API applies per-IP rate limiting and structured logging.

See [`docs/SECURITY.md`](docs/SECURITY.md) for the full security & ethics model.

## Project layout

```
src/
  core/        types, config, http, scoring, scanner (engine)
  modules/     one file per audit module (+ active/ for gated modules)
  report/      markdown & csv renderers
  api/         in-memory store + rate limiter
  server.ts    Fastify API + static dashboard
  cli.ts       terminal entrypoint
public/        dashboard SPA (index.html, app.js, styles.css)
prisma/        production schema (documented target state)
docs/          architecture, database, API, roadmap, deployment, modules, security
```

## License

Provided as-is for defensive security use. Do not use against systems you do not own or
lack written authorization to test.
