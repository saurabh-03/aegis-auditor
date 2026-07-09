# Development Roadmap — MVP → Enterprise

A phased plan taking Aegis from the current runnable core to the full enterprise SaaS.
Each phase is shippable and builds on the last.

## Phase 0 — Core engine ✅ (this repo)

- Scan orchestrator, shared context, scoring, reporting.
- 12 passive modules + 2 active (gated) modules.
- REST API, CLI, dashboard SPA, md/csv/json exports.
- Passive/active authorization gate enforced in the engine.

**Exit criteria:** `npm run scan -- <site>` and the dashboard produce a scored, fully-explained
report. _(Met.)_

## Phase 1 — Persistence & accounts (MVP SaaS)

- PostgreSQL + Prisma (swap `src/api/store.ts` for the schema in `prisma/schema.prisma`).
- JWT auth + Google/GitHub OAuth; organizations, teams, RBAC.
- Projects (targets) with **ownership verification** (DNS TXT / `.well-known`) unlocking active scans.
- Scan history + trend charts per project.
- Docker Compose for local (api + postgres + redis).

**Exit criteria:** multiple users/orgs, saved scans, login, verified-ownership active scans.

## Phase 2 — Async workers & scale ✅

- Queue abstraction (`src/queue`): `InProcessQueue` (default) + `BullMqQueue` (Redis).
- `POST /api/scans` enqueues → `202 { scanId }`; `WS /api/scans/:id/stream` streams per-module
  live progress; `GET /api/scans/:id` returns status/result.
- Standalone worker entrypoint (`src/worker.js`, `AEGIS_ROLE=worker`) for horizontal scaling;
  Redis pub/sub fans progress across API nodes. Docker Compose runs api + worker(s).
- Still to layer in: per-target politeness rate limiting, SSRF guard, Prometheus metrics,
  OpenTelemetry tracing.

**Exit criteria (met):** scans run off the request path; live progress over WebSockets;
workers scale horizontally (`docker compose up --scale worker=N`).

## Phase 3 — Depth: performance, CVE, AI ✅ (browser-CWV pending)

- **Performance module** (`performance.ts`) — passive signals: render-blocking resources,
  document weight, TTFB, resource counts, preconnect hints. **Image module** (`images.ts`) —
  formats (WebP/AVIF), lazy loading, dimensions/CLS, responsive srcset.
- **Dependency Intelligence** (`dependencies.ts` + `src/intel`) — offline curated CVE dataset
  with a semver matcher; attaches concrete CVEs + CVSS to detected component versions.
- **AI Advisor** (`src/ai`) — `LocalAdvisor` (offline) + `AnthropicAdvisor` (Claude, with
  fallback): executive summaries, prioritized actions, remediation checklists, OWASP grouping,
  and GitHub/Jira ticket generation.

**Exit criteria (met):** reports include concrete CVEs and AI-written summaries/tickets.
**Remaining:** lab Core Web Vitals (LCP/CLS/INP) via a headless-Chrome worker — needs a
browser runtime, tracked as a Phase 3 continuation.

## Phase 4 — Next.js frontend & reporting suite ✅ (core; rich explorers pending)

- **Next.js App Router app** (`web/`) with TypeScript + Tailwind + Framer Motion: landing
  quick-scan, auth (login/register + OAuth links), dashboard with projects and ownership
  verification, **live async scans over WebSocket** with animated progress, report views with
  the AI advisor panel, and Markdown/CSV/GitHub/Jira exports. Shareable report URLs
  (`/report/[id]`). Verified end-to-end; `next build` passes.
- **Remaining (rich-visualization suite):** dedicated CVE/OWASP explorers, technology graph,
  infrastructure map, SSL-certificate timeline, performance waterfall, cookie/DNS/header
  inspectors; report personas (Exec/Dev/Security/Management/Compliance); PDF export;
  scheduled/recurring scans; historical-comparison trend charts. (shadcn/ui can be layered in;
  the current app uses Tailwind primitives directly.)

**Exit criteria (met for core):** authenticated app with live scans, shareable report links,
AI advisor, and ticket exports.

## Phase 5 — Enterprise & platform

- API keys, webhooks, GraphQL (optional), SSO/SAML, SCIM provisioning.
- Kubernetes deploy (HPA on queue depth), multi-region workers, geo distribution.
- Compliance report packs (PCI-DSS / SOC 2 / GDPR mapping), audit-log export.
- SLA, alerting, on-call runbooks.

**Exit criteria:** enterprise procurement-ready: SSO, RBAC, webhooks, K8s, compliance packs.

---

## Testing strategy (per phase)

- **Unit** — modules against recorded HTTP/TLS/DNS fixtures (deterministic).
- **Integration** — engine end-to-end against a controlled fixture site in CI.
- **API** — supertest/contract tests for every endpoint incl. auth & rate limits.
- **E2E** — Playwright drives the dashboard through a scan and export.
- **Security** — the app is dogfooded: Aegis scans its own preview deployment in CI;
  dependency and secret scanning (npm audit, gitleaks) gate merges.
- **Performance** — k6 load tests on the API + worker throughput benchmarks.
- **Accessibility** — axe-core on dashboard routes.
