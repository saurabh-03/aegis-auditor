# Architecture

Aegis is designed as a production SaaS with a clean separation between the **scan engine**
(pure domain logic), the **delivery layer** (API/CLI/dashboard), and the **platform**
(auth, persistence, queue, workers). The MVP in this repo implements the engine and a
single-process delivery layer; the platform pieces are documented here as the target state.

## 1. High-level system

```
                         ┌──────────────────────────────────────────┐
                         │              Frontend (Next.js)           │
                         │  Dashboard · Issue Explorer · Reports     │
                         │  Auth (JWT/OAuth) · WebSocket live scans  │
                         └───────────────┬──────────────────────────┘
                                         │ REST / WS
                         ┌───────────────▼──────────────────────────┐
                         │            API Gateway (Fastify)          │
                         │  AuthN/Z · Rate limit · Validation · RBAC │
                         └──────┬───────────────────────┬───────────┘
                                │ enqueue               │ read
                    ┌───────────▼──────────┐   ┌────────▼─────────┐
                    │   Queue (BullMQ)     │   │  PostgreSQL      │
                    │   Redis-backed       │   │  (Prisma ORM)    │
                    └───────────┬──────────┘   └────────▲─────────┘
                                │ jobs                  │ persist
                    ┌───────────▼───────────────────────┴─────────┐
                    │              Scan Workers (N)                │
                    │   Aegis Engine · Modules · Scoring · Report  │
                    │   AI Advisor · CVE intelligence              │
                    └──────────────────────────────────────────────┘
```

### Design principles

- **Hexagonal / ports-and-adapters.** The engine (`src/core`) depends on nothing but Node
  built-ins and the module contract. API, CLI, queue, and DB are adapters around it.
- **SOLID.** Each module is a single-responsibility unit implementing the `ScanModule`
  interface (open/closed: add modules without touching the orchestrator).
- **Strong typing.** `strict` TypeScript with `noUncheckedIndexedAccess`. All domain
  shapes live in `src/core/types.ts`.
- **Fault isolation.** One module throwing never aborts a scan (`scanner.ts` wraps each run).
- **Explainability is a contract.** The `Finding` type *requires* the explanatory fields, so
  a module physically cannot emit "Missing CSP" without the full narrative.

## 2. Scan engine (implemented)

`src/core/scanner.ts` builds a shared `ScanContext`:

- a single, cached homepage fetch (`getPage()`) shared by all modules — avoids N fetches;
- a timeout-bounded `fetch` helper;
- authorization + options.

It then:

1. Selects eligible modules, **enforcing the passive/active gate** (active requires
   `authorized && includeActive`).
2. Runs modules concurrently with per-module isolation.
3. Aggregates findings → `scoring.ts` computes category and weighted overall scores.
4. Assembles an `AuditReport` with per-module structured `data` for visualizations.

### Module contract

```ts
interface ScanModule {
  name: string;
  title: string;
  category: Category;
  mode: 'passive' | 'active';
  description: string;
  run(ctx: ScanContext): Promise<ModuleResult>;
}
```

Adding a module = create a file in `src/modules`, implement `run`, register it in
`registry.ts`. No engine changes.

### Scoring

Each category starts at 100. Failing findings subtract `SEVERITY_WEIGHT` (warnings apply
half). The overall score is a **weighted mean** of categories that actually ran
(`CATEGORY_WEIGHTS` in `scoring.ts`), so a partial scan is not unfairly penalized.

## 3. Backend / API (implemented as single-process; scales to gateway + workers)

- **Fastify** for the HTTP API (`src/server.ts`): low overhead, schema-friendly, great
  plugin ecosystem (`@fastify/cors`, `@fastify/static`, `@fastify/websocket`).
- Scans run through a **queue abstraction** (`src/queue`): `POST /api/scans` enqueues and
  returns `202 { scanId }`, and clients stream progress over `WS /api/scans/:id/stream`.
  `InProcessQueue` (default) runs jobs in the API process; `BullMqQueue` (when `REDIS_URL`
  is set) distributes them to `dist/worker.js` processes and fans progress out over a Redis
  pub/sub channel so any API node can serve the WebSocket. The engine and job logic
  (`src/queue/runner.ts`) are identical for both backends — only the adapter changes.

### Target microservices

| Service        | Responsibility                                             |
| -------------- | ---------------------------------------------------------- |
| `api-gateway`  | Auth, RBAC, validation, rate limiting, enqueue, read APIs  |
| `scan-worker`  | Runs the engine per job; horizontally scalable             |
| `cve-worker`   | Enriches technology findings against NVD/GHSA (cached)     |
| `report-worker`| PDF rendering, scheduled/recurring scans                   |
| `notifier`     | Email/Slack/webhook delivery                               |

## 4. Queue design (BullMQ + Redis)

- **Queues:** `scan`, `cve-enrich`, `report-render`, `notify`.
- **Job:** `{ scanId, target, options, orgId, userId }`.
- **Concurrency:** per-worker concurrency tuned to network I/O (scans are I/O-bound).
- **Reliability:** exponential backoff, max attempts, dead-letter queue, idempotency key =
  `scanId`.
- **Rate & politeness:** per-target token bucket so one worker fleet never hammers a host;
  respects a global outbound RPS budget.
- **Progress:** workers emit `job.updateProgress()`; the gateway relays to the client WS.

## 5. Frontend architecture (Next.js app implemented + legacy SPA)

Two frontends ship:

- **`web/` — Next.js App Router app** (TypeScript + Tailwind + Framer Motion). Routes: `/`
  (landing quick-scan), `/login`, `/register`, `/dashboard` (projects, ownership verification,
  live async scans), `/report/[id]` (shareable report). A `useScanStream` hook subscribes to
  the backend's progress WebSocket; `lib/api.ts` is the typed API client. HTTP `/api/*` is
  rewritten to the backend (same-origin, no CORS); the WebSocket connects directly to the
  backend origin (`NEXT_PUBLIC_WS_ORIGIN`) since WS upgrades don't proxy through Next rewrites.
  An `AuthProvider` context holds the JWT (localStorage) and current user/orgs.
- **`public/` — legacy dependency-free SPA** served by the API for zero-build quick scans.

Still to add (Phase 4 continuation): shadcn/ui component layer, chart-based explorers
(trend lines, waterfalls, cert timelines), report personas, and PDF export.

## 6. Authentication & authorization

- **JWT** access tokens (short-lived) + rotating refresh tokens (httpOnly, Secure, SameSite).
- **OAuth** (Google, GitHub) via provider redirect → account link.
- **Organizations & Teams**: users belong to orgs; RBAC roles `owner`, `admin`, `member`,
  `viewer`. Scans and reports are org-scoped.
- **API keys** for programmatic access, scoped per org with per-key rate limits.
- **Target ownership**: active scans require a verified ownership claim (DNS TXT token or a
  `.well-known/aegis-verify` file) recorded on the `Project`.

See [`docs/AUTH.md`](AUTH.md) for the flow diagrams.

## 7. Security architecture

- Passive/active separation enforced in the engine, not just the UI.
- SSRF protection on the worker: block requests to RFC1918/link-local/metadata IPs unless the
  target is a verified private-network engagement.
- Output encoding everywhere; findings never reflect raw secrets (JS module redacts matches).
- Full audit log of who scanned what, when, and under which authorization.

## 8. Observability

- Structured JSON logs (pino via Fastify).
- Health (`/health`) + readiness; Prometheus metrics (`/metrics`) for scan durations, queue
  depth, error rates.
- OpenTelemetry traces spanning gateway → queue → worker.
