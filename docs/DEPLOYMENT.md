# Deployment Guide

## Local development

```bash
# Backend (API + legacy static dashboard)
npm install
npm run dev          # http://localhost:4000
npm run scan -- example.com
npm run typecheck

# Next.js frontend (separate terminal)
cd web && npm install
npm run dev          # http://localhost:3200  (proxies /api → :4000)
npm run build        # production build (type-checks all routes)
```

The frontend reads two settings: `API_ORIGIN` (server-side HTTP proxy target, default
`http://localhost:4000`) and `NEXT_PUBLIC_WS_ORIGIN` (browser WebSocket origin, default
`ws://localhost:4000`). In production, point both at your API and deploy the Next app
(e.g. Vercel or a Node server) alongside the API + worker services.

## Environment variables

See [`.env.example`](../.env.example). Key ones:

| Var | Default | Purpose |
|-----|---------|---------|
| `PORT` | `4000` | HTTP port |
| `HOST` | `0.0.0.0` | Bind address |
| `SCAN_TIMEOUT_MS` | `12000` | Per-request network timeout |
| `USER_AGENT` | Aegis UA | Outbound User-Agent |
| `RATE_LIMIT_WINDOW_MS` | `60000` | Rate-limit window |
| `RATE_LIMIT_MAX` | `20` | Max scans per window per IP |
| `LOG_LEVEL` | `info` | pino log level |
| `DATABASE_URL` | — | Postgres (Phase 1+) |
| `REDIS_URL` | — | Redis/BullMQ (Phase 2+) |

## Docker

Build and run the single-process app:

```bash
docker build -t aegis-auditor .
docker run -p 4000:4000 aegis-auditor
```

## Docker Compose (with Postgres + Redis for Phase 1+)

```bash
docker compose up --build
```

`docker-compose.yml` brings up:
- `api` — the Fastify app (this repo).
- `postgres` — persistence (used once Phase 1 wires Prisma).
- `redis` — queue backend (used once Phase 2 wires BullMQ).

- `worker` — scan worker(s) processing the BullMQ queue (`node dist/worker.js`).

The `api` service runs with `AEGIS_ROLE=api` (enqueue only) and the `worker` service with
`AEGIS_ROLE=worker`. Scale workers horizontally:

```bash
docker compose up --scale worker=3
```

Without `REDIS_URL`, the API runs scans in-process (no separate worker needed) — ideal for
single-node or local use. WebSocket live progress (`/api/scans/:id/stream`) works in both modes.

## Production build

```bash
npm run build        # tsc → dist/
node dist/server.js
```

The Dockerfile does a multi-stage build (deps → build → slim runtime) and runs as a
non-root user with a `HEALTHCHECK` hitting `/health`.

## CI/CD (GitHub Actions)

`.github/workflows/ci.yml` (template) runs on every push/PR:

1. `npm ci`
2. `npm run typecheck`
3. `npm test`
4. `npm run build`
5. Build & push the Docker image (on `main`).
6. Deploy (environment-specific; e.g. `docker compose pull && up -d`, or `kubectl rollout`).

## Kubernetes (Phase 5)

- `api` Deployment + Service + Ingress (TLS).
- `scan-worker` Deployment with **HPA on queue depth** (KEDA + Redis scaler).
- `postgres` (managed / StatefulSet) and `redis` (managed / Sentinel).
- `ServiceMonitor` for Prometheus; liveness `/health`, readiness `/health`.
- Secrets via sealed-secrets / external-secrets; config via ConfigMap.

## Monitoring & health

- `GET /health` — liveness/readiness (implemented).
- `/metrics` — Prometheus (Phase 2): scan duration histograms, queue depth, error rate.
- Structured JSON logs to stdout (pino) for aggregation (Loki/ELK/Datadog).
