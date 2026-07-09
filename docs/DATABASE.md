# Database & Persistence

Aegis persists through a small `Store` interface (`src/store/types.ts`). Two
implementations satisfy it:

| Implementation | When active | Use |
|----------------|-------------|-----|
| `MemoryStore` (`src/store/memory.ts`) | default (no `DATABASE_URL`) | dev, tests, demos, single-process |
| `PrismaStore` (`src/store/prisma.ts`) | when `DATABASE_URL` is set | production (PostgreSQL) |

The factory `getStore()` (`src/store/index.ts`) picks one at boot and lazy-imports Prisma so
the app runs with **zero database** in memory mode. The API layer depends only on the
interface, so swapping backends is transparent.

## Entities (Store interface)

`User`, `OAuthAccount`, `Organization`, `Membership` (RBAC role), `Team`, `Project`
(with `ownershipToken` / `verifiedAt`), `ScanRecord` (carries the full `AuditReport`).

## Prisma schema

The production schema lives in [`../prisma/schema.prisma`](../prisma/schema.prisma) and models
the full target state — including normalized `Finding`, `CategoryScore`, `Cve`,
`ScanTechnology`, `Report`, `ApiKey`, `Webhook`, `Notification`, and `AuditLog` tables.

Phase 1 persists the full report as JSON on `Scan.resultJson` for fast retrieval and history.
The normalized `Finding`/`CategoryScore` tables are reserved for Phase 3 analytics
(CVE joins, cross-scan finding trends) and are populated then.

## Setup (PostgreSQL)

```bash
# 1. Point at a database
export DATABASE_URL="postgresql://aegis:aegis@localhost:5432/aegis?schema=public"

# 2. Generate the client
npm run prisma:generate

# 3. Create & apply the initial migration (first time)
npm run db:migrate:dev -- --name init

# 4. In CI/production, apply migrations non-interactively
npm run db:migrate          # prisma migrate deploy
```

With `docker compose up`, the `postgres` service is provisioned and the `api` service reads
`DATABASE_URL`; run the migration once against it (`db:migrate:dev`) to create the schema, then
`db:migrate` on subsequent deploys.

## Why an interface instead of Prisma everywhere

- **Testability** — the full auth/tenancy suite (`test/auth.test.ts`) runs against
  `MemoryStore` with no database, keeping CI fast and hermetic.
- **Local DX** — contributors can run the whole app with `npm run dev` and no Postgres.
- **Clean boundary** — business logic never imports Prisma types; only `PrismaStore` does.
