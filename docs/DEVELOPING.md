# Developing Aegis

A practical guide to hacking on Aegis — how the pieces fit, the fastest ways to
extend it, and the conventions that keep it trustworthy. Read
[`ARCHITECTURE.md`](ARCHITECTURE.md) for the big picture; this doc is the
hands-on companion.

## The dev loop

```bash
# Backend (Fastify API + engine + legacy dashboard on :4000)
npm install
npm run dev

# Frontend (Next.js dashboard on :3200, proxies /api → :4000)
cd web && npm install && npm run dev

# Fast feedback — run these constantly
npm run typecheck          # backend types
npm test                   # 19 offline, deterministic tests
cd web && npx tsc --noEmit # frontend types

# Always finish a change with a REAL scan — heuristics only prove out live
npm run scan -- example.com
npm run scan -- example.com --format md > /tmp/report.md
```

Two long-running dev servers is the normal setup. Ports: API `4000`, web `3200`.
On Windows a stale dev server can hold `4000` — free it with
`Get-NetTCPConnection -LocalPort 4000 | Stop-Process` (`pkill -f tsx` misses it).

## Repo map

```
src/
  core/         engine — types, config, http, scoring, scanner (the orchestrator)
  modules/      one file per check; active/ holds authorization-gated modules
  intel/        CVE intelligence — OSV.dev client, CVSS calc, local dataset, semver
  ai/           advisor (Local + Anthropic), ticket export
  store/        persistence behind an interface (Memory | Prisma)
  queue/        job queue behind an interface (InProcess | BullMQ) + worker runner
  api/          Fastify routes (auth, tenancy, scans), rate limiting
  report/       markdown & csv renderers
  server.ts     API entrypoint      worker.ts  standalone worker entrypoint
  cli.ts        terminal entrypoint
web/            Next.js app (App Router, Tailwind, Framer Motion)
test/           node:test suites — MUST stay offline/deterministic
```

## Adding a scan module (the main extension point)

A new check is **one file + one line**. The engine handles scheduling, scoring,
reporting, exports, and the API surface for you.

```ts
// src/modules/mycheck.ts
import { finding, pass } from '../core/finding.js';
import type { ModuleResult, ScanContext, ScanModule } from '../core/types.js';

const MODULE = 'mycheck';

export const myCheckModule: ScanModule = {
  name: MODULE,
  title: 'My Check',
  category: 'security',       // rolls into that category's score
  mode: 'passive',            // 'active' ⇒ gated behind authorization
  description: 'One line shown in the module catalog.',
  async run(ctx: ScanContext): Promise<ModuleResult> {
    const t0 = performance.now();
    const page = await ctx.getPage();          // shared, cached homepage fetch
    const findings = [];

    if (/* something is wrong */ false) {
      findings.push(finding({
        id: 'mycheck.problem', module: MODULE, category: 'security',
        title: 'Human-readable problem',
        severity: 'medium', status: 'fail', probability: 'medium',
        risk: '…', whyItMatters: '…', technical: '…', businessImpact: '…',
        remediation: '…', estimatedFixTime: '30 minutes',
        owasp: ['A05:2021-Security Misconfiguration'],
        references: ['https://…'],
      }));
    } else {
      findings.push(pass(MODULE, 'security', 'mycheck.ok', 'All good', 'Why it passed.'));
    }

    return {
      module: MODULE, category: 'security', ok: true, findings,
      durationMs: Math.round(performance.now() - t0),
      data: { /* structured output — powers an inspector panel */ },
    };
  },
};
```

Then register it in [`src/modules/registry.ts`](../src/modules/registry.ts):

```ts
import { myCheckModule } from './mycheck.js';
export const ALL_MODULES: ScanModule[] = [ /* … */, myCheckModule ];
```

That's it. It now runs in the CLI, API, and dashboard; contributes to scoring;
appears in exports; and is selectable via `--only mycheck` / `skip`.

### The `ScanContext` you get

- `ctx.getPage()` — the homepage fetched **once** and shared across all modules
  (headers, body, cookies, redirects, latency). Prefer it over your own fetch.
- `ctx.fetch(url, init)` — timeout-bounded fetch for extra requests.
- `ctx.target` — the parsed `URL`. `ctx.now` — scan timestamp.
- `ctx.options.authorized` — respect this in `active` modules.

## The golden rule: findings must explain themselves

The `Finding` type **requires** `risk`, `whyItMatters`, `technical`,
`businessImpact`, `remediation`, and `references`. This is the product's entire
value proposition — never emit a bare "X is missing." The `finding()` / `pass()`
helpers exist so you can't forget a field. If you can't fill those in
truthfully, you don't understand the finding well enough to ship it yet.

**Never claim a vulnerability without evidence.** OWASP/CVE tags must reflect
what was actually observed. Passive modules describe misconfiguration; they do
not assert exploitability.

## Findings → UI (adding an inspector panel)

Anything a module puts in `data` is exposed as `report.data['<module>']`. The
dashboard's inspector panels render straight from it — no backend coupling:

1. Emit the structured data from your module (`data: { … }`).
2. Add a panel to [`web/components/Inspectors.tsx`](../web/components/Inspectors.tsx)
   that reads `get(report, '<module>')` and returns `null` when absent.

This is exactly how the SSL / headers / CVE / tech panels work. **Do not
fabricate data you can't measure** — e.g. there is no resource waterfall because
the passive engine has no browser to time resources. Show only what's real.

## Swap points (extend behind the interface, don't hardcode)

| Concern | Interface | Impls | Activated by |
|---|---|---|---|
| Persistence | `Store` (`src/store`) | Memory · Prisma | `DATABASE_URL` |
| Job queue | `Queue` (`src/queue`) | InProcess · BullMQ | `REDIS_URL` |
| AI advisor | `Advisor` (`src/ai`) | Local · Anthropic | `ANTHROPIC_API_KEY` |
| CVE source | `matchVulnerabilities` (`src/intel`) | OSV · local | `CVE_SOURCE` |

Add capabilities by implementing the interface, not by branching in call sites.

## Test conventions

- **Offline and deterministic, always.** `npm test` must never touch the
  network. Mock `ScanContext` (see [`test/headers.test.ts`](../test/headers.test.ts))
  or test pure functions. Anything live (OSV, Claude) sits behind a matcher you
  can invoke in `local` mode — see how `matchCves` (sync/local) is kept separate
  from `matchVulnerabilities` (async/live).
- Prefer testing behavior through the module's `run()` with a fake context over
  testing private helpers.
- New module ⇒ add at least: one failing-case test and one passing-case test,
  and assert the non-pass findings carry the required explanatory fields.

## Good first extensions

Ordered by value, and mapped to `TODO(aegis:*)` anchors in the code:

1. **Headless-Chrome worker** → real Core Web Vitals (LCP/CLS/INP) + a genuine
   resource waterfall. `TODO(aegis:cwv)` in `src/modules/performance.ts`. Runs as
   a separate worker because it needs a browser runtime.
2. **Manifest-based SCA** → parse `package-lock.json` / `composer.json` /
   `yarn.lock` when reachable, to fix CVE *detection breadth* (today only
   homepage-referenced libs are seen). `TODO(aegis:sca)` in
   `src/modules/fingerprint.ts`.
3. **New passive modules** → the fast wins: subresource-integrity coverage,
   mixed-content detection, `mailto:`/form-action leak checks, cache-header depth.
   `TODO(aegis:module)` in `src/modules/registry.ts`.
4. **Richer AI grouping** → cross-scan duplicate detection and trend narratives.
   `TODO(aegis:advisor)` in `src/ai/local.ts`.

Search the codebase for `TODO(aegis` to jump to each anchor.

## Style

Match the surrounding code: strict TypeScript, `.js` import specifiers (NodeNext),
small single-responsibility modules, no new runtime deps unless they earn their
place (the engine core is dependency-free on purpose). Run `npm run typecheck`
before every commit.
