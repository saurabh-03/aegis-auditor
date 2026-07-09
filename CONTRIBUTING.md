# Contributing to Aegis

Thanks for improving Aegis. This is a **defensive** security tool — that framing
shapes every contribution. Please read this before opening a PR.

Full developer guide: [`docs/DEVELOPING.md`](docs/DEVELOPING.md).

## Ground rules

1. **Defensive only.** No exploitation, no offensive payloads, no auth bypass, no
   brute forcing. Modules observe and explain; they never attack.
2. **Respect the passive/active gate.** Any intrusive check must be `mode:
   'active'` and must honor `ctx.options.authorized`. The engine — not just the
   UI — enforces this. Don't route around it.
3. **No unproven claims.** Only report from observed evidence. OWASP/CVE tags
   must reflect what was actually seen.
4. **Findings explain themselves.** Every finding needs risk, why-it-matters,
   technical detail, business impact, remediation, and references. Use the
   `finding()` / `pass()` helpers.
5. **Never leak secrets in output.** If a module detects a token, redact it (see
   `src/modules/jssecurity.ts`) and report it as *potential*, pending
   confirmation.

## Workflow

```bash
git checkout -b feat/my-change
# ... make the change ...
npm run typecheck && npm test          # backend
cd web && npx tsc --noEmit && npx next build   # frontend (if touched)
npm run scan -- example.com            # smoke-test against a real target
```

- Branch from `main`; keep PRs focused on one thing.
- Add tests for new logic — **offline and deterministic** (no network in
  `npm test`). See [`docs/DEVELOPING.md`](docs/DEVELOPING.md#test-conventions).
- Update docs when you change behavior (`docs/MODULES.md` for new modules,
  `docs/API.md` for endpoints, `.env.example` for new config).

## PR checklist

- [ ] `npm run typecheck` and `npm test` pass
- [ ] Frontend (if touched): `npx tsc --noEmit` and `next build` pass
- [ ] New/changed check verified with a real `npm run scan`
- [ ] New findings carry all required explanatory fields
- [ ] Active behavior (if any) is gated behind authorization
- [ ] Docs / `.env.example` updated for behavior or config changes
- [ ] No new runtime dependency without a clear reason (engine core stays lean)

## Commit style

Present-tense summary line, a short body explaining *why*, and:

```
Co-Authored-By: <you>
```

## Where to start

See **Good first extensions** in [`docs/DEVELOPING.md`](docs/DEVELOPING.md#good-first-extensions),
or search the code for `TODO(aegis` to find marked extension points.
