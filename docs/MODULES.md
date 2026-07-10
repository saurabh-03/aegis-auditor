# Modules

Each module is an independently executable unit implementing the `ScanModule` contract
(`src/core/types.ts`) and registered in `src/modules/registry.ts`. Run any subset via
`--only`/`--skip` (CLI) or `only`/`skip` (API).

Legend: ✅ implemented · 🔒 implemented but authorization-gated · 📐 designed (roadmap).

| # | Module (spec) | File | Category | Mode | Status |
|--:|---------------|------|----------|------|:------:|
| 1 | SSL Analysis | `ssl.ts` | security | passive | ✅ |
| 2 | Security Headers | `headers.ts` | security | passive | ✅ |
| 3 | Cookie Security | `cookies.ts` | security | passive | ✅ |
| 4 | DNS Analysis (SPF/DMARC/CAA/IPv6) | `dns.ts` | infrastructure | passive | ✅ |
| 5 | Technology Detection | `tech.ts` | infrastructure | passive | ✅ |
| 6 | Port Scanner | `active/ports.ts` | infrastructure | active | 🔒 |
| 7 | HTTP Analysis | `http.ts` | performance | passive | ✅ |
| 8 | Performance Analysis (HTML heuristics) | `performance.ts` | performance | passive | ✅ |
| 8b | Core Web Vitals (lab, headless browser) | `webvitals.ts` | performance | passive | ✅† |
| 9 | Image Optimization | `images.ts` | performance | passive | ✅ |
| 10 | JavaScript Security (secrets) | `jssecurity.ts` | security | passive | ✅ |
| 11 | Robots Analysis | `crawl.ts` | seo | passive | ✅ |
| 12 | Sitemap Analysis | `crawl.ts` | seo | passive | ✅ |
| 13 | Admin Discovery | `active/exposure.ts` | security | active | 🔒 |
| 14 | Sensitive File Discovery | `active/exposure.ts` | security | active | 🔒 |
| 15 | Directory Listing | `active/exposure.ts` | security | active | 🔒 |
| 16 | CORS | `cors.ts` | security | passive | ✅ |
| 17 | Content Security Policy | `csp.ts` | security | passive | ✅ |
| 18 | OWASP Top 10 Mapping | (cross-cutting: every finding carries `owasp[]`) | — | — | ✅ |
| 19 | Dependency Intelligence (CVE) | `dependencies.ts` + `intel/` | security | passive | ✅ |
| 20 | Infrastructure | `scalability.ts` + `tech.ts` | infrastructure | passive | ✅ |
| 21 | Scalability Assessment | `scalability.ts` | scalability | passive | ✅ |
| 22 | SEO | `seo.ts` | seo | passive | ✅ |
| 23 | Accessibility | `seo.ts` (a11y signals) | accessibility | passive | ✅ |
| 24 | AI Security Advisor | `ai/` (local + Claude) | — | — | ✅ |

`✅†` Lab Core Web Vitals are implemented in `webvitals.ts` via **optional** Puppeteer
(`npm run enable:browser`). It measures real LCP / CLS / FCP and TBT (the lab proxy for INP,
since true INP needs simulated interaction) plus a per-resource waterfall. Without Puppeteer the
module degrades to an info finding; the passive `performance.ts` heuristics always run. Controlled
by `BROWSER_METRICS` / `BROWSER_FORM_FACTOR` / `BROWSER_TIMEOUT_MS`.

## Notes on specific modules

### OWASP Top 10 mapping (18)
Rather than a separate pass, **every finding carries an `owasp[]` array**, so the mapping is
authored where the evidence is observed. The dashboard's category filter + the CSV `owasp`
column give you an OWASP view. Aegis never asserts an OWASP category without observed
evidence (e.g. CORS reflection → `A05` / `A01`).

### AI Security Advisor (24) — implemented
`src/ai` provides an `Advisor` abstraction with two backends: `LocalAdvisor` (deterministic,
offline, always available) and `AnthropicAdvisor` (uses Claude when `ANTHROPIC_API_KEY` is set,
with automatic fallback to local on any error). It produces an **executive summary**,
**prioritized actions**, a **remediation checklist**, and **grouped findings** (by OWASP
category). `src/ai/tickets.ts` generates **GitHub/Jira tickets** from findings. Endpoints:
`GET /api/reports/:id/advisor` and `GET /api/reports/:id/tickets?format=github|jira`.

### Active modules (6, 13, 14, 15) — ethics
- Gated behind `authorized && includeActive`; the engine refuses otherwise.
- **Port scanner**: TCP `connect()` to a small fixed port list, sequential, short timeout,
  no banner grabbing, no brute forcing.
- **Exposure checks**: a handful of GETs to well-known paths; reads only a 256-byte prefix to
  classify; never downloads full sensitive files; reports existence for remediation.

### Dependency Intelligence (19) — implemented
Two complementary paths, both in `src/intel`:

- **Passive (homepage):** `dependencies.ts` fingerprints component versions from the page
  (shared `fingerprint.ts`) and matches them via **live OSV.dev** merged with a curated offline
  dataset (`matchVulnerabilities`, deduped, OSV preferred). Sees only HTML-referenced libraries.
- **Manifest SCA (full coverage):** `manifest.ts` parses real lockfiles
  (`package-lock.json` v1/v2/v3, `package.json`, `yarn.lock`, `composer.lock`) and
  `matchPackages` runs every dependency against OSV + local with bounded concurrency. Exposed as
  `POST /api/sca` and the CI-gating CLI `npm run sca -- <manifest> --fail-on <sev>` (exit 1 on
  findings). CVSS is a real v3.1 base score computed from the advisory vector (v4-only advisories
  fall back to the severity label).

### Lab Core Web Vitals (8b) — implemented (opt-in)
`webvitals.ts` measures real LCP/CLS/FCP/TBT + a resource waterfall via optional Puppeteer
(`npm run enable:browser`). TBT is the lab proxy for INP; true INP (simulated interaction) and
moving the browser run into a dedicated worker are the remaining `TODO(aegis:cwv)` items.
