# Security & Ethics Model

Aegis is a **defensive** auditing platform. This document is the contract for how it behaves.

## Passive vs. Active

| | Passive (default) | Active (gated) |
|--|--|--|
| Examples | TLS handshake, header/cookie/CSP/CORS analysis, DNS lookups, tech fingerprint, robots/sitemap read, homepage HTML analysis | Port scan, sensitive-file discovery, admin/dir-listing checks |
| Intrusiveness | Ordinary requests a browser or resolver would make | Probes ports and well-known paths |
| Requirement | None | `authorized === true` **and** `includeActive === true` |
| Enforcement | — | In the **engine** (`scanner.ts` `selectModules`), not just the UI |

The UI additionally shows an **authorization confirmation dialog** before active scans,
and the CLI refuses `--active` without `--authorized`.

## Guarantees

- **No exploitation.** Aegis never sends attack payloads, never attempts auth bypass, never
  brute forces. Active modules only observe existence/exposure.
- **No unverified claims.** A finding is emitted only from observed evidence. OWASP/CVE tags
  reflect what was seen; the engine does not guess vulnerabilities.
- **Secret hygiene.** The JavaScript-security module redacts any matched token before it
  appears in a finding (`abcd…xyz`), and flags it as *potential* pending human confirmation.
- **Polite by design.** Active port checks are sequential with short timeouts and a tiny
  fixed port list; exposure checks read only a 256-byte prefix and hit a fixed path list.

## Production hardening (target state)

- **SSRF guard** on workers: resolve the target and refuse RFC1918 / link-local /
  cloud-metadata (169.254.169.254) addresses unless the engagement is a verified
  private-network scan.
- **Ownership verification** before active scans: DNS TXT token or
  `/.well-known/aegis-verify` file recorded on the `Project`.
- **Rate limiting**: per-IP (implemented) and per-target token bucket + global outbound RPS
  budget (worker, planned).
- **Audit logging**: every scan records who/what/when/authorization (`AuditLog`).
- **AuthZ**: org-scoped RBAC; reports and scans never leak across tenants.
- **Transport**: API behind TLS; JWT short-lived; refresh tokens httpOnly/Secure/SameSite.

## Responsible disclosure

Aegis surfaces weaknesses to the **owner** of a site to help them fix issues. It is not for
assessing third-party sites you do not control. Users are responsible for ensuring they have
authorization for any active scan.
