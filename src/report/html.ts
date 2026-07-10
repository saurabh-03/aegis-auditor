/**
 * Branded, print-optimized HTML report generator with audience personas.
 *
 *   executive  — score, category posture, top business risks, summary (management)
 *   security   — full security findings, OWASP/CVE mapping, technical detail
 *   compliance — pass/fail control table grouped by OWASP, framework framing
 *   developer  — every issue with remediation + example code
 *
 * Output is a self-contained HTML document (inline CSS, print styles) suitable
 * for viewing, printing, or rendering to PDF (see report/pdf.ts).
 */

import { summarize } from '../core/scoring.js';
import type { AuditReport, Category, Finding, Severity } from '../core/types.js';

export type Persona = 'executive' | 'security' | 'compliance' | 'developer';

export const PERSONAS: Persona[] = ['executive', 'security', 'compliance', 'developer'];

const PERSONA_TITLE: Record<Persona, string> = {
  executive: 'Executive Summary',
  security: 'Security Report',
  compliance: 'Compliance Report',
  developer: 'Developer Report',
};

const SEV_COLOR: Record<Severity, string> = {
  critical: '#c0233f',
  high: '#c25610',
  medium: '#9a7008',
  low: '#4a688c',
  info: '#6b7a8d',
};

function esc(s: unknown): string {
  return String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c] as string));
}

function scoreColor(score: number): string {
  return score >= 90 ? '#127a4e' : score >= 75 ? '#9a7008' : score >= 60 ? '#c25610' : '#c0233f';
}

function gaugeSvg(score: number, grade: string): string {
  const r = 54;
  const circ = 2 * Math.PI * r;
  const off = circ - (circ * score) / 100;
  const col = scoreColor(score);
  return `<svg viewBox="0 0 140 140" width="140" height="140" aria-label="Overall score ${score}">
    <circle cx="70" cy="70" r="${r}" fill="none" stroke="#e3e9f0" stroke-width="12"/>
    <circle cx="70" cy="70" r="${r}" fill="none" stroke="${col}" stroke-width="12" stroke-linecap="round"
      transform="rotate(-90 70 70)" stroke-dasharray="${circ.toFixed(1)}" stroke-dashoffset="${off.toFixed(1)}"/>
    <text x="70" y="66" text-anchor="middle" font-size="34" font-weight="800" fill="#16202b">${score}</text>
    <text x="70" y="88" text-anchor="middle" font-size="13" fill="#6b7a8d">GRADE ${esc(grade)}</text>
  </svg>`;
}

function categoryTable(report: AuditReport): string {
  const rows = report.categories
    .filter((c) => Object.values(c.findingCounts).reduce((a, b) => a + b, 0) > 0)
    .map(
      (c) => `<tr>
        <td style="text-transform:capitalize">${esc(c.category)}</td>
        <td class="num" style="color:${scoreColor(c.score)};font-weight:700">${c.score}</td>
        <td>${esc(c.grade)}</td>
        <td><div class="bar"><i style="width:${c.score}%;background:${scoreColor(c.score)}"></i></div></td>
      </tr>`,
    )
    .join('');
  return `<table class="cats"><thead><tr><th>Category</th><th>Score</th><th>Grade</th><th></th></tr></thead><tbody>${rows}</tbody></table>`;
}

function sevBadge(sev: Severity): string {
  return `<span class="sev" style="color:${SEV_COLOR[sev]};background:${SEV_COLOR[sev]}22">${sev.toUpperCase()}</span>`;
}

function findingCard(f: Finding, opts: { code?: boolean } = {}): string {
  return `<div class="finding" style="border-left-color:${SEV_COLOR[f.severity]}">
    <div class="fhead">${sevBadge(f.severity)} <span class="ftitle">${esc(f.title)}</span> <span class="fmeta">${esc(f.category)}${f.owasp?.length ? ' · ' + esc(f.owasp[0]) : ''}</span></div>
    <dl>
      <dt>Risk</dt><dd>${esc(f.risk)}</dd>
      <dt>Why it matters</dt><dd>${esc(f.whyItMatters)}</dd>
      <dt>Business impact</dt><dd>${esc(f.businessImpact)}</dd>
      <dt>Remediation</dt><dd>${esc(f.remediation)} <em>(${esc(f.estimatedFixTime)})</em></dd>
      ${f.cve?.length ? `<dt>CVE</dt><dd>${f.cve.map(esc).join(', ')}</dd>` : ''}
    </dl>
    ${opts.code && f.exampleCode ? `<pre>${esc(f.exampleCode)}</pre>` : ''}
  </div>`;
}

function executiveBody(report: AuditReport): string {
  const s = summarize(report);
  const posture = report.overall.score >= 90 ? 'strong' : report.overall.score >= 75 ? 'reasonable but improvable' : report.overall.score >= 60 ? 'weak and in need of attention' : 'poor, carrying material risk';
  const top = report.findings.filter((f) => f.status === 'fail' && (f.severity === 'critical' || f.severity === 'high')).slice(0, 5);
  return `<section>
    <h2>Overview</h2>
    <p>${esc(new URL(report.target).hostname)} scored <strong>${report.overall.score}/100 (${esc(report.overall.grade)})</strong> — an overall security and scalability posture that is <strong>${posture}</strong>. The audit identified <strong>${s.critical} critical</strong>, <strong>${s.high} high</strong>, ${s.medium} medium, and ${s.low} low-severity issues, with ${s.passed} checks passing.</p>
    <h2>Top priorities</h2>
    ${top.length === 0 ? '<p>No critical or high-severity issues were found. Focus on incremental hardening of the lower-severity items.</p>' : `<ol class="priorities">${top.map((f) => `<li><strong>${esc(f.title)}</strong> — ${esc(f.businessImpact)} <em>(${esc(f.estimatedFixTime)})</em></li>`).join('')}</ol>`}
  </section>`;
}

function securityBody(report: AuditReport): string {
  const sec = report.findings.filter((f) => f.category === 'security' && f.status !== 'pass');
  const owaspSet = new Set<string>();
  sec.forEach((f) => f.owasp?.forEach((o) => owaspSet.add(o)));
  return `<section>
    <h2>Security findings (${sec.length})</h2>
    ${sec.length === 0 ? '<p>No open security findings.</p>' : sec.map((f) => findingCard(f, { code: true })).join('')}
    ${owaspSet.size ? `<h2>OWASP coverage</h2><ul class="owasp">${[...owaspSet].sort().map((o) => `<li>${esc(o)}</li>`).join('')}</ul>` : ''}
  </section>`;
}

function complianceBody(report: AuditReport): string {
  // Group all checks by OWASP category (or "General") and show pass/fail.
  const byOwasp = new Map<string, { pass: number; fail: number; findings: Finding[] }>();
  for (const f of report.findings) {
    const keys = f.owasp?.length ? f.owasp : ['General controls'];
    for (const k of keys) {
      const g = byOwasp.get(k) ?? { pass: 0, fail: 0, findings: [] };
      if (f.status === 'pass') g.pass += 1;
      else g.fail += 1;
      g.findings.push(f);
      byOwasp.set(k, g);
    }
  }
  const rows = [...byOwasp.entries()]
    .sort()
    .map(([k, g]) => {
      const status = g.fail === 0 ? '<span class="pass">PASS</span>' : `<span class="fail">${g.fail} FAIL</span>`;
      return `<tr><td>${esc(k)}</td><td class="num">${g.pass}</td><td class="num">${g.fail}</td><td>${status}</td></tr>`;
    })
    .join('');
  return `<section>
    <h2>Control summary</h2>
    <p class="note">Findings mapped to OWASP Top 10 (2021) control areas. This is an evidence-based assessment, not a formal certification; use it to inform PCI-DSS, SOC 2, and GDPR readiness.</p>
    <table class="cats"><thead><tr><th>Control area</th><th>Pass</th><th>Fail</th><th>Status</th></tr></thead><tbody>${rows}</tbody></table>
    <h2>Failing controls</h2>
    ${report.findings.filter((f) => f.status === 'fail').map((f) => `<div class="ctl" style="border-left-color:${SEV_COLOR[f.severity]}">${sevBadge(f.severity)} <strong>${esc(f.title)}</strong> — ${esc(f.remediation)} <em>(${esc(f.estimatedFixTime)})</em></div>`).join('') || '<p>None.</p>'}
  </section>`;
}

function developerBody(report: AuditReport): string {
  const cats: Category[] = ['security', 'performance', 'infrastructure', 'scalability', 'seo', 'accessibility', 'maintainability'];
  return cats
    .map((cat) => {
      const items = report.findings.filter((f) => f.category === cat && f.status !== 'pass');
      if (items.length === 0) return '';
      return `<section><h2 style="text-transform:capitalize">${cat} (${items.length})</h2>${items.map((f) => findingCard(f, { code: true })).join('')}</section>`;
    })
    .join('');
}

export function renderHtmlReport(report: AuditReport, persona: Persona = 'executive'): string {
  const body =
    persona === 'executive' ? executiveBody(report) : persona === 'security' ? securityBody(report) : persona === 'compliance' ? complianceBody(report) : developerBody(report);

  return `<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">
<title>Aegis ${PERSONA_TITLE[persona]} — ${esc(report.target)}</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
  :root { --ink:#16202b; --dim:#48586a; --mute:#7688a0; --line:#dde4ee; --accent:#1187c9; }
  * { box-sizing:border-box; }
  body { font-family:-apple-system,"Segoe UI",system-ui,sans-serif; color:var(--ink); background:#fff; margin:0; line-height:1.55; }
  .page { max-width:820px; margin:0 auto; padding:40px 36px 64px; }
  header.rep { display:flex; align-items:center; gap:20px; border-bottom:2px solid var(--ink); padding-bottom:18px; margin-bottom:24px; }
  .brand { display:flex; align-items:center; gap:12px; flex:1; }
  .mark { width:40px;height:40px;border-radius:9px;background:linear-gradient(150deg,#1187c9,#6d5cff);color:#fff;display:grid;place-items:center;font-weight:800;font-size:20px; }
  .brand h1 { margin:0;font-size:19px;letter-spacing:-.02em; } .brand .sub { color:var(--mute);font-size:12px;font-family:ui-monospace,monospace; }
  .persona-tag { font-size:11px;text-transform:uppercase;letter-spacing:.12em;color:var(--mute);font-family:ui-monospace,monospace; }
  .summary-row { display:flex;gap:24px;align-items:center;margin-bottom:28px;flex-wrap:wrap; }
  .meta { font-family:ui-monospace,monospace;font-size:12px;color:var(--dim); }
  .meta div { margin:2px 0; }
  h2 { font-size:15px;letter-spacing:-.01em;margin:26px 0 12px;padding-bottom:6px;border-bottom:1px solid var(--line); }
  table { width:100%;border-collapse:collapse;font-size:13px;margin:8px 0; }
  th { text-align:left;font-size:10.5px;text-transform:uppercase;letter-spacing:.06em;color:var(--mute);padding:8px 10px;border-bottom:1px solid var(--line); }
  td { padding:8px 10px;border-bottom:1px solid var(--line); vertical-align:middle; }
  .num { font-variant-numeric:tabular-nums; text-align:right; width:60px; }
  .bar { height:7px;background:#eef2f8;border-radius:4px;overflow:hidden; } .bar i { display:block;height:100%; }
  .sev { font-size:10px;font-weight:700;padding:2px 7px;border-radius:5px; }
  .finding { border:1px solid var(--line);border-left:4px solid;border-radius:8px;padding:12px 14px;margin:10px 0; break-inside:avoid; }
  .fhead { display:flex;gap:10px;align-items:center;margin-bottom:6px; } .ftitle { font-weight:600;font-size:14px; } .fmeta { margin-left:auto;font-family:ui-monospace,monospace;font-size:11px;color:var(--mute); }
  dl { display:grid;grid-template-columns:120px 1fr;gap:4px 14px;margin:6px 0;font-size:12.5px; } dt { color:var(--mute); } dd { margin:0;color:var(--dim); }
  pre { background:#f5f7fb;border:1px solid var(--line);border-radius:6px;padding:10px;font-family:ui-monospace,monospace;font-size:11.5px;overflow-x:auto;white-space:pre-wrap; }
  .priorities li { margin:6px 0; } .owasp { columns:2;font-size:12.5px;color:var(--dim); }
  .ctl { border:1px solid var(--line);border-left:4px solid;border-radius:6px;padding:8px 12px;margin:6px 0;font-size:12.5px; break-inside:avoid; }
  .pass { color:#127a4e;font-weight:700; } .fail { color:#c0233f;font-weight:700; }
  .note { font-size:12px;color:var(--mute); }
  footer { margin-top:40px;padding-top:14px;border-top:1px solid var(--line);font-size:11px;color:var(--mute); }
  @media print { .page { max-width:none;padding:0; } header.rep { position:running(head); } body { -webkit-print-color-adjust:exact;print-color-adjust:exact; } }
</style></head>
<body><div class="page">
  <header class="rep">
    <div class="brand"><div class="mark">Æ</div><div><h1>Aegis Auditor</h1><div class="sub">${esc(report.target)}</div></div></div>
    <div class="persona-tag">${esc(PERSONA_TITLE[persona])}</div>
  </header>
  <div class="summary-row">
    ${gaugeSvg(report.overall.score, report.overall.grade)}
    <div style="flex:1;min-width:220px">${categoryTable(report)}</div>
    <div class="meta">
      <div>Scanned: ${esc(new Date(report.scannedAt).toLocaleString())}</div>
      <div>Engine: v${esc(report.meta.engineVersion)}</div>
      <div>Mode: ${report.meta.passiveOnly ? 'Passive' : 'Passive + Active'}</div>
    </div>
  </div>
  ${body}
  <footer>Generated by Aegis Auditor — a defensive security assessment. Active checks run only with explicit authorization. Findings reflect observed evidence at scan time.</footer>
</div></body></html>`;
}
