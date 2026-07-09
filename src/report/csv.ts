/** Renders findings as CSV for spreadsheet/ticketing import. */

import type { AuditReport } from '../core/types.js';

function esc(v: unknown): string {
  const s = String(v ?? '');
  return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
}

export function toCsv(report: AuditReport): string {
  const header = [
    'id',
    'module',
    'category',
    'severity',
    'status',
    'probability',
    'title',
    'risk',
    'businessImpact',
    'owasp',
    'cve',
    'remediation',
    'estimatedFixTime',
  ];
  const rows = report.findings.map((f) =>
    [
      f.id,
      f.module,
      f.category,
      f.severity,
      f.status,
      f.probability,
      f.title,
      f.risk,
      f.businessImpact,
      (f.owasp ?? []).join('; '),
      (f.cve ?? []).join('; '),
      f.remediation,
      f.estimatedFixTime,
    ]
      .map(esc)
      .join(','),
  );
  return [header.join(','), ...rows].join('\n');
}
