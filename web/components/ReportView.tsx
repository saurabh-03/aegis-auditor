'use client';

import type { AuditReport } from '@/lib/types';
import { ScoreGauge } from './ScoreGauge';
import { CategoryCards } from './CategoryCards';
import { FindingList } from './FindingList';
import { AdvisorPanel } from './AdvisorPanel';

function summary(report: AuditReport) {
  const c = { critical: 0, high: 0, medium: 0, low: 0, passed: 0 };
  for (const f of report.findings) {
    if (f.status === 'pass') c.passed++;
    else if (f.severity === 'critical') c.critical++;
    else if (f.severity === 'high') c.high++;
    else if (f.severity === 'medium') c.medium++;
    else if (f.severity === 'low') c.low++;
  }
  return c;
}

export function ReportView({ report, reportId }: { report: AuditReport; reportId?: string }) {
  const c = summary(report);
  const chips: [string, number, string][] = [
    ['Critical', c.critical, 'var(--red)'],
    ['High', c.high, 'var(--orange)'],
    ['Medium', c.medium, 'var(--yellow)'],
    ['Low', c.low, 'var(--accent)'],
    ['Passing', c.passed, 'var(--green)'],
  ];

  return (
    <div className="space-y-5">
      <div className="grid gap-4 md:grid-cols-[260px_1fr]">
        <div className="card flex flex-col items-center justify-center p-6">
          <ScoreGauge score={report.overall.score} grade={report.overall.grade} />
          <div className="mt-3 break-all text-center font-mono text-xs text-dim">{report.target}</div>
        </div>
        <div className="card p-6">
          <div className="mb-3 text-sm font-semibold">Category Scores</div>
          <CategoryCards categories={report.categories} />
        </div>
      </div>

      <div className="flex flex-wrap gap-2">
        {chips.map(([label, n, color]) => (
          <div key={label} className="flex items-center gap-2 rounded-full border border-[var(--border)] bg-elev px-4 py-2 text-sm">
            <span className="h-2.5 w-2.5 rounded-full" style={{ background: color }} />
            {n} {label}
          </div>
        ))}
      </div>

      {reportId && (
        <>
          <AdvisorPanel reportId={reportId} />
          <div className="flex flex-wrap gap-2">
            <a className="rounded-lg border border-[var(--border)] px-3 py-1.5 text-sm text-dim hover:text-ink" href={`/api/reports/${reportId}/report.md`} target="_blank" rel="noopener">
              ⬇ Markdown
            </a>
            <a className="rounded-lg border border-[var(--border)] px-3 py-1.5 text-sm text-dim hover:text-ink" href={`/api/reports/${reportId}/report.csv`} target="_blank" rel="noopener">
              ⬇ CSV
            </a>
            <a className="rounded-lg border border-[var(--border)] px-3 py-1.5 text-sm text-dim hover:text-ink" href={`/api/reports/${reportId}/tickets?format=github`} target="_blank" rel="noopener">
              ⬇ GitHub tickets
            </a>
            <a className="rounded-lg border border-[var(--border)] px-3 py-1.5 text-sm text-dim hover:text-ink" href={`/api/reports/${reportId}/tickets?format=jira`} target="_blank" rel="noopener">
              ⬇ Jira tickets
            </a>
          </div>
        </>
      )}

      <div>
        <div className="mb-3 text-sm font-semibold">Issue Explorer</div>
        <FindingList findings={report.findings} />
      </div>
    </div>
  );
}
