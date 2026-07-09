'use client';

import { useEffect, useState } from 'react';
import { api } from '@/lib/api';
import type { AdvisorOutput } from '@/lib/types';

export function AdvisorPanel({ reportId }: { reportId: string }) {
  const [advisor, setAdvisor] = useState<AdvisorOutput | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let alive = true;
    api
      .advisor(reportId)
      .then((a) => alive && setAdvisor(a))
      .catch((e) => alive && setError(String(e.message ?? e)));
    return () => {
      alive = false;
    };
  }, [reportId]);

  if (error) return <div className="card p-5 text-sm text-mute">Advisor unavailable: {error}</div>;
  if (!advisor) return <div className="card p-5 text-sm text-mute">Generating AI advisor summary…</div>;

  return (
    <div className="card p-5">
      <div className="mb-2 flex items-center gap-2">
        <h3 className="text-base font-semibold">AI Security Advisor</h3>
        <span className="rounded-full border border-[var(--border)] px-2 py-0.5 text-[11px] text-mute">
          {advisor.provider === 'anthropic' ? `Claude · ${advisor.model ?? ''}` : 'local'}
        </span>
      </div>
      <p className="text-sm leading-relaxed text-dim">{advisor.executiveSummary}</p>

      {advisor.prioritizedActions.length > 0 && (
        <div className="mt-4">
          <div className="mb-1 text-xs font-semibold uppercase tracking-wide text-mute">Prioritized actions</div>
          <ol className="space-y-1.5 text-sm text-dim">
            {advisor.prioritizedActions.map((a, i) => (
              <li key={i} className="rounded-lg border border-[var(--border)] bg-elev2 px-3 py-2">{a}</li>
            ))}
          </ol>
        </div>
      )}

      {advisor.remediationChecklist.length > 0 && (
        <div className="mt-4">
          <div className="mb-1 text-xs font-semibold uppercase tracking-wide text-mute">Remediation checklist</div>
          <div className="space-y-1">
            {advisor.remediationChecklist.map((item) => (
              <label key={item.findingId} className="flex items-center gap-2 text-sm text-dim">
                <input type="checkbox" className="accent-[var(--accent)]" />
                <span className="flex-1">{item.title}</span>
                <span className="text-[11px] text-mute">{item.estimatedFixTime}</span>
              </label>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
