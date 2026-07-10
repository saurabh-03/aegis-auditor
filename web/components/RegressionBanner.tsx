'use client';

import { useEffect, useState } from 'react';
import { api } from '@/lib/api';
import type { RegressionAssessment, ReportDiff } from '@/lib/types';

const SEV_COLOR: Record<string, string> = {
  critical: 'var(--red)',
  high: 'var(--orange)',
  medium: 'var(--yellow)',
  low: 'var(--accent)',
};

export function RegressionBanner({ scanId }: { scanId: string }) {
  const [diff, setDiff] = useState<ReportDiff | null>(null);
  const [reg, setReg] = useState<RegressionAssessment | null>(null);
  const [loaded, setLoaded] = useState(false);

  useEffect(() => {
    let alive = true;
    api
      .scanDiff(scanId)
      .then((r) => {
        if (!alive) return;
        setDiff(r.diff);
        setReg(r.regression);
        setLoaded(true);
      })
      .catch(() => alive && setLoaded(true));
    return () => {
      alive = false;
    };
  }, [scanId]);

  if (!loaded || !diff) return null; // no baseline yet (first scan) or not a project scan

  const improved = diff.scoreDelta > 0 && diff.newFindings.length === 0;
  const accent = reg?.level === 'major' ? 'var(--red)' : reg?.level === 'minor' ? 'var(--orange)' : improved ? 'var(--green)' : 'var(--text-mute)';
  const arrow = diff.scoreDelta > 0 ? '▲' : diff.scoreDelta < 0 ? '▼' : '■';
  const headline = reg?.isRegression ? `Regression detected (${reg.level})` : improved ? 'Improved since last scan' : 'Changed since last scan';

  return (
    <div className="card overflow-hidden" style={{ borderLeft: `4px solid ${accent}` }}>
      <div className="flex flex-wrap items-center gap-3 px-4 py-3">
        <span className="text-sm font-semibold" style={{ color: accent }}>
          {headline}
        </span>
        <span className="font-mono text-xs text-dim">
          score {diff.prevScore} <span style={{ color: accent }}>{arrow} {diff.currScore}</span>{' '}
          <span className="text-mute">({diff.scoreDelta >= 0 ? '+' : ''}{diff.scoreDelta})</span>
        </span>
      </div>

      {(diff.newFindings.length > 0 || diff.resolvedFindings.length > 0) && (
        <div className="grid gap-4 border-t border-[var(--border)] px-4 py-3 sm:grid-cols-2">
          {diff.newFindings.length > 0 && (
            <div>
              <div className="mb-1.5 text-xs font-semibold text-[var(--red)]">New issues ({diff.newFindings.length})</div>
              <ul className="space-y-1">
                {diff.newFindings.slice(0, 6).map((f) => (
                  <li key={f.id} className="flex items-center gap-2 text-xs text-dim">
                    <span className="h-1.5 w-1.5 rounded-full" style={{ background: SEV_COLOR[f.severity] ?? 'var(--text-mute)' }} />
                    {f.title}
                  </li>
                ))}
              </ul>
            </div>
          )}
          {diff.resolvedFindings.length > 0 && (
            <div>
              <div className="mb-1.5 text-xs font-semibold text-[var(--green)]">Resolved ({diff.resolvedFindings.length})</div>
              <ul className="space-y-1">
                {diff.resolvedFindings.slice(0, 6).map((f) => (
                  <li key={f.id} className="flex items-center gap-2 text-xs text-mute">
                    <span className="text-[var(--green)]">✓</span>
                    {f.title}
                  </li>
                ))}
              </ul>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
