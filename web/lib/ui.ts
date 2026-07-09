import type { Severity } from './types';

export function scoreColor(score: number): string {
  if (score >= 90) return 'var(--green)';
  if (score >= 75) return 'var(--yellow)';
  if (score >= 60) return 'var(--orange)';
  return 'var(--red)';
}

export const sevColor: Record<Severity, string> = {
  critical: 'var(--red)',
  high: 'var(--orange)',
  medium: 'var(--yellow)',
  low: 'var(--accent)',
  info: 'var(--text-mute)',
};

export const sevBadge: Record<Severity, string> = {
  critical: 'bg-red-500/15 text-[var(--red)]',
  high: 'bg-orange-500/15 text-[var(--orange)]',
  medium: 'bg-yellow-500/15 text-[var(--yellow)]',
  low: 'bg-blue-500/15 text-[var(--accent)]',
  info: 'bg-slate-500/15 text-[var(--text-mute)]',
};
