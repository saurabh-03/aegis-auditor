'use client';

import type { CategoryScore } from '@/lib/types';
import { scoreColor } from '@/lib/ui';

export function CategoryCards({ categories }: { categories: CategoryScore[] }) {
  const ran = categories.filter((c) => Object.values(c.findingCounts).reduce((a, b) => a + b, 0) > 0);
  return (
    <div className="grid grid-cols-2 gap-3 sm:grid-cols-3 md:grid-cols-4">
      {ran.map((c) => (
        <div key={c.category} className="rounded-xl border border-[var(--border)] bg-elev2 p-4">
          <div className="text-xs capitalize text-dim">{c.category}</div>
          <div className="my-1 text-2xl font-bold" style={{ color: scoreColor(c.score) }}>
            {c.score}
          </div>
          <div className="h-1.5 overflow-hidden rounded bg-bg">
            <div className="h-full rounded" style={{ width: `${c.score}%`, background: scoreColor(c.score) }} />
          </div>
        </div>
      ))}
    </div>
  );
}
