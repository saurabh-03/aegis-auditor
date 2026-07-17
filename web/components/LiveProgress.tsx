'use client';

import { motion } from 'framer-motion';
import type { ScanStreamState } from '@/lib/useScanStream';

export function LiveProgress({ state }: { state: ScanStreamState }) {
  const pct = Math.round(state.progress * 100);
  return (
    <div className="card p-5">
      <div className="mb-2 flex items-center justify-between text-sm">
        <span className="font-semibold capitalize">{state.status}</span>
        <span className="text-mute">{pct}%</span>
      </div>
      <div className="h-2 overflow-hidden rounded bg-bg">
        <motion.div
          className="h-full rounded bg-gradient-to-r from-[var(--accent)] to-[var(--accent-2)]"
          animate={{ width: `${pct}%` }}
          transition={{ ease: 'easeOut', duration: 0.3 }}
        />
      </div>
      <div className="mt-2 h-5 font-mono text-xs text-mute">
        {state.status === 'failed'
          ? `✗ ${state.error ?? 'failed'}`
          : state.lastModule
          ? `▸ ${state.lastModule}${state.moduleNote ? ` · ${state.moduleNote}` : ''}`
          : 'starting…'}
      </div>
    </div>
  );
}
