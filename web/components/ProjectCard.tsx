'use client';

import { useState } from 'react';
import { api, ApiError } from '@/lib/api';
import type { Project } from '@/lib/types';

export function ProjectCard({
  project,
  onScan,
  onChanged,
}: {
  project: Project;
  onScan: (p: Project, includeActive: boolean) => void;
  onChanged: () => void;
}) {
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState<string | null>(null);
  const verified = Boolean(project.verifiedAt);

  async function verify() {
    setBusy(true);
    setMsg(null);
    try {
      await api.verifyProject(project.id);
      setMsg('Verified ✓');
      onChanged();
    } catch (e) {
      setMsg(e instanceof ApiError ? e.message : 'Verification failed');
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="card p-4">
      <div className="flex items-center justify-between">
        <div>
          <div className="font-semibold">{project.name}</div>
          <div className="font-mono text-xs text-mute">{project.target}</div>
        </div>
        <span
          className={`rounded-full px-2 py-0.5 text-[11px] ${verified ? 'bg-green-500/15 text-[var(--green)]' : 'bg-slate-500/15 text-mute'}`}
        >
          {verified ? 'verified' : 'unverified'}
        </span>
      </div>
      <div className="mt-3 flex flex-wrap gap-2">
        <button onClick={() => onScan(project, false)} className="rounded-lg border border-[var(--border)] px-3 py-1.5 text-sm text-dim hover:text-ink">
          Passive scan
        </button>
        {verified ? (
          <button onClick={() => onScan(project, true)} className="btn-primary rounded-lg px-3 py-1.5 text-sm font-semibold">
            Active scan
          </button>
        ) : (
          <button onClick={verify} disabled={busy} className="rounded-lg border border-[var(--border)] px-3 py-1.5 text-sm text-dim hover:text-ink disabled:opacity-50">
            {busy ? 'Verifying…' : 'Verify ownership'}
          </button>
        )}
      </div>
      {msg && <p className="mt-2 text-xs text-mute">{msg}</p>}
    </div>
  );
}
