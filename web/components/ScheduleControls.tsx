'use client';

import { useEffect, useState } from 'react';
import { api, ApiError } from '@/lib/api';
import type { Cadence, Schedule } from '@/lib/types';

const CADENCES: Cadence[] = ['daily', 'weekly', 'monthly'];

function when(iso: string): string {
  const d = new Date(iso);
  return d.toLocaleDateString(undefined, { month: 'short', day: 'numeric' }) + ' ' + d.toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit' });
}

export function ScheduleControls({ projectId, verified }: { projectId: string; verified: boolean }) {
  const [schedules, setSchedules] = useState<Schedule[]>([]);
  const [open, setOpen] = useState(false);
  const [cadence, setCadence] = useState<Cadence>('weekly');
  const [includeActive, setIncludeActive] = useState(false);
  const [webhookUrl, setWebhookUrl] = useState('');
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  async function load() {
    try {
      const res = await api.schedules(projectId);
      setSchedules(res.schedules);
    } catch {
      /* ignore */
    }
  }
  useEffect(() => {
    if (open) void load();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open]);

  async function add() {
    setBusy(true);
    setErr(null);
    try {
      await api.createSchedule(projectId, { cadence, includeActive, webhookUrl: webhookUrl.trim() || null });
      setWebhookUrl('');
      setIncludeActive(false);
      await load();
    } catch (e) {
      setErr(e instanceof ApiError ? e.message : 'Failed to create schedule');
    } finally {
      setBusy(false);
    }
  }

  async function toggle(s: Schedule) {
    await api.updateSchedule(s.id, { enabled: !s.enabled }).catch(() => {});
    await load();
  }
  async function remove(s: Schedule) {
    await api.deleteSchedule(s.id).catch(() => {});
    await load();
  }

  return (
    <div className="mt-3 border-t border-[var(--border)] pt-3">
      <button onClick={() => setOpen((v) => !v)} className="flex w-full items-center justify-between text-xs text-dim hover:text-ink">
        <span className="font-medium">Monitoring{schedules.length > 0 ? ` · ${schedules.length}` : ''}</span>
        <span className="text-mute">{open ? '▾' : '▸'}</span>
      </button>

      {open && (
        <div className="mt-3 space-y-3">
          {schedules.length > 0 && (
            <ul className="space-y-1.5">
              {schedules.map((s) => (
                <li key={s.id} className="flex items-center gap-2 rounded-lg border border-[var(--border)] bg-elev2 px-3 py-2 text-xs">
                  <span className={`h-2 w-2 rounded-full ${s.enabled ? 'bg-[var(--green)]' : 'bg-[var(--text-mute)]'}`} />
                  <span className="font-medium capitalize">{s.cadence}</span>
                  {s.includeActive && <span className="rounded bg-[var(--accent)]/15 px-1.5 py-0.5 text-[10px] text-[var(--accent)]">active</span>}
                  {s.webhookUrl && <span title={s.webhookUrl}>🔔</span>}
                  <span className="ml-auto font-mono text-[10px] text-mute">next {when(s.nextRunAt)}</span>
                  <button onClick={() => toggle(s)} className="text-mute hover:text-ink" title={s.enabled ? 'Pause' : 'Resume'}>
                    {s.enabled ? '⏸' : '▶'}
                  </button>
                  <button onClick={() => remove(s)} className="text-mute hover:text-[var(--red)]" title="Delete">
                    ✕
                  </button>
                </li>
              ))}
            </ul>
          )}

          <div className="flex flex-wrap items-center gap-2">
            <select
              value={cadence}
              onChange={(e) => setCadence(e.target.value as Cadence)}
              className="rounded-lg border border-[var(--border)] bg-elev2 px-2 py-1.5 text-xs capitalize"
            >
              {CADENCES.map((c) => (
                <option key={c} value={c}>
                  {c}
                </option>
              ))}
            </select>
            <label className={`flex items-center gap-1.5 text-xs ${verified ? 'text-dim' : 'text-mute'}`} title={verified ? '' : 'Verify ownership to enable active scans'}>
              <input type="checkbox" checked={includeActive} disabled={!verified} onChange={(e) => setIncludeActive(e.target.checked)} />
              active
            </label>
            <input
              value={webhookUrl}
              onChange={(e) => setWebhookUrl(e.target.value)}
              placeholder="webhook URL (optional)"
              className="min-w-[140px] flex-1 rounded-lg border border-[var(--border)] bg-elev2 px-2 py-1.5 font-mono text-xs"
            />
            <button onClick={add} disabled={busy} className="btn-primary rounded-lg px-3 py-1.5 text-xs font-semibold disabled:opacity-50">
              {busy ? '…' : 'Schedule'}
            </button>
          </div>
          {err && <p className="text-xs text-[var(--red)]">{err}</p>}
          <p className="text-[11px] text-mute">Scans run automatically; a regression (new high/critical issue or score drop) raises an alert.</p>
        </div>
      )}
    </div>
  );
}
