'use client';

import { useCallback, useEffect, useRef, useState } from 'react';
import { useAuth } from '@/lib/auth';
import { api } from '@/lib/api';
import type { AppNotification } from '@/lib/types';

const SEV_COLOR: Record<string, string> = {
  critical: 'var(--red)',
  warning: 'var(--orange)',
  info: 'var(--accent)',
};

function ago(iso: string): string {
  const s = Math.max(1, Math.floor((Date.now() - new Date(iso).getTime()) / 1000));
  if (s < 60) return `${s}s ago`;
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
  return `${Math.floor(s / 86400)}d ago`;
}

export function NotificationsBell() {
  const { orgs } = useAuth();
  const orgId = orgs[0]?.id;
  const [items, setItems] = useState<AppNotification[]>([]);
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLDivElement>(null);
  const unread = items.filter((n) => !n.read).length;

  const load = useCallback(async () => {
    if (!orgId) return;
    try {
      const res = await api.notifications(orgId);
      setItems(res.notifications);
    } catch {
      /* ignore */
    }
  }, [orgId]);

  useEffect(() => {
    void load();
    const t = setInterval(() => void load(), 30_000);
    return () => clearInterval(t);
  }, [load]);

  // Close on outside click.
  useEffect(() => {
    function onDoc(e: MouseEvent) {
      if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false);
    }
    document.addEventListener('mousedown', onDoc);
    return () => document.removeEventListener('mousedown', onDoc);
  }, []);

  async function openAndRead() {
    const next = !open;
    setOpen(next);
    if (next && unread > 0) {
      await Promise.all(items.filter((n) => !n.read).map((n) => api.markNotificationRead(n.id).catch(() => {})));
      setItems((prev) => prev.map((n) => ({ ...n, read: true })));
    }
  }

  if (!orgId) return null;

  return (
    <div ref={ref} className="relative">
      <button onClick={openAndRead} className="relative rounded-lg border border-[var(--border)] px-2.5 py-1.5 text-dim hover:text-ink" aria-label="Notifications" title="Alerts">
        🔔
        {unread > 0 && (
          <span className="absolute -right-1 -top-1 grid h-4 min-w-4 place-items-center rounded-full bg-[var(--red)] px-1 text-[10px] font-bold text-white">
            {unread > 9 ? '9+' : unread}
          </span>
        )}
      </button>

      {open && (
        <div className="absolute right-0 z-50 mt-2 w-80 overflow-hidden rounded-xl border border-[var(--border)] bg-elev shadow-xl">
          <div className="border-b border-[var(--border)] px-4 py-2.5 text-xs font-semibold">Alerts</div>
          {items.length === 0 ? (
            <div className="px-4 py-6 text-center text-xs text-mute">No alerts yet. Schedule a project to get regression alerts.</div>
          ) : (
            <ul className="max-h-96 overflow-y-auto">
              {items.map((n) => (
                <li key={n.id} className="flex gap-3 border-b border-[var(--border)] px-4 py-3 last:border-0">
                  <span className="mt-1.5 h-2 w-2 flex-none rounded-full" style={{ background: SEV_COLOR[n.severity] ?? 'var(--text-mute)' }} />
                  <div className="min-w-0">
                    <div className="text-[13px] font-medium">{n.title}</div>
                    {n.body && <div className="mt-0.5 text-xs text-dim">{n.body}</div>}
                    <div className="mt-1 font-mono text-[10px] text-mute">{ago(n.createdAt)}</div>
                  </div>
                </li>
              ))}
            </ul>
          )}
        </div>
      )}
    </div>
  );
}
