'use client';

import { useCallback, useEffect, useState } from 'react';
import { api, ApiError } from '@/lib/api';
import type { Webhook, WebhookEvent } from '@/lib/types';

const EVENTS: WebhookEvent[] = ['regression', 'scan_complete'];

export function Webhooks({ orgId }: { orgId: string }) {
  const [hooks, setHooks] = useState<Webhook[]>([]);
  const [url, setUrl] = useState('');
  const [events, setEvents] = useState<WebhookEvent[]>(['regression']);
  const [busy, setBusy] = useState(false);
  const [secret, setSecret] = useState<string | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [msg, setMsg] = useState<string | null>(null);

  const load = useCallback(async () => {
    try {
      setHooks((await api.webhooks(orgId)).webhooks);
      setErr(null);
    } catch (e) {
      setErr(e instanceof ApiError ? e.message : 'Failed to load webhooks');
    }
  }, [orgId]);
  useEffect(() => {
    void load();
  }, [load]);

  function toggleEvent(e: WebhookEvent) {
    setEvents((cur) => (cur.includes(e) ? cur.filter((x) => x !== e) : [...cur, e]));
  }

  async function create(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    setErr(null);
    try {
      const res = await api.createWebhook(orgId, url.trim(), events);
      setSecret(res.secret);
      setUrl('');
      await load();
    } catch (e) {
      setErr(e instanceof ApiError ? e.message : 'Failed to create webhook');
    } finally {
      setBusy(false);
    }
  }

  async function test(h: Webhook) {
    setMsg(null);
    try {
      await api.testWebhook(h.id);
      setMsg(`Test ping sent to ${h.url}`);
    } catch {
      setMsg('Test failed to send.');
    }
  }
  async function remove(h: Webhook) {
    if (!confirm(`Delete webhook to ${h.url}?`)) return;
    await api.deleteWebhook(h.id).catch(() => {});
    await load();
  }

  return (
    <section className="card p-5">
      <div className="mb-1 text-sm font-semibold">Webhooks</div>
      <p className="mb-3 text-xs text-mute">
        Receive a signed <span className="font-mono">POST</span> when a monitored project regresses. Verify deliveries with the{' '}
        <span className="font-mono">x-aegis-signature</span> header (HMAC-SHA256 of the body).
      </p>

      {secret && (
        <div className="mb-3 rounded-lg border border-[var(--accent)]/40 bg-[var(--accent)]/10 p-3">
          <div className="mb-1 text-xs font-semibold text-ink">Signing secret — shown once. Store it to verify signatures.</div>
          <div className="flex items-center gap-2">
            <code className="flex-1 overflow-x-auto rounded bg-bg px-2 py-1.5 font-mono text-xs">{secret}</code>
            <button onClick={() => setSecret(null)} className="rounded-lg border border-[var(--border)] px-2 py-1.5 text-xs text-dim hover:text-ink">
              Done
            </button>
          </div>
        </div>
      )}

      <form onSubmit={create} className="mb-2 flex flex-wrap items-center gap-2">
        <input className="input flex-1 font-mono" placeholder="https://example.com/hooks/aegis" value={url} onChange={(e) => setUrl(e.target.value)} required />
        {EVENTS.map((ev) => (
          <label key={ev} className="flex items-center gap-1.5 text-xs text-dim">
            <input type="checkbox" checked={events.includes(ev)} onChange={() => toggleEvent(ev)} />
            {ev}
          </label>
        ))}
        <button className="btn-primary rounded-lg px-4 py-2 text-sm font-semibold disabled:opacity-50" disabled={busy}>
          {busy ? 'Adding…' : 'Add webhook'}
        </button>
      </form>
      {err && <p className="mb-2 text-xs text-[var(--red)]">{err}</p>}
      {msg && <p className="mb-2 text-xs text-[var(--green)]">{msg}</p>}

      {hooks.length === 0 ? (
        <p className="text-xs text-mute">No webhooks configured.</p>
      ) : (
        <ul className="divide-y divide-[var(--border)]">
          {hooks.map((h) => (
            <li key={h.id} className="flex flex-wrap items-center gap-x-3 gap-y-1 py-2.5 text-sm">
              <code className="font-mono text-xs">{h.url}</code>
              <span className="font-mono text-[11px] text-mute">{h.events.join(', ')}</span>
              <div className="ml-auto flex gap-2">
                <button onClick={() => test(h)} className="rounded-lg border border-[var(--border)] px-2.5 py-1 text-xs text-dim hover:text-ink">
                  Test
                </button>
                <button onClick={() => remove(h)} className="rounded-lg border border-[var(--border)] px-2.5 py-1 text-xs text-dim hover:text-[var(--red)]">
                  Delete
                </button>
              </div>
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}
