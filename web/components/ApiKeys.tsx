'use client';

import { useCallback, useEffect, useState } from 'react';
import { api, ApiError } from '@/lib/api';
import type { ApiKey } from '@/lib/types';

function date(iso: string): string {
  return new Date(iso).toLocaleDateString(undefined, { month: 'short', day: 'numeric', year: 'numeric' });
}

export function ApiKeys({ orgId }: { orgId: string }) {
  const [keys, setKeys] = useState<ApiKey[]>([]);
  const [name, setName] = useState('');
  const [creating, setCreating] = useState(false);
  const [fresh, setFresh] = useState<string | null>(null); // plaintext, shown once
  const [copied, setCopied] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  const load = useCallback(async () => {
    try {
      const res = await api.apiKeys(orgId);
      setKeys(res.keys);
      setErr(null);
    } catch (e) {
      setErr(e instanceof ApiError ? e.message : 'Failed to load keys');
    }
  }, [orgId]);

  useEffect(() => {
    void load();
  }, [load]);

  async function create(e: React.FormEvent) {
    e.preventDefault();
    setCreating(true);
    setErr(null);
    try {
      const res = await api.createApiKey(orgId, name.trim() || 'API key');
      setFresh(res.key);
      setCopied(false);
      setName('');
      await load();
    } catch (e) {
      setErr(e instanceof ApiError ? e.message : 'Failed to create key');
    } finally {
      setCreating(false);
    }
  }

  async function revoke(k: ApiKey) {
    if (!confirm(`Revoke "${k.name}"? Any client using it will stop working.`)) return;
    await api.revokeApiKey(k.id).catch(() => {});
    await load();
  }

  async function copy() {
    if (!fresh) return;
    try {
      await navigator.clipboard.writeText(fresh);
      setCopied(true);
    } catch {
      /* clipboard blocked */
    }
  }

  return (
    <section className="card p-5">
      <div className="mb-1 text-sm font-semibold">API keys</div>
      <p className="mb-3 text-xs text-mute">
        Authenticate programmatic requests with <span className="font-mono">X-Api-Key</span> (e.g. CI running{' '}
        <span className="font-mono">POST /api/scans</span>). Keys act for you within this organization.
      </p>

      {fresh && (
        <div className="mb-3 rounded-lg border border-[var(--accent)]/40 bg-[var(--accent)]/10 p-3">
          <div className="mb-1 text-xs font-semibold text-ink">Copy your new key now — it won't be shown again.</div>
          <div className="flex items-center gap-2">
            <code className="flex-1 overflow-x-auto rounded bg-bg px-2 py-1.5 font-mono text-xs text-ink">{fresh}</code>
            <button onClick={copy} className="btn-primary rounded-lg px-3 py-1.5 text-xs font-semibold">
              {copied ? 'Copied ✓' : 'Copy'}
            </button>
            <button onClick={() => setFresh(null)} className="rounded-lg border border-[var(--border)] px-2 py-1.5 text-xs text-dim hover:text-ink">
              Done
            </button>
          </div>
        </div>
      )}

      <form onSubmit={create} className="mb-3 flex flex-wrap gap-2">
        <input className="input flex-1" placeholder="Key name (e.g. CI pipeline)" value={name} onChange={(e) => setName(e.target.value)} />
        <button className="btn-primary rounded-lg px-4 py-2 text-sm font-semibold disabled:opacity-50" disabled={creating}>
          {creating ? 'Creating…' : 'Create key'}
        </button>
      </form>
      {err && <p className="mb-2 text-xs text-[var(--red)]">{err}</p>}

      {keys.length === 0 ? (
        <p className="text-xs text-mute">No API keys yet.</p>
      ) : (
        <ul className="divide-y divide-[var(--border)]">
          {keys.map((k) => {
            const revoked = Boolean(k.revokedAt);
            return (
              <li key={k.id} className="flex flex-wrap items-center gap-x-3 gap-y-1 py-2.5 text-sm">
                <span className={`font-medium ${revoked ? 'text-mute line-through' : ''}`}>{k.name}</span>
                <code className="font-mono text-xs text-mute">{k.keyPrefix}••••••••</code>
                <span className="ml-auto font-mono text-[11px] text-mute">
                  {k.lastUsedAt ? `used ${date(k.lastUsedAt)}` : 'never used'} · created {date(k.createdAt)}
                </span>
                {revoked ? (
                  <span className="rounded-full bg-[var(--red)]/15 px-2 py-0.5 text-[11px] text-[var(--red)]">revoked</span>
                ) : (
                  <button onClick={() => revoke(k)} className="rounded-lg border border-[var(--border)] px-2.5 py-1 text-xs text-dim hover:text-[var(--red)]">
                    Revoke
                  </button>
                )}
              </li>
            );
          })}
        </ul>
      )}
    </section>
  );
}
