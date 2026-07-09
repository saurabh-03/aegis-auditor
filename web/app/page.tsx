'use client';

import { useState } from 'react';
import Link from 'next/link';
import { api, ApiError } from '@/lib/api';
import type { AuditReport } from '@/lib/types';
import { ReportView } from '@/components/ReportView';

export default function Home() {
  const [target, setTarget] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [report, setReport] = useState<AuditReport | null>(null);
  const [reportId, setReportId] = useState<string | null>(null);

  async function run() {
    if (!target.trim()) return;
    setLoading(true);
    setError(null);
    setReport(null);
    try {
      const res = await api.quickScan(target.trim());
      setReport(res.report);
      setReportId(res.id);
    } catch (e) {
      setError(e instanceof ApiError ? e.message : String(e));
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="space-y-6">
      <section className="card p-6">
        <div className="flex flex-col gap-3 sm:flex-row">
          <input
            className="input flex-1 font-mono"
            placeholder="example.com"
            value={target}
            spellCheck={false}
            onChange={(e) => setTarget(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && run()}
          />
          <button onClick={run} disabled={loading} className="btn-primary rounded-lg px-6 py-2.5 font-semibold disabled:opacity-50">
            {loading ? 'Scanning…' : 'Run Audit'}
          </button>
        </div>
        <p className="mt-3 text-xs leading-relaxed text-mute">
          This quick scan runs <strong>passive checks only</strong>. Active checks (port scan, sensitive-file discovery) run on a{' '}
          <strong>verified project</strong> — <Link href="/dashboard" className="text-accent hover:underline">sign in</Link> to create one.
          Aegis performs no exploitation and includes no offensive payloads.
        </p>
        {error && <p className="mt-2 text-sm text-[var(--red)]">{error}</p>}
      </section>

      {loading && <div className="card p-8 text-center text-sm text-mute">Running {target}…</div>}
      {report && reportId && <ReportView report={report} reportId={reportId} />}
    </div>
  );
}
