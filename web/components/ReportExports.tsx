'use client';

import { useState } from 'react';

type Persona = 'executive' | 'security' | 'compliance' | 'developer';
const PERSONAS: { id: Persona; label: string }[] = [
  { id: 'executive', label: 'Executive' },
  { id: 'security', label: 'Security' },
  { id: 'compliance', label: 'Compliance' },
  { id: 'developer', label: 'Developer' },
];

export function ReportExports({ reportId }: { reportId: string }) {
  const [persona, setPersona] = useState<Persona>('executive');
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState<string | null>(null);

  function openHtml() {
    window.open(`/api/reports/${reportId}/report.html?persona=${persona}`, '_blank', 'noopener');
  }

  async function downloadPdf() {
    setBusy(true);
    setMsg(null);
    try {
      const res = await fetch(`/api/reports/${reportId}/report.pdf?persona=${persona}`);
      if (res.status === 501) {
        const j = await res.json().catch(() => ({}));
        setMsg(j.message ?? 'PDF rendering is not enabled on the server. Use the HTML report.');
        return;
      }
      if (!res.ok) {
        setMsg('Could not generate the PDF.');
        return;
      }
      const blob = await res.blob();
      const a = document.createElement('a');
      a.href = URL.createObjectURL(blob);
      a.download = `aegis-${persona}-${reportId}.pdf`;
      a.click();
      URL.revokeObjectURL(a.href);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="rounded-lg border border-[var(--border)] bg-elev2 p-3">
      <div className="flex flex-wrap items-center gap-2">
        <span className="text-xs font-semibold text-dim">Report</span>
        <select
          value={persona}
          onChange={(e) => setPersona(e.target.value as Persona)}
          className="rounded-lg border border-[var(--border)] bg-elev px-2 py-1.5 text-xs"
        >
          {PERSONAS.map((p) => (
            <option key={p.id} value={p.id}>
              {p.label}
            </option>
          ))}
        </select>
        <button onClick={openHtml} className="rounded-lg border border-[var(--border)] px-3 py-1.5 text-xs text-dim hover:text-ink">
          Open HTML
        </button>
        <button onClick={downloadPdf} disabled={busy} className="btn-primary rounded-lg px-3 py-1.5 text-xs font-semibold disabled:opacity-50">
          {busy ? 'Rendering…' : '⬇ PDF'}
        </button>
        <span className="text-[11px] text-mute">audience-specific: exec · security · compliance · developer</span>
      </div>
      {msg && <p className="mt-2 text-xs text-[var(--orange)]">{msg}</p>}
    </div>
  );
}
