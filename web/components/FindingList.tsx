'use client';

import { useMemo, useState } from 'react';
import { AnimatePresence, motion } from 'framer-motion';
import type { Finding } from '@/lib/types';
import { sevBadge, sevColor } from '@/lib/ui';

function Row({ f }: { f: Finding }) {
  const [open, setOpen] = useState(false);
  const badge = f.status === 'pass' ? 'bg-green-500/15 text-[var(--green)]' : sevBadge[f.severity];
  return (
    <div className="overflow-hidden rounded-xl border border-[var(--border)] bg-elev" style={{ borderLeft: `4px solid ${f.status === 'pass' ? 'var(--green)' : sevColor[f.severity]}` }}>
      <button onClick={() => setOpen((o) => !o)} className="flex w-full items-center gap-3 px-4 py-3 text-left">
        <span className={`rounded px-2 py-1 text-[10px] font-bold uppercase ${badge}`}>{f.status === 'pass' ? 'pass' : f.severity}</span>
        <span className="flex-1 text-[15px] font-semibold">{f.title}</span>
        <span className="text-[11px] capitalize text-mute">{f.category}</span>
        <span className={`text-mute transition-transform ${open ? 'rotate-90' : ''}`}>▸</span>
      </button>
      <AnimatePresence initial={false}>
        {open && (
          <motion.div initial={{ height: 0, opacity: 0 }} animate={{ height: 'auto', opacity: 1 }} exit={{ height: 0, opacity: 0 }} className="overflow-hidden">
            <div className="space-y-2 px-4 pb-4 text-sm text-dim">
              <Field label="Risk" value={f.risk} />
              <Field label="Why it matters" value={f.whyItMatters} />
              <Field label="Technical" value={f.technical} />
              <Field label="Business impact" value={f.businessImpact} />
              <Field label="Remediation" value={f.remediation} />
              <Field label="Fix effort" value={f.estimatedFixTime} />
              {(f.owasp?.length || f.cve?.length) && (
                <div className="flex flex-wrap gap-1.5 pt-1">
                  {(f.owasp ?? []).map((o) => (
                    <span key={o} className="rounded border border-[var(--border)] bg-elev2 px-2 py-0.5 text-[11px]">{o}</span>
                  ))}
                  {(f.cve ?? []).map((c) => (
                    <span key={c} className="rounded border border-[var(--border)] bg-elev2 px-2 py-0.5 text-[11px] text-[var(--orange)]">{c}</span>
                  ))}
                </div>
              )}
              {f.exampleCode && (
                <pre className="overflow-x-auto rounded-lg border border-[var(--border)] bg-bg p-3 font-mono text-xs text-ink">{f.exampleCode}</pre>
              )}
              {f.references.length > 0 && (
                <div className="pt-1">
                  {f.references.map((r) => (
                    <a key={r} href={r} target="_blank" rel="noopener" className="block text-xs text-accent hover:underline">
                      {r}
                    </a>
                  ))}
                </div>
              )}
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}

function Field({ label, value }: { label: string; value: string }) {
  if (!value) return null;
  return (
    <div className="grid grid-cols-[130px_1fr] gap-3">
      <div className="text-mute">{label}</div>
      <div className="leading-relaxed">{value}</div>
    </div>
  );
}

export function FindingList({ findings }: { findings: Finding[] }) {
  const [q, setQ] = useState('');
  const [sev, setSev] = useState('');
  const [cat, setCat] = useState('');
  const [showPass, setShowPass] = useState(false);

  const cats = useMemo(() => [...new Set(findings.map((f) => f.category))], [findings]);
  const list = findings.filter((f) => {
    if (!showPass && f.status === 'pass') return false;
    if (sev && f.severity !== sev) return false;
    if (cat && f.category !== cat) return false;
    if (q && !`${f.title} ${f.risk} ${f.technical}`.toLowerCase().includes(q.toLowerCase())) return false;
    return true;
  });

  return (
    <div>
      <div className="mb-3 flex flex-wrap items-center gap-2">
        <input value={q} onChange={(e) => setQ(e.target.value)} placeholder="Search findings…" className="input min-w-[180px] flex-1 text-sm" />
        <select value={sev} onChange={(e) => setSev(e.target.value)} className="input text-sm">
          <option value="">All severities</option>
          {['critical', 'high', 'medium', 'low'].map((s) => (
            <option key={s} value={s}>{s}</option>
          ))}
        </select>
        <select value={cat} onChange={(e) => setCat(e.target.value)} className="input text-sm">
          <option value="">All categories</option>
          {cats.map((c) => (
            <option key={c} value={c}>{c}</option>
          ))}
        </select>
        <label className="flex items-center gap-2 text-sm text-mute">
          <input type="checkbox" checked={showPass} onChange={(e) => setShowPass(e.target.checked)} /> show passing
        </label>
      </div>
      <div className="space-y-2">
        {list.length === 0 ? <p className="text-sm text-mute">No findings match the filters.</p> : list.map((f) => <Row key={f.id} f={f} />)}
      </div>
    </div>
  );
}
