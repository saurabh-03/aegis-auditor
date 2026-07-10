'use client';

/**
 * OWASP Top 10 explorer + technology graph. Both render from data the scan
 * already produces (findings[].owasp, report.data.tech/dns/scalability).
 */

import type { AuditReport, Finding, Severity } from '@/lib/types';

const SEV_COLOR: Record<Severity, string> = {
  critical: 'var(--red)',
  high: 'var(--orange)',
  medium: 'var(--yellow)',
  low: 'var(--accent)',
  info: 'var(--text-mute)',
};
const SEV_RANK: Record<Severity, number> = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };

const OWASP_10: { id: string; name: string }[] = [
  { id: 'A01', name: 'Broken Access Control' },
  { id: 'A02', name: 'Cryptographic Failures' },
  { id: 'A03', name: 'Injection' },
  { id: 'A04', name: 'Insecure Design' },
  { id: 'A05', name: 'Security Misconfiguration' },
  { id: 'A06', name: 'Vulnerable & Outdated Components' },
  { id: 'A07', name: 'Identification & Auth Failures' },
  { id: 'A08', name: 'Software & Data Integrity Failures' },
  { id: 'A09', name: 'Security Logging & Monitoring Failures' },
  { id: 'A10', name: 'Server-Side Request Forgery' },
];

function PanelHead({ title, tag }: { title: string; tag?: string }) {
  return (
    <div className="flex items-center gap-2 border-b border-[var(--border)] px-4 py-3">
      <span className="text-[13px] font-semibold">{title}</span>
      {tag && <span className="ml-auto rounded-md border border-[var(--border)] bg-elev2 px-2 py-0.5 font-mono text-[11px] text-mute">{tag}</span>}
    </div>
  );
}

/* ---------------- OWASP Top 10 explorer ---------------- */
function OwaspExplorer({ report }: { report: AuditReport }) {
  // Bucket findings by OWASP category prefix (A01..A10).
  const buckets = new Map<string, { fails: Finding[]; passes: number }>();
  for (const f of report.findings) {
    if (!f.owasp?.length) continue;
    for (const tag of f.owasp) {
      const id = tag.slice(0, 3);
      const b = buckets.get(id) ?? { fails: [], passes: 0 };
      if (f.status === 'pass') b.passes += 1;
      else b.fails.push(f);
      buckets.set(id, b);
    }
  }
  const mappedCount = [...buckets.values()].reduce((n, b) => n + b.fails.length, 0);

  return (
    <div className="card overflow-hidden">
      <PanelHead title="OWASP Top 10 (2021)" tag={`${mappedCount} mapped`} />
      <div className="flex flex-col divide-y divide-[var(--border)]">
        {OWASP_10.map((cat) => {
          const b = buckets.get(cat.id);
          const fails = b?.fails ?? [];
          const worst = fails.reduce<Severity>((w, f) => (SEV_RANK[f.severity] > SEV_RANK[w] ? f.severity : w), 'info');
          const color = fails.length ? SEV_COLOR[worst] : 'var(--green)';
          return (
            <div key={cat.id} className="flex items-center gap-3 px-4 py-2.5 text-[12.5px]">
              <span className="font-mono text-[11px] text-mute">{cat.id}</span>
              <span className="flex-1">{cat.name}</span>
              {fails.length > 0 ? (
                <span className="rounded-full px-2 py-0.5 text-[11px] font-semibold" style={{ color, background: `color-mix(in oklab, ${color} 16%, transparent)` }}>
                  {fails.length} issue{fails.length > 1 ? 's' : ''}
                </span>
              ) : (
                <span className="text-[11px] text-[var(--green)]">✓ clear</span>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}

/* ---------------- Technology graph ---------------- */
interface Tech {
  name: string;
  category: string;
  version?: string;
}
const CAT_COLOR: Record<string, string> = {
  CMS: 'var(--accent)',
  Framework: 'var(--accent-2)',
  Frontend: 'var(--accent-2)',
  'JS library': 'var(--yellow)',
  'CSS framework': 'var(--yellow)',
  CDN: 'var(--green)',
  Hosting: 'var(--green)',
  'Web server': 'var(--orange)',
  Language: 'var(--orange)',
  Analytics: 'var(--text-mute)',
  DNS: 'var(--text-mute)',
  Infra: 'var(--green)',
};

function TechGraph({ report }: { report: AuditReport }) {
  const data = report.data ?? {};
  const detected = ((data['tech'] as Record<string, unknown>)?.['detected'] as Tech[]) ?? [];
  const dns = data['dns'] as Record<string, unknown> | undefined;
  const scale = data['scalability'] as Record<string, unknown> | undefined;

  const nodes: Tech[] = [...detected];
  if (scale?.['cdn']) nodes.push({ name: String(scale['cdn']), category: 'CDN' });
  if (dns?.['spf']) nodes.push({ name: 'SPF', category: 'DNS' });
  if (dns?.['dmarc']) nodes.push({ name: 'DMARC', category: 'DNS' });

  if (nodes.length === 0) return null;

  const W = 460, H = 300, cx = W / 2, cy = H / 2;
  const r = Math.min(W, H) / 2 - 56;
  let host = report.target;
  try {
    host = new URL(report.target).hostname;
  } catch {
    /* keep */
  }

  return (
    <div className="card overflow-hidden">
      <PanelHead title="Technology graph" tag={`${nodes.length} nodes`} />
      <div className="overflow-x-auto p-2">
        <svg viewBox={`0 0 ${W} ${H}`} width="100%" style={{ minWidth: 360, maxWidth: 560, display: 'block', margin: '0 auto' }}>
          {nodes.map((n, i) => {
            const a = (i / nodes.length) * Math.PI * 2 - Math.PI / 2;
            const x = cx + r * Math.cos(a);
            const y = cy + r * Math.sin(a);
            return <line key={'l' + i} x1={cx} y1={cy} x2={x} y2={y} stroke="var(--border)" strokeWidth={1} />;
          })}
          {/* center node */}
          <circle cx={cx} cy={cy} r={30} fill="var(--bg-elev-2)" stroke="var(--accent)" strokeWidth={1.5} />
          <text x={cx} y={cy + 4} textAnchor="middle" fontSize={10} fill="var(--text)" fontFamily="var(--font-mono, monospace)">
            {host.length > 14 ? host.slice(0, 12) + '…' : host}
          </text>
          {nodes.map((n, i) => {
            const a = (i / nodes.length) * Math.PI * 2 - Math.PI / 2;
            const x = cx + r * Math.cos(a);
            const y = cy + r * Math.sin(a);
            const color = CAT_COLOR[n.category] ?? 'var(--text-mute)';
            const label = `${n.name}${n.version ? ' ' + n.version : ''}`;
            const w = Math.max(44, label.length * 6.2 + 12);
            return (
              <g key={'n' + i}>
                <rect x={x - w / 2} y={y - 11} width={w} height={22} rx={11} fill="var(--bg-elev)" stroke={color} strokeWidth={1.5} />
                <circle cx={x - w / 2 + 9} cy={y} r={3} fill={color} />
                <text x={x + 4} y={y + 3.5} textAnchor="middle" fontSize={10} fill="var(--text-dim)">
                  {label.length > 18 ? label.slice(0, 16) + '…' : label}
                </text>
              </g>
            );
          })}
        </svg>
      </div>
    </div>
  );
}

export function Explorers({ report }: { report: AuditReport }) {
  if (!report.data && !report.findings.some((f) => f.owasp?.length)) return null;
  return (
    <div className="space-y-4">
      <div className="text-sm font-semibold">Explorers</div>
      <div className="grid gap-4 md:grid-cols-2">
        <OwaspExplorer report={report} />
        <TechGraph report={report} />
      </div>
    </div>
  );
}
