'use client';

/**
 * Inspector panels — specialized views rendered from the per-module `data`
 * the scanner already produces (report.data[<module>]). Each panel returns
 * null when its module didn't run, so the section degrades gracefully.
 *
 * Deliberately honest: there is no per-resource "waterfall" here because the
 * passive engine has no browser to measure resource timings. We show only what
 * is really measured. Lab Core Web Vitals arrive with the headless-Chrome worker.
 */

import type { AuditReport } from '@/lib/types';

type Data = Record<string, unknown>;
const get = (report: AuditReport, mod: string): Data | undefined => report.data?.[mod];
const str = (v: unknown): string => (v == null ? '' : String(v));

function sevColor(sev: string): string {
  return sev === 'critical'
    ? 'var(--red)'
    : sev === 'high'
    ? 'var(--orange)'
    : sev === 'medium'
    ? 'var(--yellow)'
    : sev === 'low'
    ? 'var(--accent)'
    : 'var(--text-mute)';
}
function cvssColor(score: number): string {
  return score >= 9 ? 'var(--red)' : score >= 7 ? 'var(--orange)' : score >= 4 ? 'var(--yellow)' : 'var(--accent)';
}

function PanelHead({ title, tag }: { title: string; tag?: string }) {
  return (
    <div className="flex items-center gap-2 border-b border-[var(--border)] px-4 py-3">
      <span className="text-[13px] font-semibold">{title}</span>
      {tag && (
        <span className="ml-auto rounded-md border border-[var(--border)] bg-elev2 px-2 py-0.5 font-mono text-[11px] text-mute">
          {tag}
        </span>
      )}
    </div>
  );
}

/* ---------------- SSL certificate timeline ---------------- */
function CertPanel({ report }: { report: AuditReport }) {
  const d = get(report, 'ssl');
  if (!d || !d['valid_to']) return null;

  const from = new Date(str(d['valid_from'])).getTime();
  const to = new Date(str(d['valid_to'])).getTime();
  const now = Date.now();
  const daysLeft = Math.round((to - now) / 86_400_000);
  const pct = Math.max(0, Math.min(100, ((now - from) / (to - from)) * 100));
  const lifeColor = daysLeft < 0 ? 'var(--red)' : daysLeft < 30 ? 'var(--yellow)' : 'var(--green)';

  const issuer = (d['issuer'] as Record<string, string>) || {};
  const subject = (d['subject'] as Record<string, string>) || {};
  const cipher = (d['cipher'] as Record<string, string>) || {};
  const sans = str(d['subjectaltname']).split(',').filter(Boolean).length;
  const trusted = d['authorized'] === true;
  const fmt = (t: number) => (Number.isFinite(t) ? new Date(t).toLocaleDateString(undefined, { month: 'short', day: 'numeric', year: '2-digit' }) : '—');

  return (
    <div className="card overflow-hidden">
      <PanelHead title="SSL / TLS certificate" tag={str(d['protocol']) || 'tls'} />
      <div className="p-5">
        <div className="relative mx-1 mt-7 h-1 rounded" style={{ background: 'linear-gradient(90deg, var(--green), var(--yellow) 82%, var(--red))' }}>
          <Node left={0} color="var(--green)" label={`Issued\n${fmt(from)}`} />
          <Node left={pct} color="var(--accent)" label="Today" solid />
          <Node left={100} color={lifeColor} label={`Expires\n${fmt(to)}`} />
        </div>
        <div className="mt-3 flex justify-between font-mono text-[11px] text-dim">
          <span>{issuer['O'] || issuer['CN'] || 'Issuer'}</span>
          <span style={{ color: lifeColor }}>{daysLeft < 0 ? `expired ${-daysLeft}d ago` : `${daysLeft} days left`}</span>
        </div>
        <dl className="mt-4 grid grid-cols-[auto_1fr] gap-x-4 gap-y-1.5 font-mono text-[12px]">
          <Row k="Protocol" v={str(d['protocol']) || '—'} />
          <Row k="Cipher" v={cipher['name'] || '—'} />
          <Row k="Subject" v={subject['CN'] || report.target} />
          <Row k="SANs" v={`${sans} name${sans === 1 ? '' : 's'}`} />
          <Row k="Chain" v={trusted ? 'trusted' : 'not trusted'} color={trusted ? 'var(--green)' : 'var(--red)'} />
        </dl>
      </div>
    </div>
  );
}
function Node({ left, color, label, solid }: { left: number; color: string; label: string; solid?: boolean }) {
  return (
    <div className="absolute top-1/2" style={{ left: `${left}%` }}>
      <div
        className="h-3 w-3 -translate-x-1/2 -translate-y-1/2 rounded-full border-2"
        style={{ background: solid ? color : 'var(--bg-elev)', borderColor: color }}
      />
      <div className="absolute -top-8 -translate-x-1/2 whitespace-pre text-center font-mono text-[10px] leading-tight text-mute">{label}</div>
    </div>
  );
}
function Row({ k, v, color }: { k: string; v: string; color?: string }) {
  return (
    <>
      <dt className="text-mute">{k}</dt>
      <dd className="m-0 truncate" style={color ? { color } : undefined}>{v}</dd>
    </>
  );
}

/* ---------------- Security headers inspector ---------------- */
const TRACKED = [
  ['content-security-policy', 'CSP'],
  ['strict-transport-security', 'HSTS'],
  ['x-frame-options', 'X-Frame-Options'],
  ['x-content-type-options', 'nosniff'],
  ['referrer-policy', 'Referrer-Policy'],
  ['permissions-policy', 'Permissions-Policy'],
  ['cross-origin-opener-policy', 'COOP'],
] as const;
const LEAKY = ['server', 'x-powered-by'];

function HeadersPanel({ report }: { report: AuditReport }) {
  const d = get(report, 'security-headers');
  const headers = (d?.['headers'] as Record<string, string>) || null;
  if (!headers) return null;

  const present = TRACKED.filter(([h]) => headers[h]).length;
  const grade = present >= 6 ? 'A' : present >= 4 ? 'B' : present >= 2 ? 'C' : present >= 1 ? 'D' : 'F';

  return (
    <div className="card overflow-hidden">
      <PanelHead title="Security headers inspector" tag={`grade ${grade}`} />
      <div className="flex flex-col gap-1.5 p-4 font-mono text-[12px]">
        {TRACKED.map(([h, label]) => {
          const val = headers[h];
          const ok = Boolean(val);
          return (
            <div key={h} className="flex items-center gap-3">
              <Pip color={ok ? 'var(--green)' : 'var(--red)'} sym={ok ? '✓' : '✕'} />
              <span className="w-[190px] shrink-0 text-dim">{label}</span>
              <span className="truncate text-mute" title={val || 'absent'}>{val ? val : '— absent'}</span>
            </div>
          );
        })}
        {LEAKY.filter((h) => headers[h]).map((h) => (
          <div key={h} className="flex items-center gap-3">
            <Pip color="var(--yellow)" sym="!" />
            <span className="w-[190px] shrink-0 text-dim">{h}</span>
            <span className="truncate text-mute">discloses “{headers[h]}”</span>
          </div>
        ))}
      </div>
    </div>
  );
}
function Pip({ color, sym }: { color: string; sym: string }) {
  return (
    <span className="grid h-4 w-4 shrink-0 place-items-center rounded text-[10px] text-white" style={{ background: color }}>
      {sym}
    </span>
  );
}

/* ---------------- CVE explorer ---------------- */
interface Match {
  component: string;
  version: string;
  cve: string;
  cvss: number;
  severity: string;
  weakness: string;
  fixedIn: string;
  reference?: string;
}
function CvePanel({ report }: { report: AuditReport }) {
  const d = get(report, 'dependencies');
  if (!d) return null;
  const matches = (d['matches'] as Match[]) || [];
  const source = str(d['source']) || 'dependency intel';

  return (
    <div className="card overflow-hidden">
      <PanelHead title="CVE explorer" tag={source} />
      {matches.length === 0 ? (
        <div className="p-5 text-[13px] text-dim">
          <span style={{ color: 'var(--green)' }}>✓ No known CVEs matched</span> for the component versions detected on the
          homepage.
          <div className="mt-1.5 text-[12px] text-mute">
            Passive detection only sees libraries referenced in the page HTML. Run software-composition analysis in CI for
            authoritative coverage.
          </div>
        </div>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full border-collapse text-[12.5px]">
            <thead>
              <tr className="text-left font-mono text-[10.5px] uppercase tracking-wider text-mute">
                <th className="border-b border-[var(--border)] px-4 py-3 font-medium">Component</th>
                <th className="border-b border-[var(--border)] px-4 py-3 font-medium">CVE</th>
                <th className="border-b border-[var(--border)] px-4 py-3 font-medium">Weakness</th>
                <th className="border-b border-[var(--border)] px-4 py-3 font-medium">CVSS</th>
                <th className="border-b border-[var(--border)] px-4 py-3 font-medium">Fixed in</th>
              </tr>
            </thead>
            <tbody>
              {matches.map((m) => (
                <tr key={m.cve + m.component}>
                  <td className="border-b border-[var(--border)] px-4 py-2.5 font-mono">{m.component} {m.version}</td>
                  <td className="border-b border-[var(--border)] px-4 py-2.5">
                    <a
                      className="font-mono"
                      style={{ color: 'var(--accent)' }}
                      href={m.reference || `https://nvd.nist.gov/vuln/detail/${m.cve}`}
                      target="_blank"
                      rel="noopener"
                    >
                      {m.cve}
                    </a>
                  </td>
                  <td className="border-b border-[var(--border)] px-4 py-2.5 text-dim">{m.weakness}</td>
                  <td className="border-b border-[var(--border)] px-4 py-2.5">
                    <div className="flex items-center gap-2">
                      <span className="h-1.5 w-[62px] overflow-hidden rounded border border-[var(--border)] bg-elev2">
                        <span className="block h-full" style={{ width: `${(m.cvss / 10) * 100}%`, background: cvssColor(m.cvss) }} />
                      </span>
                      <b className="font-mono tabular-nums">{m.cvss.toFixed(1)}</b>
                    </div>
                  </td>
                  <td className="border-b border-[var(--border)] px-4 py-2.5 font-mono">{m.fixedIn}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

/* ---------------- Technology & infrastructure map ---------------- */
interface Tech {
  name: string;
  category: string;
  version?: string;
}
function TechPanel({ report }: { report: AuditReport }) {
  const tech = get(report, 'tech');
  const dns = get(report, 'dns');
  const scale = get(report, 'scalability');
  const detected = (tech?.['detected'] as Tech[]) || [];
  if (!detected.length && !dns && !scale) return null;

  const chips: [string, string][] = [];
  if (scale?.['cdn']) chips.push(['CDN', str(scale['cdn'])]);
  if (scale?.['connection']) chips.push(['Conn', str(scale['connection']) || 'keep-alive']);
  detected.forEach((t) => chips.push([t.category, `${t.name}${t.version ? ' ' + t.version : ''}`]));
  if (dns) {
    if (dns['spf']) chips.push(['DNS', 'SPF']);
    if (dns['dmarc']) chips.push(['DNS', 'DMARC']);
    const aaaa = dns['aaaa'] as unknown[] | null;
    if (aaaa && aaaa.length) chips.push(['IPv6', 'dual-stack']);
  }

  return (
    <div className="card overflow-hidden">
      <PanelHead title="Technology & infrastructure" tag={`${detected.length} detected`} />
      <div className="flex flex-wrap gap-2 p-4">
        {chips.map(([k, v], i) => (
          <span key={k + v + i} className="inline-flex items-center gap-2 rounded-lg border border-[var(--border)] bg-elev2 px-3 py-2 text-[12.5px]">
            <span className="font-mono text-[10px] uppercase tracking-wider text-mute">{k}</span>
            <span className="font-semibold">{v}</span>
          </span>
        ))}
        {chips.length === 0 && <span className="text-[13px] text-mute">No technologies fingerprinted.</span>}
      </div>
    </div>
  );
}

/* ---------------- Core Web Vitals (lab) ---------------- */
function vBand(value: number, good: number, poor: number): string {
  return value < good ? 'var(--green)' : value < poor ? 'var(--yellow)' : 'var(--red)';
}
function WebVitalsPanel({ report }: { report: AuditReport }) {
  const d = get(report, 'webvitals');
  if (!d || d['lcp'] == null) return null; // only render when a browser run produced metrics
  const lcp = Number(d['lcp']);
  const cls = Number(d['cls']);
  const tbt = Number(d['tbt']);
  const fcp = Number(d['fcp']);
  const ttfb = Number(d['ttfb']);

  const tiles: { label: string; value: string; color: string }[] = [
    { label: 'LCP', value: `${(lcp / 1000).toFixed(2)}s`, color: vBand(lcp, 2500, 4000) },
    { label: 'CLS', value: cls.toFixed(3), color: vBand(cls, 0.1, 0.25) },
    { label: 'TBT', value: `${tbt}ms`, color: vBand(tbt, 200, 600) },
    { label: 'FCP', value: `${(fcp / 1000).toFixed(2)}s`, color: vBand(fcp, 1800, 3000) },
    { label: 'TTFB', value: `${ttfb}ms`, color: vBand(ttfb, 800, 1800) },
  ];

  return (
    <div className="card overflow-hidden">
      <PanelHead title="Core Web Vitals (lab)" tag={`${str(d['formFactor']) || 'desktop'} · headless`} />
      <div className="grid grid-cols-2 gap-3 p-4 sm:grid-cols-5">
        {tiles.map((t) => (
          <div key={t.label} className="rounded-lg border border-[var(--border)] bg-elev2 p-3 text-center">
            <div className="font-mono text-[10px] uppercase tracking-wider text-mute">{t.label}</div>
            <div className="mt-1 font-mono text-lg font-bold tabular-nums" style={{ color: t.color }}>{t.value}</div>
          </div>
        ))}
      </div>
    </div>
  );
}

/* ---------------- Resource waterfall (real timings) ---------------- */
interface Res {
  name: string;
  type: string;
  start: number;
  duration: number;
  size: number;
}
const RES_COLOR: Record<string, string> = {
  navigation: 'var(--accent)',
  link: 'var(--green)',
  css: 'var(--green)',
  script: 'var(--yellow)',
  img: 'var(--orange)',
  fetch: 'var(--accent-2)',
  xmlhttprequest: 'var(--accent-2)',
};
function shortName(url: string): string {
  try {
    const u = new URL(url);
    const last = u.pathname.split('/').filter(Boolean).pop() || u.hostname;
    return last.length > 28 ? last.slice(0, 27) + '…' : last;
  } catch {
    return url.slice(0, 28);
  }
}
function WaterfallPanel({ report }: { report: AuditReport }) {
  const d = get(report, 'webvitals');
  const resources = (d?.['resources'] as Res[]) || [];
  if (!resources.length) return null;
  const rows = resources.slice(0, 30);
  const maxEnd = Math.max(...rows.map((r) => r.start + r.duration), 1);

  return (
    <div className="card overflow-hidden">
      <PanelHead title="Resource waterfall" tag={`${resources.length} requests`} />
      <div className="flex flex-col gap-1.5 p-4">
        {rows.map((r, i) => (
          <div key={i} className="grid grid-cols-[150px_1fr_54px] items-center gap-2.5 font-mono text-[11px]">
            <span className="truncate text-dim" title={r.name}>{shortName(r.name)}</span>
            <span className="relative h-3 rounded border border-[var(--border)] bg-elev2">
              <span
                className="absolute bottom-px top-px rounded-sm"
                style={{
                  left: `${(r.start / maxEnd) * 100}%`,
                  width: `${Math.max(0.5, (r.duration / maxEnd) * 100)}%`,
                  background: RES_COLOR[r.type] || 'var(--text-mute)',
                }}
              />
            </span>
            <span className="text-right text-mute">{r.duration}ms</span>
          </div>
        ))}
      </div>
    </div>
  );
}

/* ---------------- wrapper ---------------- */
export function Inspectors({ report }: { report: AuditReport }) {
  // If no per-module data was returned at all, render nothing.
  if (!report.data) return null;

  return (
    <div className="space-y-4">
      <div className="text-sm font-semibold">Inspectors</div>
      <WebVitalsPanel report={report} />
      <div className="grid gap-4 md:grid-cols-2">
        <CertPanel report={report} />
        <HeadersPanel report={report} />
      </div>
      <CvePanel report={report} />
      <WaterfallPanel report={report} />
      <TechPanel report={report} />
    </div>
  );
}
