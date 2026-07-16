'use client';

import { useState } from 'react';
import { api, ApiError } from '@/lib/api';
import type { Project, ScanAuthInput } from '@/lib/types';
import { ScheduleControls } from './ScheduleControls';

export function ProjectCard({
  project,
  onScan,
  onChanged,
}: {
  project: Project;
  onScan: (p: Project, includeActive: boolean, auth?: ScanAuthInput) => void;
  onChanged: () => void;
}) {
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState<string | null>(null);
  const verified = Boolean(project.verifiedAt);

  // Optional authenticated-scan inputs (verified projects only).
  const [showAuth, setShowAuth] = useState(false);
  const [cookie, setCookie] = useState('');
  const [hdrName, setHdrName] = useState('');
  const [hdrValue, setHdrValue] = useState('');
  const [exclude, setExclude] = useState('');
  const [loginUrl, setLoginUrl] = useState('');
  const [loginUser, setLoginUser] = useState('');
  const [loginPass, setLoginPass] = useState('');

  /** Assemble the auth payload, or undefined if the panel is empty/closed. */
  function buildAuth(): ScanAuthInput | undefined {
    if (!showAuth) return undefined;
    const a: ScanAuthInput = {};
    if (hdrName.trim() && hdrValue.trim()) a.authHeaders = { [hdrName.trim()]: hdrValue };
    if (cookie.trim()) a.authCookie = cookie.trim();
    const pats = exclude.split(',').map((s) => s.trim()).filter(Boolean);
    if (pats.length) a.excludeUrlPatterns = pats;
    if (loginUrl.trim() && loginUser.trim() && loginPass) {
      a.formLogin = { loginUrl: loginUrl.trim(), username: loginUser.trim(), password: loginPass };
    }
    return Object.keys(a).length ? a : undefined;
  }

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
        <button onClick={() => onScan(project, false, buildAuth())} className="rounded-lg border border-[var(--border)] px-3 py-1.5 text-sm text-dim hover:text-ink">
          Passive scan
        </button>
        {verified ? (
          <button onClick={() => onScan(project, true, buildAuth())} className="btn-primary rounded-lg px-3 py-1.5 text-sm font-semibold">
            Active scan
          </button>
        ) : (
          <button onClick={verify} disabled={busy} className="rounded-lg border border-[var(--border)] px-3 py-1.5 text-sm text-dim hover:text-ink disabled:opacity-50">
            {busy ? 'Verifying…' : 'Verify ownership'}
          </button>
        )}
        {verified && (
          <button
            onClick={() => setShowAuth((v) => !v)}
            className="rounded-lg border border-[var(--border)] px-3 py-1.5 text-sm text-dim hover:text-ink"
          >
            {showAuth ? '− Authentication' : '+ Authentication'}
          </button>
        )}
      </div>

      {verified && showAuth && (
        <div className="mt-3 space-y-2 rounded-lg border border-[var(--border)] bg-elev2 p-3">
          <p className="text-[11px] text-mute">
            Optional — scan behind a login. Credentials are sent to the target only for this scan and are never stored.
          </p>
          <textarea
            className="input w-full font-mono text-xs"
            rows={2}
            placeholder="Cookie header, e.g. session=abc; role=admin"
            value={cookie}
            onChange={(e) => setCookie(e.target.value)}
          />
          <div className="flex gap-2">
            <input className="input w-1/3 font-mono text-xs" placeholder="Header name" value={hdrName} onChange={(e) => setHdrName(e.target.value)} />
            <input className="input flex-1 font-mono text-xs" placeholder="Header value (e.g. Bearer …)" value={hdrValue} onChange={(e) => setHdrValue(e.target.value)} />
          </div>
          <input className="input w-full font-mono text-xs" placeholder="Exclude URL patterns (comma-separated)" value={exclude} onChange={(e) => setExclude(e.target.value)} />
          <div className="border-t border-[var(--border)] pt-2">
            <p className="mb-1 text-[11px] text-mute">Or automate a form-login (needs the browser engine):</p>
            <input className="input mb-2 w-full font-mono text-xs" placeholder="Login page URL (same site)" value={loginUrl} onChange={(e) => setLoginUrl(e.target.value)} />
            <div className="flex gap-2">
              <input className="input flex-1 text-xs" placeholder="Username" value={loginUser} onChange={(e) => setLoginUser(e.target.value)} autoComplete="off" />
              <input className="input flex-1 text-xs" type="password" placeholder="Password" value={loginPass} onChange={(e) => setLoginPass(e.target.value)} autoComplete="off" />
            </div>
          </div>
        </div>
      )}
      {msg && <p className="mt-2 text-xs text-mute">{msg}</p>}
      <ScheduleControls projectId={project.id} verified={verified} />
    </div>
  );
}
