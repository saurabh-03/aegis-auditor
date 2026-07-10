'use client';

import { useEffect, useState } from 'react';
import { useRouter } from 'next/navigation';
import { useAuth } from '@/lib/auth';
import { api, ApiError } from '@/lib/api';
import type { AuditReport, Project } from '@/lib/types';
import { useScanStream } from '@/lib/useScanStream';
import { LiveProgress } from '@/components/LiveProgress';
import { ReportView } from '@/components/ReportView';
import { ProjectCard } from '@/components/ProjectCard';
import { RegressionBanner } from '@/components/RegressionBanner';

export default function Dashboard() {
  const { user, orgs, loading } = useAuth();
  const router = useRouter();
  const [projects, setProjects] = useState<Project[]>([]);
  const [name, setName] = useState('');
  const [target, setTarget] = useState('');
  const [verification, setVerification] = useState<{ token: string; instructions: Record<string, string> } | null>(null);
  const [error, setError] = useState<string | null>(null);

  const [scanId, setScanId] = useState<string | null>(null);
  const [report, setReport] = useState<AuditReport | null>(null);
  const stream = useScanStream(scanId);
  const orgId = orgs[0]?.id;

  useEffect(() => {
    if (!loading && !user) router.push('/login');
  }, [loading, user, router]);

  async function loadProjects() {
    if (!orgId) return;
    try {
      const res = await api.projects(orgId);
      setProjects(res.projects);
    } catch {
      /* ignore */
    }
  }
  useEffect(() => {
    void loadProjects();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [orgId]);

  // When a scan completes, fetch the full report.
  useEffect(() => {
    if (stream.status === 'completed' && scanId) {
      api.scanStatus(scanId).then((s) => s.report && setReport(s.report)).catch(() => {});
    }
  }, [stream.status, scanId]);

  async function createProject(e: React.FormEvent) {
    e.preventDefault();
    if (!orgId) return;
    setError(null);
    try {
      const res = await api.createProject(orgId, name, target);
      setVerification(res.verification);
      setName('');
      setTarget('');
      await loadProjects();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : String(err));
    }
  }

  async function runScan(project: Project | null, includeActive: boolean) {
    setReport(null);
    setError(null);
    try {
      const res = await api.enqueueScan(project ? { projectId: project.id, includeActive } : { target, includeActive: false });
      setScanId(res.scanId);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : String(err));
    }
  }

  if (loading || !user) return <div className="card p-8 text-center text-mute">Loading…</div>;

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-lg font-bold">Dashboard</h1>
        <p className="text-sm text-mute">{orgs[0]?.name}</p>
      </div>

      <section className="card p-5">
        <div className="mb-3 text-sm font-semibold">New project</div>
        <form onSubmit={createProject} className="flex flex-wrap gap-2">
          <input className="input flex-1" placeholder="Project name" value={name} onChange={(e) => setName(e.target.value)} required />
          <input className="input flex-1 font-mono" placeholder="example.com" value={target} onChange={(e) => setTarget(e.target.value)} required />
          <button className="btn-primary rounded-lg px-5 py-2 font-semibold">Create</button>
        </form>
        {error && <p className="mt-2 text-sm text-[var(--red)]">{error}</p>}
        {verification && (
          <div className="mt-3 rounded-lg border border-[var(--border)] bg-elev2 p-3 text-xs text-dim">
            <div className="mb-1 font-semibold text-ink">Verify ownership to unlock active scans:</div>
            <div className="font-mono">DNS TXT: aegis-verify={verification.token}</div>
            <div className="font-mono">or serve token at /.well-known/aegis-verify</div>
          </div>
        )}
      </section>

      <section>
        <div className="mb-3 text-sm font-semibold">Projects</div>
        {projects.length === 0 ? (
          <p className="text-sm text-mute">No projects yet. Create one above.</p>
        ) : (
          <div className="grid gap-3 sm:grid-cols-2">
            {projects.map((p) => (
              <ProjectCard key={p.id} project={p} onScan={runScan} onChanged={loadProjects} />
            ))}
          </div>
        )}
      </section>

      {scanId && stream.status !== 'completed' && <LiveProgress state={stream} />}
      {report && (
        <section className="space-y-3">
          <div className="text-sm font-semibold">Latest scan</div>
          {scanId && <RegressionBanner scanId={scanId} />}
          <ReportView report={report} reportId={scanId ?? undefined} />
        </section>
      )}
    </div>
  );
}
