/**
 * Post-scan regression alerting.
 *
 * After a project-scoped scan completes, compare it to the previous scan for
 * that project. If it's a regression, record a notification and fire any
 * webhooks configured on the project's schedules. Best-effort — never throws
 * into the scan pipeline.
 */

import { createHmac } from 'node:crypto';
import { assessRegression, diffReports } from '../core/diff.js';
import type { AuditReport } from '../core/types.js';
import type { Store } from '../store/types.js';

interface CompletedJob {
  scanId: string;
  projectId: string | null;
  orgId: string | null;
}

export async function handleScanCompletion(store: Store, job: CompletedJob, report: AuditReport): Promise<void> {
  // Only project-scoped scans have a baseline to compare against.
  if (!job.projectId || !job.orgId) return;

  const prev = await store.previousScanForProject(job.projectId, job.scanId);
  const diff = diffReports(prev?.report ?? null, report);
  const assessment = assessRegression(diff);
  if (!diff || !assessment.isRegression) return;

  const project = await store.getProject(job.projectId);
  const name = project?.name ?? report.target;
  const title = `${assessment.level === 'major' ? '🔴' : '🟠'} Regression on ${name} (${diff.prevScore} → ${diff.currScore})`;
  const body = assessment.reasons.join(' · ');

  await store.createNotification({
    orgId: job.orgId,
    type: 'regression',
    scanId: job.scanId,
    projectId: job.projectId,
    title,
    body,
    severity: assessment.level === 'major' ? 'critical' : 'warning',
  });

  const payload = {
    event: 'regression' as const,
    level: assessment.level,
    project: name,
    target: report.target,
    scanId: job.scanId,
    prevScore: diff.prevScore,
    currScore: diff.currScore,
    scoreDelta: diff.scoreDelta,
    newFindings: diff.newFindings,
    reasons: assessment.reasons,
    at: new Date().toISOString(),
  };

  // Per-schedule webhooks (legacy, unsigned) + org-level webhooks (HMAC-signed).
  const schedules = await store.listSchedules({ projectId: job.projectId });
  const orgHooks = await store.webhooksForEvent(job.orgId, 'regression');
  await Promise.all([
    ...schedules.filter((s) => s.webhookUrl).map((s) => fireWebhook(s.webhookUrl as string, payload)),
    ...orgHooks.map((h) => fireWebhook(h.url, payload, h.secret)),
  ]);
}

/** POST the payload; when a secret is given, add an HMAC-SHA256 signature header. */
export async function fireWebhook(url: string, payload: unknown, secret?: string): Promise<void> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 5000);
  const body = JSON.stringify(payload);
  const headers: Record<string, string> = { 'content-type': 'application/json', 'user-agent': 'AegisAuditor/webhook' };
  if (secret) headers['x-aegis-signature'] = 'sha256=' + createHmac('sha256', secret).update(body).digest('hex');
  try {
    await fetch(url, { method: 'POST', headers, body, signal: controller.signal });
  } catch {
    /* best-effort */
  } finally {
    clearTimeout(timer);
  }
}
