/**
 * Shared scan-job processing logic, used by both queue backends.
 * Runs the engine, emits progress, and persists status transitions.
 */

import { normalizeTarget } from '../core/http.js';
import { runScan } from '../core/scanner.js';
import { ALL_MODULES } from '../modules/registry.js';
import { handleScanCompletion } from '../schedule/alerts.js';
import type { Store } from '../store/types.js';
import type { ProgressEvent, ScanJob } from './types.js';

function now(): string {
  return new Date().toISOString();
}

/**
 * Process one scan job. `emit` publishes progress to whatever transport the
 * queue backend uses (in-process EventEmitter or Redis pub/sub).
 */
export async function processScanJob(
  job: ScanJob,
  store: Store,
  emit: (event: ProgressEvent) => void,
): Promise<void> {
  const total = ALL_MODULES.length;
  let done = 0;
  // Fractional progress of modules still running (module name → 0..1), so a long
  // active module (e.g. Nuclei) advances the overall bar instead of freezing it.
  const inFlight = new Map<string, number>();
  const overall = () => Math.min(1, (done + [...inFlight.values()].reduce((a, b) => a + b, 0)) / total);

  await store.updateScan(job.scanId, { status: 'RUNNING' });
  emit({ scanId: job.scanId, type: 'running', progress: 0, at: now() });

  try {
    const target = normalizeTarget(job.target);
    const report = await runScan(target, ALL_MODULES, job.options, {
      onModuleProgress: (m, fraction, note) => {
        inFlight.set(m.name, fraction);
        emit({
          scanId: job.scanId,
          type: 'module-progress',
          module: m.name,
          moduleProgress: fraction,
          ...(note ? { note } : {}),
          progress: overall(),
          at: now(),
        });
      },
      onModuleFinish: (r) => {
        inFlight.delete(r.module);
        done += 1;
        emit({
          scanId: job.scanId,
          type: 'module',
          module: r.module,
          moduleOk: r.ok,
          progress: overall(),
          at: now(),
        });
      },
    });

    await store.updateScan(job.scanId, {
      status: 'COMPLETED',
      overall: report.overall.score,
      grade: report.overall.grade,
      report,
    });
    emit({
      scanId: job.scanId,
      type: 'completed',
      progress: 1,
      overall: report.overall.score,
      grade: report.overall.grade,
      at: now(),
    });

    // Regression detection & alerting (best-effort; never fails the scan).
    await handleScanCompletion(store, job, report).catch(() => {});
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    await store.updateScan(job.scanId, { status: 'FAILED' });
    emit({ scanId: job.scanId, type: 'failed', error: message, at: now() });
  }
}
