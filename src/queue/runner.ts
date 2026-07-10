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

  await store.updateScan(job.scanId, { status: 'RUNNING' });
  emit({ scanId: job.scanId, type: 'running', progress: 0, at: now() });

  try {
    const target = normalizeTarget(job.target);
    const report = await runScan(target, ALL_MODULES, job.options, {
      onModuleFinish: (r) => {
        done += 1;
        emit({
          scanId: job.scanId,
          type: 'module',
          module: r.module,
          moduleOk: r.ok,
          progress: Math.min(1, done / total),
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
