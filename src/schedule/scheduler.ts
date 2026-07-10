/**
 * Recurring-scan scheduler.
 *
 * Polls the store for due schedules and enqueues a scan for each, then advances
 * the schedule's nextRunAt by its cadence. Runs in-process on a single node
 * (the API process by default); for multi-node, exactly one instance should own
 * scheduling. The interval is unref'd so it never keeps the process alive on its
 * own (important for tests and clean shutdown).
 */

import { config } from '../core/config.js';
import type { Queue } from '../queue/types.js';
import { nextRunFrom, type Store } from '../store/types.js';

export class Scheduler {
  private timer: ReturnType<typeof setInterval> | undefined;

  constructor(
    private store: Store,
    private queue: Queue,
    private intervalMs: number = config.scheduler.intervalMs,
  ) {}

  start(): void {
    if (this.timer) return;
    this.timer = setInterval(() => void this.tick().catch(() => {}), this.intervalMs);
    // Do not hold the event loop open just for the scheduler.
    if (typeof this.timer.unref === 'function') this.timer.unref();
    // Kick once shortly after start (also unref'd).
    void this.tick().catch(() => {});
  }

  stop(): void {
    if (this.timer) clearInterval(this.timer);
    this.timer = undefined;
  }

  /** Dispatch all currently-due schedules. Returns how many scans were enqueued. */
  async tick(): Promise<number> {
    const due = await this.store.listDueSchedules(new Date().toISOString());
    let dispatched = 0;

    for (const s of due) {
      const project = await this.store.getProject(s.projectId);
      if (!project) {
        // Orphaned schedule — disable it so we stop retrying.
        await this.store.updateSchedule(s.id, { enabled: false });
        continue;
      }

      // Active checks only run if the schedule asked for them AND ownership is verified.
      const includeActive = s.includeActive && Boolean(project.verifiedAt);

      const rec = await this.store.saveScan({
        projectId: project.id,
        orgId: s.orgId,
        userId: null,
        target: project.target,
        status: 'QUEUED',
        authorized: includeActive,
        overall: null,
        grade: null,
        report: null,
      });

      await this.queue.enqueue({
        scanId: rec.id,
        target: project.target,
        projectId: project.id,
        orgId: s.orgId,
        userId: null,
        options: {
          authorized: includeActive,
          includeActive,
          timeoutMs: config.defaultTimeoutMs,
        },
      });

      await this.store.updateSchedule(s.id, {
        lastRunAt: new Date().toISOString(),
        nextRunAt: nextRunFrom(s.cadence),
      });
      dispatched += 1;
    }

    return dispatched;
  }
}
