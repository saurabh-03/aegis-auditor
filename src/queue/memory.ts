/**
 * In-process queue. Default when no REDIS_URL is set. Jobs run asynchronously
 * in the same Node process; progress is fanned out via an EventEmitter.
 *
 * A small concurrency limit keeps the API responsive while a scan runs. This is
 * ideal for single-node deploys, dev, and tests; use BullMqQueue to scale out.
 */

import { EventEmitter } from 'node:events';
import type { Store } from '../store/types.js';
import { processScanJob } from './runner.js';
import type { ProgressEvent, ProgressListener, Queue, ScanJob } from './types.js';

export class InProcessQueue implements Queue {
  readonly kind = 'inprocess' as const;
  private emitter = new EventEmitter();
  private pending: ScanJob[] = [];
  private active = 0;
  private readonly concurrency: number;
  /** Buffer recent events so a WS that connects slightly late still sees them. */
  private buffers = new Map<string, ProgressEvent[]>();

  constructor(private store: Store, concurrency = Number(process.env.SCAN_CONCURRENCY ?? 4)) {
    this.concurrency = Math.max(1, concurrency);
    this.emitter.setMaxListeners(0);
  }

  async init(): Promise<void> {}
  async close(): Promise<void> {
    this.emitter.removeAllListeners();
  }

  async enqueue(job: ScanJob): Promise<void> {
    this.buffers.set(job.scanId, []);
    this.emit({ scanId: job.scanId, type: 'queued', progress: 0, at: new Date().toISOString() });
    this.pending.push(job);
    this.drain();
  }

  subscribe(scanId: string, listener: ProgressListener): () => void {
    // Replay buffered events for this scan.
    for (const e of this.buffers.get(scanId) ?? []) listener(e);
    const handler = (e: ProgressEvent) => {
      if (e.scanId === scanId) listener(e);
    };
    this.emitter.on('progress', handler);
    return () => this.emitter.off('progress', handler);
  }

  private emit(event: ProgressEvent): void {
    const buf = this.buffers.get(event.scanId);
    if (buf) {
      buf.push(event);
      if (buf.length > 64) buf.shift();
    }
    this.emitter.emit('progress', event);
    // Clean up buffer shortly after terminal events.
    if (event.type === 'completed' || event.type === 'failed') {
      setTimeout(() => this.buffers.delete(event.scanId), 60_000).unref?.();
    }
  }

  private drain(): void {
    while (this.active < this.concurrency && this.pending.length > 0) {
      const job = this.pending.shift() as ScanJob;
      this.active += 1;
      void processScanJob(job, this.store, (e) => this.emit(e)).finally(() => {
        this.active -= 1;
        this.drain();
      });
    }
  }
}
