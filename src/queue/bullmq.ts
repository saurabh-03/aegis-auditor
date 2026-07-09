/**
 * BullMQ + Redis queue. Activated when REDIS_URL is set. Enables horizontal
 * scaling: any number of worker processes consume the `scans` queue, and
 * progress is fanned out to all API nodes over a Redis pub/sub channel so a
 * WebSocket client connected to any node receives live updates.
 *
 * Roles (AEGIS_ROLE):
 *   "api"    → enqueue + subscribe only (no Worker)
 *   "worker" → Worker only
 *   unset    → both (single-node default)
 */

import { EventEmitter } from 'node:events';
import { Queue as BullQueue, Worker, type Job } from 'bullmq';
import IORedis, { type Redis } from 'ioredis';
import type { Store } from '../store/types.js';
import { processScanJob } from './runner.js';
import type { ProgressEvent, ProgressListener, Queue, ScanJob } from './types.js';

const QUEUE_NAME = 'scans';
const CHANNEL = 'aegis:progress';

/** Parse a redis:// URL into bullmq-compatible connection options. */
function connectionOptions(url: string): Record<string, unknown> {
  const u = new URL(url);
  return {
    host: u.hostname,
    port: Number(u.port || 6379),
    ...(u.password ? { password: u.password } : {}),
    ...(u.username ? { username: u.username } : {}),
    ...(u.pathname && u.pathname.length > 1 ? { db: Number(u.pathname.slice(1)) } : {}),
    ...(u.protocol === 'rediss:' ? { tls: {} } : {}),
    maxRetriesPerRequest: null,
  };
}

export class BullMqQueue implements Queue {
  readonly kind = 'bullmq' as const;
  // Loose typing: bullmq v5 generics don't round-trip cleanly through field annotations.
  private queue!: InstanceType<typeof BullQueue>;
  private worker?: InstanceType<typeof Worker>;
  private pub!: Redis;
  private sub!: Redis;
  private emitter = new EventEmitter();

  constructor(private store: Store, private url: string) {
    this.emitter.setMaxListeners(0);
  }

  async init(): Promise<void> {
    const connection = connectionOptions(this.url);
    this.queue = new BullQueue(QUEUE_NAME, { connection });
    this.pub = new IORedis(this.url);
    this.sub = new IORedis(this.url);

    await this.sub.subscribe(CHANNEL);
    this.sub.on('message', (_channel, message) => {
      try {
        this.emitter.emit('progress', JSON.parse(message) as ProgressEvent);
      } catch {
        /* ignore malformed */
      }
    });

    if (process.env.AEGIS_ROLE !== 'api') {
      const concurrency = Math.max(1, Number(process.env.SCAN_CONCURRENCY ?? 4));
      this.worker = new Worker(
        QUEUE_NAME,
        async (job: Job) => {
          await processScanJob(job.data as ScanJob, this.store, (e) => {
            void this.pub.publish(CHANNEL, JSON.stringify(e));
          });
        },
        { connection, concurrency },
      );
    }
  }

  async close(): Promise<void> {
    await this.worker?.close();
    await this.queue.close();
    this.pub.disconnect();
    this.sub.disconnect();
    this.emitter.removeAllListeners();
  }

  async enqueue(job: ScanJob): Promise<void> {
    const queued: ProgressEvent = { scanId: job.scanId, type: 'queued', progress: 0, at: new Date().toISOString() };
    await this.pub.publish(CHANNEL, JSON.stringify(queued));
    await this.queue.add('scan', job, {
      jobId: job.scanId,
      attempts: 2,
      backoff: { type: 'exponential', delay: 2000 },
      removeOnComplete: 1000,
      removeOnFail: 1000,
    });
  }

  subscribe(scanId: string, listener: ProgressListener): () => void {
    const handler = (e: ProgressEvent) => {
      if (e.scanId === scanId) listener(e);
    };
    this.emitter.on('progress', handler);
    return () => this.emitter.off('progress', handler);
  }
}
