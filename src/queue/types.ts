/**
 * Async scan queue abstraction. `InProcessQueue` (default) runs jobs in the same
 * process; `BullMqQueue` (when REDIS_URL is set) distributes them to workers.
 * The API depends only on this interface — see docs/ARCHITECTURE.md §4.
 */

import type { ScanOptions } from '../core/types.js';

export interface ScanJob {
  scanId: string;
  target: string;
  options: ScanOptions;
  projectId: string | null;
  orgId: string | null;
  userId: string | null;
}

export type ProgressType = 'queued' | 'running' | 'module' | 'completed' | 'failed';

export interface ProgressEvent {
  scanId: string;
  type: ProgressType;
  /** 0..1 fraction of modules finished (for progress bars). */
  progress?: number;
  /** Module name for `type: "module"` events. */
  module?: string;
  moduleOk?: boolean;
  /** Present on `completed`. */
  overall?: number;
  grade?: string;
  /** Present on `failed`. */
  error?: string;
  at: string;
}

export type ProgressListener = (event: ProgressEvent) => void;

export interface Queue {
  readonly kind: 'inprocess' | 'bullmq';
  init(): Promise<void>;
  close(): Promise<void>;
  /** Enqueue a scan job for asynchronous processing. */
  enqueue(job: ScanJob): Promise<void>;
  /** Subscribe to progress for a scan; returns an unsubscribe function. */
  subscribe(scanId: string, listener: ProgressListener): () => void;
}
