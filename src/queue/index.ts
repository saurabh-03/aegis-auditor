/** Queue factory: BullMqQueue when REDIS_URL is set, else InProcessQueue. */

import type { Store } from '../store/types.js';
import { InProcessQueue } from './memory.js';
import type { Queue } from './types.js';

let singleton: Queue | null = null;

export async function getQueue(store: Store): Promise<Queue> {
  if (singleton) return singleton;
  if (process.env.REDIS_URL) {
    const { BullMqQueue } = await import('./bullmq.js');
    singleton = new BullMqQueue(store, process.env.REDIS_URL);
  } else {
    singleton = new InProcessQueue(store);
  }
  await singleton.init();
  return singleton;
}

export type { Queue, ScanJob, ProgressEvent } from './types.js';
