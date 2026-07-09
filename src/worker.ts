/**
 * Standalone scan worker entrypoint (Phase 2, scaled deployments).
 *
 * Run one or more of these alongside the API to process the BullMQ `scans`
 * queue. Requires REDIS_URL (and DATABASE_URL to share persistence with the API).
 *
 *   AEGIS_ROLE=worker REDIS_URL=redis://… DATABASE_URL=… node dist/worker.js
 *
 * With no REDIS_URL this exits — the in-process queue runs inside the API instead.
 */

import { getStore } from './store/index.js';
import { getQueue } from './queue/index.js';

async function main(): Promise<void> {
  if (!process.env.REDIS_URL) {
    console.error('worker: REDIS_URL is not set. In single-node mode the API runs scans in-process; no separate worker is needed.');
    process.exit(1);
  }
  process.env.AEGIS_ROLE = 'worker';
  const store = await getStore();
  const queue = await getQueue(store);
  console.log(`Aegis worker started — store=${store.kind} queue=${queue.kind}. Waiting for jobs…`);

  const shutdown = async () => {
    console.log('worker: shutting down…');
    await queue.close();
    await store.close();
    process.exit(0);
  };
  process.on('SIGINT', shutdown);
  process.on('SIGTERM', shutdown);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
