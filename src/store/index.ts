/** Store factory: PrismaStore when DATABASE_URL is set, else MemoryStore. */

import type { Store } from './types.js';
import { MemoryStore } from './memory.js';

let singleton: Store | null = null;

export async function getStore(): Promise<Store> {
  if (singleton) return singleton;
  if (process.env.DATABASE_URL) {
    // Lazy import so the app runs without @prisma/client generated in dev.
    const { PrismaStore } = await import('./prisma.js');
    singleton = new PrismaStore();
  } else {
    singleton = new MemoryStore();
  }
  await singleton.init();
  return singleton;
}

export function resetStoreForTests(store: Store): void {
  singleton = store;
}

export type { Store } from './types.js';
