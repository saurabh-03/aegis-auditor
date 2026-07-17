import { test } from 'node:test';
import assert from 'node:assert/strict';
import { runScan } from '../src/core/scanner.js';
import type { ScanContext, ScanModule } from '../src/core/types.js';

/** A module that reports progress (including an out-of-range value to clamp). */
function reporter(name: string): ScanModule {
  return {
    name,
    title: name,
    category: 'security',
    mode: 'passive',
    description: 'test',
    async run(ctx: ScanContext) {
      ctx.progress(0.25, 'quarter');
      ctx.progress(2, 'over'); // must clamp to 1
      ctx.progress(-1); // must clamp to 0
      return { module: name, category: 'security', ok: true, findings: [], durationMs: 0 };
    },
  };
}

test('ctx.progress is bound per-module and fractions are clamped to 0..1', async () => {
  const events: Array<{ name: string; fraction: number; note?: string }> = [];
  // Public IP literal → assertPublicHost passes without DNS; the module never
  // calls getPage/getSurface, so no network happens.
  await runScan(new URL('http://8.8.8.8/'), [reporter('alpha')], { authorized: false, timeoutMs: 1000 }, {
    onModuleProgress: (m, fraction, note) => events.push({ name: m.name, fraction, note }),
  });

  assert.equal(events.length, 3);
  assert.deepEqual(events[0], { name: 'alpha', fraction: 0.25, note: 'quarter' });
  assert.equal(events[1]?.fraction, 1); // clamped from 2
  assert.equal(events[2]?.fraction, 0); // clamped from -1
  // Every event is attributed to the reporting module.
  assert.ok(events.every((e) => e.name === 'alpha'));
});

test('progress events are attributed to the correct module when several run', async () => {
  const names = new Set<string>();
  await runScan(new URL('http://8.8.8.8/'), [reporter('alpha'), reporter('beta')], { authorized: false, timeoutMs: 1000 }, {
    onModuleProgress: (m) => names.add(m.name),
  });
  assert.deepEqual([...names].sort(), ['alpha', 'beta']);
});
