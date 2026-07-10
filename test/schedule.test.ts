import { test } from 'node:test';
import assert from 'node:assert/strict';
import { MemoryStore } from '../src/store/memory.js';
import { Scheduler } from '../src/schedule/scheduler.js';
import { handleScanCompletion } from '../src/schedule/alerts.js';
import { finding } from '../src/core/finding.js';
import type { AuditReport, Finding } from '../src/core/types.js';
import type { Queue, ScanJob } from '../src/queue/types.js';

function fakeQueue(): Queue & { jobs: ScanJob[] } {
  const jobs: ScanJob[] = [];
  return {
    kind: 'inprocess',
    jobs,
    async init() {},
    async close() {},
    async enqueue(job) {
      jobs.push(job);
    },
    subscribe() {
      return () => {};
    },
  };
}

function report(score: number, findings: Finding[] = []): AuditReport {
  return {
    target: 'https://example.com/',
    scannedAt: new Date().toISOString(),
    durationMs: 1,
    authorized: false,
    overall: { score, grade: score >= 90 ? 'A' : 'F' },
    categories: [{ category: 'security', score, grade: 'x', findingCounts: { pass: 0, warn: 0, fail: 0, info: 0 } }],
    findings,
    modules: [],
    data: {},
    meta: { engineVersion: '0.1.0', passiveOnly: true },
  };
}

async function seedProject(store: MemoryStore) {
  const user = await store.createUser({ email: 'a@b.com' });
  const org = await store.createOrganization('Acme', user.id);
  const project = await store.createProject(org.id, 'Site', 'https://example.com/', 'tok');
  return { user, org, project };
}

test('schedule lifecycle: create → due detection → tick enqueues + advances', async () => {
  const store = new MemoryStore();
  const queue = fakeQueue();
  const { org, project } = await seedProject(store);

  const sched = await store.createSchedule({ projectId: project.id, orgId: org.id, cadence: 'daily' });
  // Fresh schedule is in the future → not due.
  assert.equal((await store.listDueSchedules(new Date().toISOString())).length, 0);

  // Force it due.
  await store.updateSchedule(sched.id, { nextRunAt: new Date(Date.now() - 1000).toISOString() });
  assert.equal((await store.listDueSchedules(new Date().toISOString())).length, 1);

  const dispatched = await new Scheduler(store, queue).tick();
  assert.equal(dispatched, 1);
  assert.equal(queue.jobs.length, 1);
  assert.equal(queue.jobs[0]!.projectId, project.id);

  // nextRunAt advanced back into the future; lastRunAt set.
  const after = await store.getSchedule(sched.id);
  assert.ok(after!.nextRunAt > new Date().toISOString());
  assert.ok(after!.lastRunAt);
  assert.equal((await store.listDueSchedules(new Date().toISOString())).length, 0);
});

test('handleScanCompletion raises a regression notification', async () => {
  const store = new MemoryStore();
  const { org, project } = await seedProject(store);

  // Previous (good) completed scan.
  await store.saveScan({
    projectId: project.id, orgId: org.id, userId: null, target: project.target,
    status: 'COMPLETED', authorized: false, overall: 92, grade: 'A', report: report(92),
  });

  // Current (worse) scan with a new high-severity finding.
  const curr = report(70, [
    finding({ id: 'csp.missing', module: 'm', category: 'security', title: 'No CSP', severity: 'high', status: 'fail', risk: 'r', whyItMatters: 'w', technical: 't', businessImpact: 'b', probability: 'high', remediation: 'fix', estimatedFixTime: '1d' }),
  ]);
  const rec = await store.saveScan({
    projectId: project.id, orgId: org.id, userId: null, target: project.target,
    status: 'COMPLETED', authorized: false, overall: 70, grade: 'F', report: curr,
  });

  await handleScanCompletion(store, { scanId: rec.id, projectId: project.id, orgId: org.id }, curr);

  const notifs = await store.listNotifications(org.id, { limit: 10 });
  assert.equal(notifs.length, 1);
  assert.equal(notifs[0]!.type, 'regression');
  assert.equal(notifs[0]!.severity, 'critical'); // major → critical
  assert.match(notifs[0]!.title, /Regression/);
});

test('handleScanCompletion stays silent for ad-hoc (no project) scans', async () => {
  const store = new MemoryStore();
  const { org } = await seedProject(store);
  await handleScanCompletion(store, { scanId: 'x', projectId: null, orgId: org.id }, report(10));
  assert.equal((await store.listNotifications(org.id, { limit: 10 })).length, 0);
});
