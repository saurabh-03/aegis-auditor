import { test } from 'node:test';
import assert from 'node:assert/strict';
import { diffReports, assessRegression } from '../src/core/diff.js';
import { finding, pass } from '../src/core/finding.js';
import type { AuditReport, Finding } from '../src/core/types.js';

function report(score: number, findings: Finding[]): AuditReport {
  return {
    target: 'https://example.com/',
    scannedAt: new Date().toISOString(),
    durationMs: 100,
    authorized: false,
    overall: { score, grade: score >= 90 ? 'A' : score >= 70 ? 'C' : 'F' },
    categories: [
      { category: 'security', score, grade: 'x', findingCounts: { pass: 0, warn: 0, fail: 0, info: 0 } },
    ],
    findings,
    modules: [],
    data: {},
    meta: { engineVersion: '0.1.0', passiveOnly: true },
  };
}

const fail = (id: string, sev: Finding['severity']): Finding =>
  finding({ id, module: 'm', category: 'security', title: id, severity: sev, status: 'fail', risk: 'r', whyItMatters: 'w', technical: 't', businessImpact: 'b', probability: 'high', remediation: 'fix', estimatedFixTime: '1h' });

test('diffReports returns null without a baseline', () => {
  assert.equal(diffReports(null, report(90, [])), null);
});

test('diffReports detects new and resolved findings + score delta', () => {
  const prev = report(90, [fail('headers.hsts.missing', 'high'), pass('m', 'security', 'ok', 'ok', 'ok')]);
  const curr = report(72, [fail('csp.missing', 'high'), pass('m', 'security', 'ok', 'ok', 'ok')]);
  const d = diffReports(prev, curr)!;
  assert.equal(d.scoreDelta, -18);
  assert.ok(d.newFindings.some((f) => f.id === 'csp.missing'));
  assert.ok(d.resolvedFindings.some((f) => f.id === 'headers.hsts.missing'));
});

test('assessRegression flags major on new high-severity finding', () => {
  const prev = report(90, []);
  const curr = report(88, [fail('csp.missing', 'high')]);
  const a = assessRegression(diffReports(prev, curr));
  assert.equal(a.isRegression, true);
  assert.equal(a.level, 'major');
});

test('assessRegression flags minor on moderate score drop only', () => {
  const prev = report(90, [fail('x', 'low')]);
  const curr = report(83, [fail('x', 'low')]); // same findings, -7 points
  const a = assessRegression(diffReports(prev, curr));
  assert.equal(a.level, 'minor');
});

test('assessRegression clears when improving', () => {
  const prev = report(70, [fail('x', 'high')]);
  const curr = report(95, []);
  const a = assessRegression(diffReports(prev, curr));
  assert.equal(a.isRegression, false);
});
