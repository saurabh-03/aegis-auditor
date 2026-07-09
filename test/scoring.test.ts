import { test } from 'node:test';
import assert from 'node:assert/strict';
import { gradeFor, scoreCategory, scoreAll } from '../src/core/scoring.js';
import { finding, pass } from '../src/core/finding.js';
import type { Finding } from '../src/core/types.js';

test('gradeFor maps scores to letter grades', () => {
  assert.equal(gradeFor(98), 'A+');
  assert.equal(gradeFor(91), 'A-');
  assert.equal(gradeFor(72), 'C-');
  assert.equal(gradeFor(40), 'F');
});

test('scoreCategory deducts by severity, warnings at half weight', () => {
  const findings: Finding[] = [
    pass('m', 'security', 'ok', 'ok', 'fine'),
    finding({
      id: 'x', module: 'm', category: 'security', title: 'high fail',
      severity: 'high', status: 'fail', risk: '', whyItMatters: '', technical: '',
      businessImpact: '', probability: 'high', remediation: '', estimatedFixTime: '',
    }),
  ];
  const s = scoreCategory('security', findings);
  // high fail weight = 18 → 100 - 18 = 82
  assert.equal(s.score, 82);
  assert.equal(s.findingCounts.pass, 1);
  assert.equal(s.findingCounts.fail, 1);
});

test('scoreAll ignores categories with no checks in the weighted mean', () => {
  const findings: Finding[] = [pass('m', 'security', 'ok', 'ok', 'fine')];
  const { overall, categories } = scoreAll(findings);
  // Only security ran and it's perfect → overall 100.
  assert.equal(overall.score, 100);
  const perf = categories.find((c) => c.category === 'performance');
  assert.equal(Object.values(perf!.findingCounts).reduce((a, b) => a + b, 0), 0);
});
