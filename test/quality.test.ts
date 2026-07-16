import { test } from 'node:test';
import assert from 'node:assert/strict';
import { refineFindings, signatureOf } from '../src/core/quality.js';
import type { Finding } from '../src/core/types.js';

function f(partial: Partial<Finding> & Pick<Finding, 'module' | 'title'>): Finding {
  return {
    id: partial.id ?? `${partial.module}.${Math.random()}`,
    module: partial.module,
    category: partial.category ?? 'security',
    title: partial.title,
    severity: partial.severity ?? 'medium',
    status: partial.status ?? 'fail',
    risk: 'r',
    whyItMatters: 'w',
    technical: 't',
    businessImpact: 'b',
    probability: 'medium',
    remediation: 'fix',
    estimatedFixTime: '1h',
    references: [],
    ...partial,
  };
}

test('per-endpoint ZAP header findings collapse to one site-wide finding', () => {
  const findings = [
    f({ module: 'zap', title: 'Content Security Policy (CSP) Header Not Set', location: { url: 'http://x.com/' } }),
    f({ module: 'zap', title: 'Content Security Policy (CSP) Header Not Set', location: { url: 'http://x.com/a' } }),
    f({ module: 'zap', title: 'Content Security Policy (CSP) Header Not Set', location: { url: 'http://x.com/b' } }),
  ];
  const { findings: out, merged } = refineFindings(findings);
  assert.equal(out.length, 1);
  assert.equal(merged, 2);
  assert.deepEqual(out[0]?.evidence?.affectedUrls, ['http://x.com/', 'http://x.com/a', 'http://x.com/b']);
  assert.equal(out[0]?.evidence?.occurrences, 3);
});

test('cross-engine agreement corroborates and raises confidence to confirmed', () => {
  const findings = [
    f({ module: 'headers', title: 'No Content-Security-Policy header', confidence: 'firm' }),
    f({ module: 'zap', title: 'Content Security Policy (CSP) Header Not Set', location: { url: 'http://x.com/' } }),
    f({ module: 'nuclei', title: 'CSP missing', location: { url: 'http://x.com/' } }),
  ];
  const { findings: out } = refineFindings(findings);
  assert.equal(out.length, 1);
  assert.deepEqual(out[0]?.corroboratedBy, ['headers', 'nuclei', 'zap']);
  assert.equal(out[0]?.confidence, 'confirmed');
});

test('distinct header issues are NOT merged (nosniff vs CSP share CWE-693)', () => {
  const findings = [
    f({ module: 'zap', title: 'Content Security Policy (CSP) Header Not Set', cwe: ['CWE-693'] }),
    f({ module: 'zap', title: 'X-Content-Type-Options Header Missing', cwe: ['CWE-693'] }),
  ];
  const { findings: out } = refineFindings(findings);
  assert.equal(out.length, 2);
});

test('injection findings stay separate per endpoint/param', () => {
  const findings = [
    f({ module: 'zap', title: 'SQL Injection', severity: 'high', location: { url: 'http://x.com/a', param: 'q' } }),
    f({ module: 'zap', title: 'SQL Injection', severity: 'high', location: { url: 'http://x.com/b', param: 'id' } }),
  ];
  const { findings: out, merged } = refineFindings(findings);
  assert.equal(out.length, 2);
  assert.equal(merged, 0);
});

test('same injection on the same endpoint+param from two engines merges', () => {
  const findings = [
    f({ module: 'zap', title: 'SQL Injection', severity: 'high', location: { url: 'http://x.com/a', param: 'q' } }),
    f({ module: 'nuclei', title: 'SQLi detected', severity: 'high', location: { url: 'http://x.com/a', param: 'q' } }),
  ];
  const { findings: out } = refineFindings(findings);
  assert.equal(out.length, 1);
  assert.deepEqual(out[0]?.corroboratedBy, ['nuclei', 'zap']);
});

test('representative keeps the highest severity in the group', () => {
  const findings = [
    f({ module: 'a', title: 'SQL Injection', severity: 'medium', location: { url: 'http://x.com/a', param: 'q' } }),
    f({ module: 'b', title: 'SQL Injection', severity: 'critical', location: { url: 'http://x.com/a', param: 'q' } }),
  ];
  const { findings: out } = refineFindings(findings);
  assert.equal(out[0]?.severity, 'critical');
});

test('pass and info findings pass through untouched', () => {
  const findings = [
    f({ module: 'ssl', title: 'TLS ok', status: 'pass', severity: 'info' }),
    f({ module: 'ssl', title: 'TLS ok', status: 'pass', severity: 'info' }),
    f({ module: 'nuclei', title: 'Tech detect', status: 'warn', severity: 'info' }),
  ];
  const { findings: out, merged } = refineFindings(findings);
  // Two passes preserved; the info-severity warn is not a fail/warn dedup target
  // for merge unless duplicated — here it is unique.
  assert.equal(out.filter((x) => x.status === 'pass').length, 2);
  assert.equal(merged, 0);
});

test('single findings are unchanged and get no corroboration metadata', () => {
  const { findings: out } = refineFindings([f({ module: 'zap', title: 'SQL Injection', location: { url: 'http://x.com/a', param: 'q' } })]);
  assert.equal(out.length, 1);
  assert.equal(out[0]?.corroboratedBy, undefined);
});

test('signatureOf includes category so cross-category issues never merge', () => {
  const a = f({ module: 'm', title: 'Server Leaks Version Information', category: 'security' });
  const b = f({ module: 'm', title: 'Server Leaks Version Information', category: 'infrastructure' });
  assert.notEqual(signatureOf(a), signatureOf(b));
});
