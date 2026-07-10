import { test } from 'node:test';
import assert from 'node:assert/strict';
import { renderHtmlReport, PERSONAS } from '../src/report/html.js';
import { finding, pass } from '../src/core/finding.js';
import type { AuditReport, Finding } from '../src/core/types.js';

function fakeReport(): AuditReport {
  const findings: Finding[] = [
    finding({ id: 'csp.missing', module: 'csp', category: 'security', title: 'No Content-Security-Policy', severity: 'high', status: 'fail', risk: 'XSS barrier missing', whyItMatters: 'w', technical: 't', businessImpact: 'Account takeover risk', probability: 'high', remediation: 'Deploy a strict CSP', estimatedFixTime: '1-3 days', owasp: ['A03:2021-Injection'], exampleCode: "Content-Security-Policy: default-src 'self'" }),
    finding({ id: 'perf.ttfb', module: 'performance', category: 'performance', title: 'Slow TTFB', severity: 'medium', status: 'fail', risk: 'slow', whyItMatters: 'w', technical: 't', businessImpact: 'conversion', probability: 'high', remediation: 'Add caching', estimatedFixTime: '1 day' }),
    pass('ssl', 'security', 'ssl.ok', 'TLS 1.3 in use', 'modern protocol'),
  ];
  return {
    target: 'https://example.com/',
    scannedAt: new Date('2026-07-10T12:00:00Z').toISOString(),
    durationMs: 900,
    authorized: false,
    overall: { score: 78, grade: 'C+' },
    categories: [
      { category: 'security', score: 60, grade: 'D', findingCounts: { pass: 1, warn: 0, fail: 1, info: 0 } },
      { category: 'performance', score: 82, grade: 'B-', findingCounts: { pass: 0, warn: 0, fail: 1, info: 0 } },
    ],
    findings,
    modules: [],
    data: {},
    meta: { engineVersion: '0.1.0', passiveOnly: true },
  };
}

test('renders all personas as valid, self-contained HTML documents', () => {
  for (const persona of PERSONAS) {
    const html = renderHtmlReport(fakeReport(), persona);
    assert.ok(html.startsWith('<!DOCTYPE html>'));
    assert.ok(html.includes('</html>'));
    assert.ok(html.includes('example.com'));
    assert.ok(html.includes('78')); // overall score
  }
});

test('executive persona shows top priorities and business impact', () => {
  const html = renderHtmlReport(fakeReport(), 'executive');
  assert.ok(html.includes('Executive Summary'));
  assert.ok(html.includes('Top priorities'));
  assert.ok(html.includes('Account takeover risk'));
});

test('security persona lists findings + OWASP and example code', () => {
  const html = renderHtmlReport(fakeReport(), 'security');
  assert.ok(html.includes('Security findings'));
  assert.ok(html.includes('A03:2021-Injection'));
  assert.ok(html.includes('Content-Security-Policy: default-src')); // exampleCode present
});

test('compliance persona shows pass/fail control table', () => {
  const html = renderHtmlReport(fakeReport(), 'compliance');
  assert.ok(html.includes('Control summary'));
  assert.ok(html.includes('PASS') || html.includes('FAIL'));
});

test('escapes HTML to prevent injection from finding text', () => {
  const rep = fakeReport();
  rep.findings[0]!.title = '<script>alert(1)</script>';
  const html = renderHtmlReport(rep, 'security');
  assert.ok(!html.includes('<script>alert(1)</script>'));
  assert.ok(html.includes('&lt;script&gt;'));
});
