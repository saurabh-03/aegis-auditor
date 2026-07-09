import { test } from 'node:test';
import assert from 'node:assert/strict';
import { inVulnerableRange, lt } from '../src/intel/semver.js';
import { matchCves } from '../src/intel/cve-match.js';
import { LocalAdvisor } from '../src/ai/local.js';
import { generateTickets } from '../src/ai/tickets.js';
import type { AuditReport } from '../src/core/types.js';
import { finding } from '../src/core/finding.js';

test('semver comparison and vulnerable range', () => {
  assert.equal(lt('3.4.1', '3.5.0'), true);
  assert.equal(lt('3.5.0', '3.5.0'), false);
  assert.equal(inVulnerableRange('3.4.0', '3.5.0', '1.2.0'), true);
  assert.equal(inVulnerableRange('3.5.1', '3.5.0', '1.2.0'), false);
  assert.equal(inVulnerableRange('1.1.0', '3.5.0', '1.2.0'), false); // below introduced
});

test('matchCves flags outdated jQuery, clears patched jQuery', () => {
  const vuln = matchCves([{ name: 'jQuery', category: 'JS library', version: '3.3.1' }]);
  assert.ok(vuln.length >= 1);
  assert.ok(vuln.some((m) => m.entry.cve === 'CVE-2020-11022'));

  const safe = matchCves([{ name: 'jQuery', category: 'JS library', version: '3.7.1' }]);
  assert.equal(safe.length, 0);
});

function fakeReport(): AuditReport {
  return {
    target: 'https://example.com/',
    scannedAt: new Date().toISOString(),
    durationMs: 100,
    authorized: false,
    overall: { score: 62, grade: 'D' },
    categories: [],
    findings: [
      finding({ id: 'a', module: 'm', category: 'security', title: 'No CSP', severity: 'high', status: 'fail', risk: 'r', whyItMatters: 'w', technical: 't', businessImpact: 'b', probability: 'high', remediation: 'Deploy a strict CSP', estimatedFixTime: '1 day', owasp: ['A03:2021-Injection'] }),
      finding({ id: 'b', module: 'm', category: 'security', title: 'Missing HSTS', severity: 'medium', status: 'fail', risk: 'r', whyItMatters: 'w', technical: 't', businessImpact: 'b', probability: 'medium', remediation: 'Add HSTS', estimatedFixTime: '15 min' }),
    ],
    modules: [{ module: 'm', category: 'security', ok: true, durationMs: 5 }],
    data: {},
    meta: { engineVersion: '0.1.0', passiveOnly: true },
  };
}

test('local advisor produces summary, actions, checklist, groups', async () => {
  const out = await new LocalAdvisor().advise(fakeReport());
  assert.equal(out.provider, 'local');
  assert.match(out.executiveSummary, /62\/100/);
  assert.ok(out.prioritizedActions.length >= 2);
  assert.equal(out.remediationChecklist.length, 2);
  // Highest-priority action first (the high-severity CSP finding).
  assert.match(out.prioritizedActions[0]!, /CSP/i);
  assert.ok(out.groups.length >= 1);
});

test('ticket generation formats findings for trackers', () => {
  const tickets = generateTickets(fakeReport(), 'github');
  assert.equal(tickets.length, 2);
  assert.match(tickets[0]!.title, /\[HIGH\]/);
  assert.ok(tickets[0]!.labels.includes('severity:high'));
  assert.match(tickets[0]!.body, /Remediation/);
});
