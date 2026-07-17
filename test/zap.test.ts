import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parseZapAlerts, runZapScan } from '../src/integrations/zap.js';
import { mapZapAlerts } from '../src/modules/active/zap.js';

// A representative slice of ZAP's /JSON/core/view/alerts response.
const RAW = {
  alerts: [
    {
      pluginId: '40018',
      alert: 'SQL Injection',
      risk: 'High',
      confidence: 'Medium',
      url: 'https://example.com/search?q=1',
      param: 'q',
      method: 'GET',
      attack: "q=1' OR '1'='1",
      evidence: 'SQL error in response',
      description: 'SQL injection may be possible.',
      solution: 'Use parameterized queries.',
      reference: 'https://owasp.org/sqli https://cwe.mitre.org/89',
      cweid: '89',
      wascid: '19',
    },
    {
      pluginId: '10021',
      alert: 'X-Content-Type-Options Missing',
      risk: 'Low',
      confidence: 'High',
      url: 'https://example.com/',
      method: 'GET',
      description: 'Header not set.',
      solution: 'Set nosniff.',
      reference: '',
      cweid: '693',
    },
    // Duplicate of the SQLi (same plugin+url+param) → must dedup to one.
    {
      pluginId: '40018',
      alert: 'SQL Injection',
      risk: 'High',
      confidence: 'Medium',
      url: 'https://example.com/search?q=1',
      param: 'q',
      method: 'GET',
    },
    // False positive → must be dropped.
    {
      pluginId: '99999',
      alert: 'Noise',
      risk: 'Medium',
      confidence: 'False Positive',
      url: 'https://example.com/x',
    },
  ],
};

test('parseZapAlerts normalizes fields and tolerates missing ones', () => {
  const alerts = parseZapAlerts(RAW);
  assert.equal(alerts.length, 4); // parsing keeps all; dedup/FP-filter happens in mapping
  const sqli = alerts.find((a) => a.pluginId === '40018');
  assert.equal(sqli?.risk, 'High');
  assert.equal(sqli?.cweid, 89);
  assert.equal(sqli?.param, 'q');
});

test('mapZapAlerts maps severity/confidence, dedups, drops false positives, sets active fields', () => {
  const findings = mapZapAlerts(parseZapAlerts(RAW));
  // 4 raw → dedup the SQLi pair and drop the FP → 2 findings.
  assert.equal(findings.length, 2);

  const sqli = findings.find((f) => f.title === 'SQL Injection');
  assert.ok(sqli);
  assert.equal(sqli?.severity, 'high');
  assert.equal(sqli?.status, 'fail');
  assert.equal(sqli?.confidence, 'firm'); // ZAP Medium → firm
  assert.equal(sqli?.location?.url, 'https://example.com/search?q=1');
  assert.equal(sqli?.location?.param, 'q');
  assert.deepEqual(sqli?.cwe, ['CWE-89']);
  assert.match(sqli?.id ?? '', /^zap\.40018\.[0-9a-f]{10}$/);
  // Only http(s) references survive the reference split.
  assert.ok(sqli?.references.every((r) => r.startsWith('http')));

  const low = findings.find((f) => f.title.includes('X-Content-Type'));
  assert.equal(low?.severity, 'low');
  assert.equal(low?.confidence, 'confirmed'); // ZAP High → confirmed

  // No false-positive alert leaked through.
  assert.ok(!findings.some((f) => f.title === 'Noise'));

  // Self-explaining invariant holds for every finding.
  for (const f of findings) {
    assert.ok(f.risk && f.whyItMatters && f.technical && f.businessImpact && f.remediation);
  }
});

test('mapZapAlerts returns empty for no alerts', () => {
  assert.deepEqual(mapZapAlerts([]), []);
});

test('runZapScan degrades to null when the daemon is unreachable', async () => {
  const out = await runZapScan(['https://example.com/'], {
    apiUrl: 'http://127.0.0.1:1', // connection refused
    target: 'https://example.com',
    timeoutMs: 3000,
  });
  assert.equal(out, null);
});
