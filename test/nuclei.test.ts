import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parseNucleiJsonl, runNuclei } from '../src/integrations/nuclei.js';
import { mapNucleiResults } from '../src/modules/active/nuclei.js';

// A representative slice of `nuclei -jsonl` output (one object per line), plus a
// blank line and a malformed line the parser must tolerate.
const SAMPLE = [
  JSON.stringify({
    'template-id': 'CVE-2021-44228',
    info: {
      name: 'Apache Log4j RCE',
      severity: 'critical',
      description: 'Log4Shell remote code execution.',
      reference: ['https://nvd.nist.gov/vuln/detail/CVE-2021-44228'],
      remediation: 'Upgrade Log4j to 2.17+.',
      tags: ['cve', 'rce'],
      classification: { 'cve-id': ['CVE-2021-44228'], 'cwe-id': ['CWE-502'], 'cvss-score': 10.0 },
    },
    'matched-at': 'https://example.com/api',
    type: 'http',
    request: 'GET /api HTTP/1.1',
    response: 'HTTP/1.1 200 OK',
  }),
  '',
  '{ this is not valid json',
  JSON.stringify({
    'template-id': 'tech-detect',
    info: { name: 'Nginx detected', severity: 'info', tags: ['tech'] },
    'matched-at': 'https://example.com/',
    type: 'http',
  }),
  // Duplicate of the first (same template + location) — must dedup to one finding.
  JSON.stringify({
    'template-id': 'CVE-2021-44228',
    info: { name: 'Apache Log4j RCE', severity: 'critical', classification: { 'cve-id': ['CVE-2021-44228'] } },
    'matched-at': 'https://example.com/api',
    type: 'http',
  }),
].join('\n');

test('parseNucleiJsonl parses valid lines and skips blank/malformed ones', () => {
  const results = parseNucleiJsonl(SAMPLE);
  assert.equal(results.length, 3); // two CVE lines + one tech-detect (malformed skipped)
  const log4j = results.find((r) => r.templateId === 'CVE-2021-44228');
  assert.ok(log4j);
  assert.equal(log4j?.severity, 'critical');
  assert.equal(log4j?.cvss, 10);
  assert.deepEqual(log4j?.cve, ['CVE-2021-44228']);
  assert.deepEqual(log4j?.cwe, ['CWE-502']);
  assert.equal(log4j?.matchedAt, 'https://example.com/api');
});

test('mapNucleiResults maps severity, dedups by template+location, and sets active fields', () => {
  const findings = mapNucleiResults(parseNucleiJsonl(SAMPLE));
  // 3 parsed results but the two identical Log4j matches dedup → 2 findings.
  assert.equal(findings.length, 2);

  const log4j = findings.find((f) => f.title.includes('Log4j'));
  assert.ok(log4j);
  assert.equal(log4j?.severity, 'critical');
  assert.equal(log4j?.status, 'fail');
  assert.equal(log4j?.confidence, 'firm');
  assert.equal(log4j?.location?.url, 'https://example.com/api');
  assert.deepEqual(log4j?.cwe, ['CWE-502']);
  assert.ok(log4j?.requestResponse?.request.includes('GET /api'));
  // id embeds a location hash so the diff engine tracks per-endpoint.
  assert.match(log4j?.id ?? '', /^nuclei\.CVE-2021-44228\.[0-9a-f]{10}$/);

  // Info-severity template → warn status + tentative confidence, doesn't read as a failure.
  const tech = findings.find((f) => f.title.includes('Nginx'));
  assert.equal(tech?.severity, 'info');
  assert.equal(tech?.status, 'warn');
  assert.equal(tech?.confidence, 'tentative');

  // Every non-pass finding stays self-explaining (engine invariant).
  for (const f of findings) {
    assert.ok(f.risk && f.whyItMatters && f.technical && f.businessImpact && f.remediation);
  }
});

test('mapNucleiResults returns empty for no results', () => {
  assert.deepEqual(mapNucleiResults([]), []);
});

test('runNuclei degrades to null when the binary is absent', async () => {
  const out = await runNuclei(['https://example.com/'], {
    binaryPath: 'definitely-not-a-real-binary-aegis-xyz',
    timeoutMs: 5000,
  });
  assert.equal(out, null);
});

test('runNuclei returns [] for an empty target list without spawning', async () => {
  const out = await runNuclei([], { binaryPath: 'definitely-not-a-real-binary-aegis-xyz' });
  assert.deepEqual(out, []);
});
