import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parseManifest } from '../src/intel/manifest.js';
import { matchPackages } from '../src/intel/cve-match.js';

const PACKAGE_LOCK = JSON.stringify({
  name: 'demo',
  lockfileVersion: 3,
  packages: {
    '': { name: 'demo', version: '1.0.0' },
    'node_modules/lodash': { version: '4.17.4' },
    'node_modules/jquery': { version: '3.3.1' },
    'node_modules/safe-pkg': { version: '9.9.9' },
  },
});

const YARN_LOCK = `# yarn lockfile v1

lodash@^4.17.4:
  version "4.17.4"
  resolved "https://registry.yarnpkg.com/lodash/-/lodash-4.17.4.tgz"

jquery@^3.3.1:
  version "3.3.1"
`;

const COMPOSER_LOCK = JSON.stringify({
  packages: [{ name: 'monolog/monolog', version: 'v2.0.0' }],
  'packages-dev': [{ name: 'phpunit/phpunit', version: '9.5.0' }],
});

test('parses npm package-lock.json v3', () => {
  const m = parseManifest(PACKAGE_LOCK, 'package-lock.json');
  assert.equal(m.format, 'package-lock.json');
  assert.equal(m.ecosystem, 'npm');
  const names = m.packages.map((p) => `${p.name}@${p.version}`);
  assert.ok(names.includes('lodash@4.17.4'));
  assert.ok(names.includes('jquery@3.3.1'));
  // Root project ("") must be excluded.
  assert.ok(!names.includes('demo@1.0.0'));
});

test('parses yarn.lock (classic)', () => {
  const m = parseManifest(YARN_LOCK, 'yarn.lock');
  assert.equal(m.format, 'yarn.lock');
  const names = m.packages.map((p) => `${p.name}@${p.version}`);
  assert.ok(names.includes('lodash@4.17.4'));
  assert.ok(names.includes('jquery@3.3.1'));
});

test('parses composer.lock (Packagist, strips v prefix)', () => {
  const m = parseManifest(COMPOSER_LOCK, 'composer.lock');
  assert.equal(m.format, 'composer.lock');
  assert.equal(m.ecosystem, 'Packagist');
  assert.ok(m.packages.some((p) => p.name === 'monolog/monolog' && p.version === '2.0.0'));
});

test('rejects unrecognized manifests', () => {
  assert.throws(() => parseManifest('just some text', 'notes.txt'));
});

test('matchPackages (local source) flags vulnerable lodash + jquery', async () => {
  const m = parseManifest(PACKAGE_LOCK, 'package-lock.json');
  const { matches, scanned } = await matchPackages(m.packages, { source: 'local' });
  assert.equal(scanned, 3);
  assert.ok(matches.some((x) => x.component === 'lodash' && x.entry.cve === 'CVE-2019-10744'));
  assert.ok(matches.some((x) => x.component === 'jquery' && x.entry.cve.startsWith('CVE-')));
  // safe-pkg (unknown) and root produce nothing.
  assert.ok(!matches.some((x) => x.component === 'safe-pkg'));
  // Sorted worst-first.
  for (let i = 1; i < matches.length; i++) {
    assert.ok(matches[i - 1]!.entry.cvss >= matches[i]!.entry.cvss);
  }
});
