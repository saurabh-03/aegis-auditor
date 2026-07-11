import { test } from 'node:test';
import assert from 'node:assert/strict';
import { isBlockedIp, assertPublicHost, BlockedTargetError } from '../src/core/ssrf.js';

test('isBlockedIp blocks private, loopback, link-local, metadata, and reserved ranges', () => {
  for (const ip of ['127.0.0.1', '10.0.0.5', '172.16.9.9', '172.31.255.255', '192.168.1.1', '169.254.169.254', '0.0.0.0', '100.64.0.1', '224.0.0.1', '::1', 'fe80::1', 'fd00::1', '::ffff:127.0.0.1']) {
    assert.equal(isBlockedIp(ip), true, `${ip} should be blocked`);
  }
});

test('isBlockedIp allows public addresses', () => {
  for (const ip of ['8.8.8.8', '1.1.1.1', '93.184.216.34', '172.15.0.1', '172.32.0.1', '2606:4700:4700::1111']) {
    assert.equal(isBlockedIp(ip), false, `${ip} should be allowed`);
  }
});

test('assertPublicHost rejects internal hostnames and IP literals', async () => {
  for (const host of ['localhost', 'foo.local', 'svc.internal', '127.0.0.1', '169.254.169.254', '10.1.2.3']) {
    await assert.rejects(() => assertPublicHost(host), BlockedTargetError, `${host} should be rejected`);
  }
});

test('assertPublicHost allows a public IP literal without DNS', async () => {
  await assert.doesNotReject(() => assertPublicHost('8.8.8.8'));
});
