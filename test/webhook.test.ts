import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHmac } from 'node:crypto';
import { MemoryStore } from '../src/store/memory.js';

async function seed(store: MemoryStore) {
  const u = await store.createUser({ email: 'w@e.com' });
  const org = await store.createOrganization('WhOrg', u.id);
  return org.id;
}

test('webhook: create hides secret, list excludes it, event lookup includes it', async () => {
  const store = new MemoryStore();
  const orgId = await seed(store);

  const created = await store.createWebhook({ orgId, url: 'https://x.test/hook', events: ['regression'], secret: 'whsec_abc' });
  assert.equal((created as Record<string, unknown>).secret, undefined); // public shape hides secret
  assert.deepEqual(created.events, ['regression']);

  const list = await store.listWebhooks(orgId);
  assert.equal(list.length, 1);
  assert.equal((list[0] as Record<string, unknown>).secret, undefined);

  // Event lookup returns the secret for signing.
  const forRegression = await store.webhooksForEvent(orgId, 'regression');
  assert.equal(forRegression.length, 1);
  assert.equal(forRegression[0]!.secret, 'whsec_abc');

  // Not subscribed to scan_complete.
  assert.equal((await store.webhooksForEvent(orgId, 'scan_complete')).length, 0);

  assert.equal(await store.deleteWebhook(created.id), true);
  assert.equal((await store.listWebhooks(orgId)).length, 0);
});

test('HMAC signature is verifiable with the secret', () => {
  const secret = 'whsec_test';
  const body = JSON.stringify({ event: 'regression', level: 'major' });
  const sig = 'sha256=' + createHmac('sha256', secret).update(body).digest('hex');
  // Receiver recomputes and compares.
  const check = 'sha256=' + createHmac('sha256', secret).update(body).digest('hex');
  assert.equal(sig, check);
  assert.notEqual(sig, 'sha256=' + createHmac('sha256', 'wrong').update(body).digest('hex'));
});
