import { test } from 'node:test';
import assert from 'node:assert/strict';
import { generateApiKey, hashApiKey, looksLikeApiKey } from '../src/auth/apikey.js';
import { MemoryStore } from '../src/store/memory.js';

test('generateApiKey returns a prefixed secret, matching hash, and display prefix', () => {
  const k = generateApiKey();
  assert.ok(k.plaintext.startsWith('aegis_sk_'));
  assert.equal(k.hashedKey, hashApiKey(k.plaintext));
  assert.ok(k.plaintext.startsWith(k.keyPrefix));
  assert.equal(k.keyPrefix.length, 'aegis_sk_'.length + 8);
  assert.ok(looksLikeApiKey(k.plaintext));
  assert.ok(!looksLikeApiKey('nope'));
  // Two keys differ.
  assert.notEqual(k.plaintext, generateApiKey().plaintext);
});

test('store: create → resolve by hash → revoke; secret never exposed', async () => {
  const store = new MemoryStore();
  const user = await store.createUser({ email: 'k@e.com' });
  const org = await store.createOrganization('KeyOrg', user.id);

  const gen = generateApiKey();
  const created = await store.createApiKey({ orgId: org.id, userId: user.id, name: 'CI', hashedKey: gen.hashedKey, keyPrefix: gen.keyPrefix });
  assert.equal(created.name, 'CI');
  assert.equal((created as Record<string, unknown>).hashedKey, undefined); // secret hash not in public shape

  // List does not leak the hash.
  const list = await store.listApiKeys(org.id);
  assert.equal(list.length, 1);
  assert.equal((list[0] as Record<string, unknown>).hashedKey, undefined);

  // Resolve by hash.
  const resolved = await store.getApiKeyByHash(gen.hashedKey);
  assert.equal(resolved?.id, created.id);
  assert.equal(resolved?.revokedAt, null);

  // Wrong hash → null.
  assert.equal(await store.getApiKeyByHash(hashApiKey('aegis_sk_wrongwrongwrong')), null);

  // Revoke marks revokedAt.
  assert.equal(await store.revokeApiKey(created.id), true);
  const after = await store.getApiKeyByHash(gen.hashedKey);
  assert.ok(after?.revokedAt);
});
