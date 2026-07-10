/**
 * API key generation & hashing.
 *
 * Keys look like `aegis_sk_<random>`. Only a SHA-256 hash is stored; the
 * plaintext is shown to the user exactly once at creation. A short, non-secret
 * prefix is stored for display in the UI (so users can recognize a key without
 * exposing it).
 */

import { createHash, randomBytes } from 'node:crypto';

const PREFIX = 'aegis_sk_';

export interface GeneratedKey {
  plaintext: string;
  hashedKey: string;
  keyPrefix: string;
}

export function generateApiKey(): GeneratedKey {
  const secret = randomBytes(24).toString('base64url'); // 32 url-safe chars
  const plaintext = `${PREFIX}${secret}`;
  return {
    plaintext,
    hashedKey: hashApiKey(plaintext),
    keyPrefix: plaintext.slice(0, PREFIX.length + 8), // e.g. aegis_sk_AbC12345
  };
}

export function hashApiKey(plaintext: string): string {
  return createHash('sha256').update(plaintext).digest('hex');
}

/** Quick shape check before hashing/looking up an incoming key. */
export function looksLikeApiKey(value: string): boolean {
  return value.startsWith(PREFIX) && value.length > PREFIX.length + 16;
}
