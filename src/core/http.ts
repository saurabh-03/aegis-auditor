/** Network helpers shared by modules: timed fetch and redirect tracing. */

import { config } from './config.js';
import type { PageSnapshot, RedirectHop, ScanAuth } from './types.js';

/**
 * Flatten {@link ScanAuth} into a plain header map (headers + a Cookie header).
 * Header names are lowercased so callers merge without duplicating. Returns an
 * empty object when there is no auth. These values are secrets — never log them.
 */
export function buildAuthHeaders(auth?: ScanAuth): Record<string, string> {
  if (!auth) return {};
  const out: Record<string, string> = {};
  for (const [k, v] of Object.entries(auth.headers ?? {})) {
    if (k && typeof v === 'string') out[k.toLowerCase()] = v;
  }
  if (auth.cookies) out['cookie'] = auth.cookies;
  return out;
}

/** fetch() with an AbortController-backed timeout. */
export async function timedFetch(
  url: string,
  timeoutMs: number,
  init: RequestInit = {},
): Promise<Response> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    return await fetch(url, {
      redirect: 'manual',
      ...init,
      signal: controller.signal,
      headers: {
        'user-agent': config.userAgent,
        accept: 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        ...(init.headers ?? {}),
      },
    });
  } finally {
    clearTimeout(timer);
  }
}

function headersToObject(h: Headers): Record<string, string> {
  const out: Record<string, string> = {};
  h.forEach((value, key) => {
    // Preserve last value; set-cookie is handled separately.
    if (key.toLowerCase() !== 'set-cookie') out[key.toLowerCase()] = value;
  });
  return out;
}

function getSetCookie(h: Headers): string[] {
  // Node 18.14+ exposes getSetCookie(); fall back gracefully.
  const anyH = h as Headers & { getSetCookie?: () => string[] };
  if (typeof anyH.getSetCookie === 'function') return anyH.getSetCookie();
  const raw = h.get('set-cookie');
  return raw ? [raw] : [];
}

/**
 * Fetch a page while tracing the redirect chain manually (up to `maxHops`).
 * Returns a {@link PageSnapshot} describing the final response.
 */
export async function fetchPage(
  startUrl: string,
  timeoutMs: number,
  maxHops = 8,
  authHeaders: Record<string, string> = {},
): Promise<PageSnapshot> {
  const redirects: RedirectHop[] = [];
  let current = startUrl;
  let latencyMs = 0;

  for (let hop = 0; hop <= maxHops; hop++) {
    const started = performance.now();
    const res = await timedFetch(current, timeoutMs, { headers: authHeaders });
    latencyMs = Math.round(performance.now() - started);

    if (res.status >= 300 && res.status < 400 && res.headers.get('location')) {
      const location = res.headers.get('location') as string;
      redirects.push({ url: current, status: res.status, location });
      current = new URL(location, current).toString();
      // Drain the body to free the socket.
      await res.arrayBuffer().catch(() => undefined);
      continue;
    }

    const body = await res.text().catch(() => '');
    return {
      finalUrl: current,
      status: res.status,
      headers: headersToObject(res.headers),
      setCookie: getSetCookie(res.headers),
      body,
      redirects,
      latencyMs,
    };
  }

  throw new Error(`Too many redirects (>${maxHops}) starting from ${startUrl}`);
}

/** Convenience: normalize a user-supplied target into an https URL. */
export function normalizeTarget(input: string): URL {
  let raw = input.trim();
  if (!/^https?:\/\//i.test(raw)) raw = `https://${raw}`;
  const url = new URL(raw);
  if (!url.hostname) throw new Error('Invalid target: missing hostname');
  return url;
}
