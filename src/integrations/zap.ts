/**
 * OWASP ZAP adapter (daemon mode).
 *
 * ZAP (https://www.zaproxy.org) runs as a long-lived daemon exposing a JSON REST
 * API. Unlike Nuclei (a per-run binary) ZAP is a service, so this adapter talks
 * HTTP to `ZAP_API_URL`. It is an OPTIONAL capability: if the daemon isn't
 * reachable, `runZapScan` resolves `null` and the calling module degrades to an
 * info finding — the scan never fails because the service is down.
 *
 * Flow: seed the discovered endpoints into ZAP's site tree (accessUrl), launch a
 * recursive active scan against the target, poll status for progress, then pull
 * and normalize the alerts. The pure `mapZapAlerts` mapping is exported so the
 * alert→Finding translation is unit-testable without a running daemon.
 */

export type ZapRisk = 'High' | 'Medium' | 'Low' | 'Informational';

/** One normalized ZAP alert. */
export interface ZapAlert {
  pluginId: string;
  name: string;
  risk: ZapRisk;
  /** ZAP confidence label: High | Medium | Low | Confirmed | False Positive. */
  confidence: string;
  url: string;
  param?: string;
  method?: string;
  evidence?: string;
  attack?: string;
  description?: string;
  solution?: string;
  reference?: string;
  cweid?: number;
  wascid?: number;
}

export interface ZapOptions {
  /** Daemon base URL (`ZAP_API_URL`), e.g. http://zap:8080. */
  apiUrl?: string;
  /** API key (`ZAP_API_KEY`); sent as the `apikey` query param. */
  apiKey?: string;
  /** Origin/URL to actively scan (recurse covers the seeded tree). */
  target: string;
  /** Overall wall-clock budget for the active scan poll loop. */
  timeoutMs?: number;
  /** Status poll interval. */
  pollIntervalMs?: number;
  /** Cap on endpoints seeded into the tree (bounds setup time). */
  maxSeedUrls?: number;
  /** Best-effort progress (0..1) from the active-scan status. */
  onProgress?: (fraction: number, note?: string) => void;
  log?: (msg: string) => void;
}

const VALID_RISKS: ZapRisk[] = ['High', 'Medium', 'Low', 'Informational'];

function normalizeRisk(raw: unknown): ZapRisk {
  const s = String(raw ?? '').trim();
  const hit = VALID_RISKS.find((r) => r.toLowerCase() === s.toLowerCase());
  return hit ?? 'Informational';
}

/**
 * Normalize the raw `alerts` array from ZAP's `/JSON/core/view/alerts` into
 * typed {@link ZapAlert}s. Tolerant of missing fields and shape drift.
 */
export function parseZapAlerts(raw: unknown): ZapAlert[] {
  const list = Array.isArray((raw as any)?.alerts) ? (raw as any).alerts : Array.isArray(raw) ? raw : [];
  const out: ZapAlert[] = [];
  for (const a of list) {
    if (!a || typeof a !== 'object') continue;
    const url = String(a.url ?? '').trim();
    const name = String(a.alert ?? a.name ?? '').trim();
    if (!url || !name) continue;
    const cweRaw = Number(a.cweid);
    const wascRaw = Number(a.wascid);
    out.push({
      pluginId: String(a.pluginId ?? a.pluginid ?? a.alertRef ?? '0'),
      name,
      risk: normalizeRisk(a.risk),
      confidence: String(a.confidence ?? '').trim(),
      url,
      param: a.param ? String(a.param) : undefined,
      method: a.method ? String(a.method) : undefined,
      evidence: a.evidence ? String(a.evidence) : undefined,
      attack: a.attack ? String(a.attack) : undefined,
      description: a.description ? String(a.description) : undefined,
      solution: a.solution ? String(a.solution) : undefined,
      reference: a.reference ? String(a.reference) : undefined,
      ...(Number.isFinite(cweRaw) && cweRaw > 0 ? { cweid: cweRaw } : {}),
      ...(Number.isFinite(wascRaw) && wascRaw > 0 ? { wascid: wascRaw } : {}),
    });
  }
  return out;
}

async function zapGet(
  base: string,
  path: string,
  params: Record<string, string>,
  apiKey: string | undefined,
  timeoutMs: number,
): Promise<any> {
  const url = new URL(path, base);
  for (const [k, v] of Object.entries(params)) url.searchParams.set(k, v);
  if (apiKey) url.searchParams.set('apikey', apiKey);

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetch(url.toString(), { signal: controller.signal });
    if (!res.ok) throw new Error(`ZAP ${path} → HTTP ${res.status}`);
    return await res.json();
  } finally {
    clearTimeout(timer);
  }
}

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

/**
 * Run a ZAP active scan against `opts.target`, seeded with `urls`. Resolves:
 *   - `ZapAlert[]` on success (possibly empty),
 *   - `null` when the daemon is unreachable or the scan can't start (degrade).
 *
 * Never rejects: failures map to `null` or best-effort partial alerts.
 */
export async function runZapScan(urls: string[], opts: ZapOptions): Promise<ZapAlert[] | null> {
  const log = opts.log ?? (() => {});
  const base = opts.apiUrl ?? process.env.ZAP_API_URL ?? 'http://localhost:8080';
  const apiKey = opts.apiKey ?? process.env.ZAP_API_KEY;
  const timeoutMs = opts.timeoutMs ?? 300_000;
  const pollIntervalMs = opts.pollIntervalMs ?? 3_000;
  const perCallTimeout = 15_000;

  // 1) Health check — if the daemon isn't there, degrade quietly.
  try {
    await zapGet(base, '/JSON/core/view/version/', {}, apiKey, perCallTimeout);
  } catch (err) {
    log(`ZAP daemon not reachable at ${base} — skipping active scan.`);
    return null;
  }

  try {
    // 2) Seed discovered endpoints into ZAP's site tree so the active scan has
    //    context beyond the bare origin. Best-effort per URL.
    const seeds = urls.slice(0, opts.maxSeedUrls ?? 100);
    for (const u of seeds) {
      await zapGet(base, '/JSON/core/action/accessUrl/', { url: u, followRedirects: 'false' }, apiKey, perCallTimeout).catch(
        () => {},
      );
    }

    // 3) Launch the recursive active scan against the target.
    const startRes = await zapGet(
      base,
      '/JSON/ascan/action/scan/',
      { url: opts.target, recurse: 'true', inScopeOnly: 'false' },
      apiKey,
      perCallTimeout,
    );
    const scanId = String(startRes?.scan ?? '');
    if (!scanId || scanId === '-1') {
      log('ZAP active scan did not start (no scan id returned).');
      return null;
    }

    // 4) Poll status → progress, until 100% or the time budget is spent.
    const deadline = Date.now() + timeoutMs;
    opts.onProgress?.(0.02, 'active scan starting');
    for (;;) {
      const statusRes = await zapGet(base, '/JSON/ascan/view/status/', { scanId }, apiKey, perCallTimeout).catch(() => null);
      const pct = Number(statusRes?.status);
      if (Number.isFinite(pct)) {
        opts.onProgress?.(Math.max(0, Math.min(1, pct / 100)), `${pct}%`);
        if (pct >= 100) break;
      }
      if (Date.now() > deadline) {
        log('ZAP active scan exceeded time budget — collecting alerts so far.');
        try {
          await zapGet(base, '/JSON/ascan/action/stop/', { scanId }, apiKey, perCallTimeout);
        } catch {
          /* ignore */
        }
        break;
      }
      await sleep(pollIntervalMs);
    }

    // 5) Pull alerts for the target and normalize.
    const alertsRes = await zapGet(
      base,
      '/JSON/core/view/alerts/',
      { baseurl: opts.target, start: '0', count: '1000' },
      apiKey,
      perCallTimeout,
    );
    return parseZapAlerts(alertsRes);
  } catch (err) {
    log(`ZAP adapter error: ${err instanceof Error ? err.message : String(err)}`);
    return null;
  }
}
