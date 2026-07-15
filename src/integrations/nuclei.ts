/**
 * Nuclei adapter.
 *
 * Nuclei (https://github.com/projectdiscovery/nuclei) is an external binary with
 * a large community template set for known CVEs and misconfigurations. We treat
 * it exactly like Puppeteer: an OPTIONAL capability. If the binary isn't on PATH
 * (or `NUCLEI_BIN`), `runNuclei` resolves `null` and the calling module degrades
 * to an informational finding — the scan never fails because a tool is missing.
 *
 * The pure JSONL parser (`parseNucleiJsonl`) is separated from process spawning
 * so the result→Finding mapping can be unit-tested without the binary installed.
 */

import { spawn } from 'node:child_process';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

export type NucleiSeverity = 'info' | 'low' | 'medium' | 'high' | 'critical' | 'unknown';

/** One normalized Nuclei match. */
export interface NucleiResult {
  templateId: string;
  name: string;
  severity: NucleiSeverity;
  description?: string;
  /** The exact URL/location the template matched at. */
  matchedAt: string;
  type?: string;
  cve: string[];
  cwe: string[];
  cvss?: number;
  reference: string[];
  remediation?: string;
  tags: string[];
  request?: string;
  response?: string;
}

export interface NucleiOptions {
  /** Binary name/path; defaults to `NUCLEI_BIN` env or `nuclei`. */
  binaryPath?: string;
  /** Severity floor filter passed to `-severity` (e.g. ['medium','high','critical']). */
  severities?: NucleiSeverity[];
  /** Requests-per-second cap (`-rl`). */
  rateLimit?: number;
  /** Hard wall-clock kill timeout for the whole run. */
  timeoutMs?: number;
  /** Restrict to specific templates/dirs (`-t`); empty = default template set. */
  templates?: string[];
  /** Capture request/response pairs (`-irr`) for evidence. */
  includeRequestResponse?: boolean;
  /** Escape hatch for additional raw args. */
  extraArgs?: string[];
  log?: (msg: string) => void;
}

const VALID_SEVERITIES: NucleiSeverity[] = ['info', 'low', 'medium', 'high', 'critical', 'unknown'];

function normalizeSeverity(raw: unknown): NucleiSeverity {
  const s = String(raw ?? '').toLowerCase();
  return (VALID_SEVERITIES as string[]).includes(s) ? (s as NucleiSeverity) : 'unknown';
}

function asStringArray(v: unknown): string[] {
  if (Array.isArray(v)) return v.map((x) => String(x)).filter(Boolean);
  if (typeof v === 'string' && v) return [v];
  return [];
}

/**
 * Parse Nuclei `-jsonl` output (one JSON object per line) into normalized
 * results. Malformed lines are skipped, so a partial/truncated stream still
 * yields whatever parsed cleanly.
 */
export function parseNucleiJsonl(text: string): NucleiResult[] {
  const out: NucleiResult[] = [];
  for (const line of text.split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!trimmed || trimmed[0] !== '{') continue;
    let obj: any;
    try {
      obj = JSON.parse(trimmed);
    } catch {
      continue;
    }
    const info = obj.info ?? {};
    const cls = info.classification ?? {};
    const templateId = String(obj['template-id'] ?? obj.templateID ?? obj.template ?? '').trim();
    const matchedAt = String(obj['matched-at'] ?? obj.matched ?? obj.host ?? '').trim();
    if (!templateId || !matchedAt) continue;

    const cvssRaw = cls['cvss-score'] ?? cls.cvssScore;
    const cvss = typeof cvssRaw === 'number' ? cvssRaw : Number.isFinite(Number(cvssRaw)) ? Number(cvssRaw) : undefined;

    out.push({
      templateId,
      name: String(info.name ?? templateId),
      severity: normalizeSeverity(info.severity),
      description: info.description ? String(info.description) : undefined,
      matchedAt,
      type: obj.type ? String(obj.type) : undefined,
      cve: asStringArray(cls['cve-id'] ?? cls.cveId),
      cwe: asStringArray(cls['cwe-id'] ?? cls.cweId),
      ...(cvss !== undefined ? { cvss } : {}),
      reference: asStringArray(info.reference),
      remediation: info.remediation ? String(info.remediation) : undefined,
      tags: asStringArray(info.tags),
      request: obj.request ? String(obj.request) : undefined,
      response: obj.response ? String(obj.response) : undefined,
    });
  }
  return out;
}

/**
 * Run Nuclei against `urls`. Resolves:
 *   - `NucleiResult[]` on success (possibly empty — no matches is a valid result),
 *   - `null` when the binary is unavailable or failed to start (degrade to info).
 *
 * Never rejects: every failure path maps to `null` or partial results, so a
 * scan module can `?? handleUnavailable()` cleanly.
 */
export async function runNuclei(urls: string[], opts: NucleiOptions = {}): Promise<NucleiResult[] | null> {
  const log = opts.log ?? (() => {});
  if (urls.length === 0) return [];

  const bin = opts.binaryPath ?? process.env.NUCLEI_BIN ?? 'nuclei';
  const timeoutMs = opts.timeoutMs ?? 120_000;

  let dir: string | null = null;
  try {
    dir = await mkdtemp(join(tmpdir(), 'aegis-nuclei-'));
    const listFile = join(dir, 'targets.txt');
    await writeFile(listFile, urls.join('\n'), 'utf8');

    const args = [
      '-jsonl',
      '-silent',
      '-nc', // no color
      '-duc', // disable update check (no network calls to update templates mid-scan)
      '-l',
      listFile,
    ];
    if (opts.severities?.length) args.push('-severity', opts.severities.join(','));
    if (opts.rateLimit) args.push('-rl', String(opts.rateLimit));
    for (const t of opts.templates ?? []) args.push('-t', t);
    if (opts.includeRequestResponse) args.push('-irr');
    if (opts.extraArgs?.length) args.push(...opts.extraArgs);

    const results = await new Promise<NucleiResult[] | null>((resolve) => {
      let stdout = '';
      let settled = false;
      const done = (value: NucleiResult[] | null) => {
        if (settled) return;
        settled = true;
        resolve(value);
      };

      let child: ReturnType<typeof spawn>;
      try {
        child = spawn(bin, args, { stdio: ['ignore', 'pipe', 'pipe'] });
      } catch {
        done(null);
        return;
      }

      const killer = setTimeout(() => {
        log(`Nuclei exceeded ${timeoutMs}ms — terminating; returning partial results.`);
        try {
          child.kill('SIGKILL');
        } catch {
          /* ignore */
        }
        done(parseNucleiJsonl(stdout));
      }, timeoutMs);

      child.stdout?.on('data', (d) => {
        stdout += d.toString();
      });
      child.stderr?.on('data', (d) => {
        const s = d.toString().trim();
        if (s) log(`nuclei: ${s.slice(0, 200)}`);
      });
      child.on('error', (err: NodeJS.ErrnoException) => {
        clearTimeout(killer);
        if (err.code === 'ENOENT') {
          log(`Nuclei binary "${bin}" not found — skipping active template scan.`);
          done(null);
        } else {
          log(`Nuclei failed to start: ${err.message}`);
          done(null);
        }
      });
      child.on('close', () => {
        clearTimeout(killer);
        done(parseNucleiJsonl(stdout));
      });
    });

    return results;
  } catch (err) {
    log(`Nuclei adapter error: ${err instanceof Error ? err.message : String(err)}`);
    return null;
  } finally {
    if (dir) await rm(dir, { recursive: true, force: true }).catch(() => {});
  }
}
