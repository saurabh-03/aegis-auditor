/**
 * Software-composition analysis endpoint.
 *   POST /api/sca   body: { manifest: string, filename?: string, source?, failOn? }
 *
 * Parses a dependency manifest (package-lock.json, package.json, yarn.lock,
 * composer.lock), matches every package against OSV.dev + the local dataset,
 * and returns vulnerabilities + a severity summary. Public + rate-limited, like
 * the synchronous scan endpoint; put auth/an API key in front for production.
 */

import type { FastifyInstance } from 'fastify';
import { matchPackages } from '../intel/cve-match.js';
import { parseManifest } from '../intel/manifest.js';
import { rateLimit } from './ratelimit.js';

const SEV_RANK: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1 };

interface ScaBody {
  manifest?: string;
  filename?: string;
  source?: 'local' | 'osv' | 'both';
  failOn?: string;
}

export function registerScaRoutes(app: FastifyInstance): void {
  app.post<{ Body: ScaBody }>(
    '/api/sca',
    { bodyLimit: 12 * 1024 * 1024 }, // lockfiles can be large
    async (req, reply) => {
      const rl = rateLimit(req.ip || 'unknown');
      reply.header('x-ratelimit-remaining', String(rl.remaining));
      if (!rl.ok) return reply.code(429).send({ error: 'rate_limited', resetAt: rl.resetAt });

      const body = req.body ?? {};
      if (!body.manifest || typeof body.manifest !== 'string') {
        return reply.code(400).send({ error: 'missing_manifest', message: 'Provide the manifest file contents as "manifest".' });
      }

      let parsed;
      try {
        parsed = parseManifest(body.manifest, body.filename);
      } catch (err) {
        return reply.code(400).send({ error: 'unrecognized_manifest', message: (err as Error).message });
      }

      const { matches, sourceUsed, scanned } = await matchPackages(parsed.packages, {
        ...(body.source ? { source: body.source } : {}),
      });

      const summary = { critical: 0, high: 0, medium: 0, low: 0 };
      for (const m of matches) summary[m.entry.severity as keyof typeof summary]++;

      const failOn = (body.failOn ?? 'high').toLowerCase();
      const threshold = SEV_RANK[failOn] ?? SEV_RANK.high!;
      const failing = matches.filter((m) => (SEV_RANK[m.entry.severity] ?? 0) >= threshold).length;

      return reply.send({
        manifest: parsed.format,
        ecosystem: parsed.ecosystem,
        scanned,
        sourceUsed,
        summary,
        failOn,
        failing,
        vulnerabilities: matches.map((m) => ({
          package: m.component,
          version: m.version,
          cve: m.entry.cve,
          cvss: m.entry.cvss,
          severity: m.entry.severity,
          weakness: m.entry.weakness,
          fixedIn: m.entry.fixedIn,
          reference: m.entry.reference,
        })),
      });
    },
  );
}
