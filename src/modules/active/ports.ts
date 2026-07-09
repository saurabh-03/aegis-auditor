/**
 * Module 6 — Port Scanner (ACTIVE, authorization-gated).
 *
 * Conservative by design: TCP connect() to a small fixed list of well-known
 * ports with a short timeout, sequentially. No banner grabbing, no exploitation,
 * no brute forcing. Purpose is to flag *unexpectedly exposed* services.
 */

import net from 'node:net';
import { finding, pass } from '../../core/finding.js';
import type { Finding, ModuleResult, ScanContext, ScanModule } from '../../core/types.js';

const MODULE = 'ports';

interface PortDef {
  port: number;
  service: string;
  /** Severity if this port is open to the internet. */
  exposedSeverity: Finding['severity'] | null;
  note: string;
}

const PORTS: PortDef[] = [
  { port: 80, service: 'HTTP', exposedSeverity: null, note: 'Expected for web traffic (should redirect to HTTPS).' },
  { port: 443, service: 'HTTPS', exposedSeverity: null, note: 'Expected for web traffic.' },
  { port: 21, service: 'FTP', exposedSeverity: 'high', note: 'FTP is plaintext; credentials and data are exposed. Prefer SFTP/FTPS and restrict access.' },
  { port: 22, service: 'SSH', exposedSeverity: 'low', note: 'SSH exposed publicly — ensure key-only auth, no root login, and fail2ban/allow-listing.' },
  { port: 23, service: 'Telnet', exposedSeverity: 'critical', note: 'Telnet is plaintext and obsolete; it should never be internet-exposed.' },
  { port: 25, service: 'SMTP', exposedSeverity: 'low', note: 'Ensure the mail server is not an open relay.' },
  { port: 3306, service: 'MySQL', exposedSeverity: 'critical', note: 'Databases must never be internet-exposed; bind to private networks only.' },
  { port: 5432, service: 'PostgreSQL', exposedSeverity: 'critical', note: 'Databases must never be internet-exposed; bind to private networks only.' },
  { port: 6379, service: 'Redis', exposedSeverity: 'critical', note: 'Redis is frequently unauthenticated; public exposure is a common breach vector.' },
  { port: 27017, service: 'MongoDB', exposedSeverity: 'critical', note: 'Exposed MongoDB has caused numerous mass data breaches.' },
  { port: 9200, service: 'Elasticsearch', exposedSeverity: 'critical', note: 'Exposed Elasticsearch clusters routinely leak entire datasets.' },
  { port: 11211, service: 'Memcached', exposedSeverity: 'high', note: 'Exposed Memcached enables data leakage and UDP amplification DDoS.' },
];

function probe(host: string, port: number, timeoutMs: number): Promise<boolean> {
  return new Promise((resolve) => {
    const socket = new net.Socket();
    let settled = false;
    const done = (open: boolean) => {
      if (settled) return;
      settled = true;
      socket.destroy();
      resolve(open);
    };
    socket.setTimeout(timeoutMs);
    socket.once('connect', () => done(true));
    socket.once('timeout', () => done(false));
    socket.once('error', () => done(false));
    socket.connect(port, host);
  });
}

export const portsModule: ScanModule = {
  name: MODULE,
  title: 'Port Scanner',
  category: 'infrastructure',
  mode: 'active',
  description: 'Checks a small list of well-known ports for unexpected exposure (authorization required).',
  async run(ctx: ScanContext): Promise<ModuleResult> {
    const t0 = performance.now();
    const host = ctx.target.hostname;
    const findings: Finding[] = [];
    const open: number[] = [];
    const timeout = Math.min(ctx.options.timeoutMs, 3000);

    // Sequential to stay gentle.
    for (const def of PORTS) {
      const isOpen = await probe(host, def.port, timeout);
      if (!isOpen) continue;
      open.push(def.port);
      if (def.exposedSeverity === null) continue;
      findings.push(
        finding({
          id: `ports.open.${def.port}`,
          module: MODULE,
          category: 'infrastructure',
          title: `${def.service} port ${def.port} is open to the internet`,
          severity: def.exposedSeverity,
          status: 'fail',
          risk: `Publicly reachable ${def.service} increases attack surface substantially.`,
          whyItMatters:
            `${def.note} Every internet-exposed service is a potential entry point that must be patched, monitored, and access-controlled.`,
          technical: `A TCP connection to ${host}:${def.port} (${def.service}) succeeded. Restrict this to private networks / a VPN / an allow-list, or close it entirely if unused.`,
          businessImpact:
            def.exposedSeverity === 'critical'
              ? 'Potential full data breach or system compromise via a directly exposed backend service.'
              : 'Expanded attack surface and higher likelihood of compromise.',
          probability: def.exposedSeverity === 'critical' ? 'high' : 'medium',
          owasp: ['A05:2021-Security Misconfiguration'],
          remediation: `Firewall port ${def.port} to trusted sources only, or disable the service if not required. Bind databases to localhost/private subnets.`,
          estimatedFixTime: '1-3 hours',
          exampleCode: `# ufw example\nsudo ufw deny ${def.port}\n# or bind db to private interface only (e.g. bind-address=10.0.0.5)`,
          references: ['https://owasp.org/Top10/A05_2021-Security_Misconfiguration/'],
          evidence: { port: def.port, service: def.service },
        }),
      );
    }

    if (findings.length === 0) {
      findings.push(pass(MODULE, 'infrastructure', 'ports.clean', 'No unexpected open ports found', `Open ports among the checked set: ${open.join(', ') || 'none beyond standard web ports'}.`, { open }));
    }

    return { module: MODULE, category: 'infrastructure', ok: true, findings, durationMs: Math.round(performance.now() - t0), data: { open } };
  },
};
