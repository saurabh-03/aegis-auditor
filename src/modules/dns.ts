/** Module 4 — DNS & email-authentication analysis. */

import { Resolver } from 'node:dns/promises';
import { finding, pass } from '../core/finding.js';
import type { Finding, ModuleResult, ScanContext, ScanModule } from '../core/types.js';

const MODULE = 'dns';

async function safe<T>(p: Promise<T>): Promise<T | null> {
  try {
    return await p;
  } catch {
    return null;
  }
}

function registrableDomain(hostname: string): string {
  const parts = hostname.split('.');
  return parts.length <= 2 ? hostname : parts.slice(-2).join('.');
}

export const dnsModule: ScanModule = {
  name: MODULE,
  title: 'DNS Analysis',
  category: 'infrastructure',
  mode: 'passive',
  description: 'Inspects A/AAAA/MX/TXT records plus SPF, DMARC, and CAA email/security posture.',
  async run(ctx: ScanContext): Promise<ModuleResult> {
    const t0 = performance.now();
    const resolver = new Resolver({ timeout: ctx.options.timeoutMs, tries: 2 });
    const host = ctx.target.hostname;
    const domain = registrableDomain(host);
    const findings: Finding[] = [];

    const [a, aaaa, mx, txt, caa, dmarc] = await Promise.all([
      safe(resolver.resolve4(host)),
      safe(resolver.resolve6(host)),
      safe(resolver.resolveMx(domain)),
      safe(resolver.resolveTxt(domain)),
      safe(resolver.resolveCaa(domain)),
      safe(resolver.resolveTxt(`_dmarc.${domain}`)),
    ]);

    const txtFlat = (txt ?? []).map((chunks) => chunks.join(''));
    const spf = txtFlat.find((r) => /^v=spf1/i.test(r));

    // IPv6
    if (!aaaa || aaaa.length === 0) {
      findings.push(
        finding({
          id: 'dns.no-ipv6',
          module: MODULE,
          category: 'infrastructure',
          title: 'No AAAA (IPv6) record',
          severity: 'low',
          status: 'warn',
          risk: 'IPv6-only clients and some mobile networks may reach the site less efficiently.',
          whyItMatters: 'IPv6 improves reach and latency on modern networks and is increasingly expected for infrastructure maturity.',
          technical: `No AAAA record for ${host}. Consider dual-stack (A + AAAA) via your CDN/host.`,
          businessImpact: 'Marginal reach/performance gap; infrastructure-maturity signal.',
          probability: 'low',
          remediation: 'Enable IPv6 at your CDN/hosting provider and publish AAAA records.',
          estimatedFixTime: '1-2 hours',
          references: ['https://www.internetsociety.org/deploy360/ipv6/'],
        }),
      );
    } else {
      findings.push(pass(MODULE, 'infrastructure', 'dns.ipv6.ok', 'IPv6 (AAAA) available', `${aaaa.length} AAAA record(s).`, { aaaa }));
    }

    // SPF
    if (mx && mx.length > 0 && !spf) {
      findings.push(
        finding({
          id: 'dns.spf.missing',
          module: MODULE,
          category: 'security',
          title: 'No SPF record for a mail-enabled domain',
          severity: 'medium',
          status: 'fail',
          risk: 'Attackers can spoof email from your domain, aiding phishing.',
          whyItMatters: 'SPF tells receivers which servers may send mail for your domain. Without it, spoofed mail is more likely to be delivered.',
          technical: `Domain ${domain} has MX records but no "v=spf1" TXT record.`,
          businessImpact: 'Phishing/impersonation of your brand, deliverability issues, and reputational harm.',
          probability: 'medium',
          owasp: ['A05:2021-Security Misconfiguration'],
          remediation: 'Publish an SPF record listing authorized senders and ending in -all (or ~all during rollout).',
          estimatedFixTime: '30 minutes',
          exampleCode: `${domain}. IN TXT "v=spf1 include:_spf.google.com -all"`,
          references: ['https://datatracker.ietf.org/doc/html/rfc7208'],
        }),
      );
    } else if (spf) {
      findings.push(pass(MODULE, 'security', 'dns.spf.ok', 'SPF record present', spf, { spf }));
    }

    // DMARC
    const dmarcRec = (dmarc ?? []).map((c) => c.join('')).find((r) => /^v=DMARC1/i.test(r));
    if (mx && mx.length > 0 && !dmarcRec) {
      findings.push(
        finding({
          id: 'dns.dmarc.missing',
          module: MODULE,
          category: 'security',
          title: 'No DMARC record',
          severity: 'medium',
          status: 'fail',
          risk: 'Without DMARC, SPF/DKIM failures are not enforced and you get no visibility into abuse.',
          whyItMatters: 'DMARC ties SPF/DKIM together, tells receivers what to do with failures, and provides aggregate reports on who sends as you.',
          technical: `No "v=DMARC1" TXT record at _dmarc.${domain}. Start at p=none with rua reporting, then progress to quarantine/reject.`,
          businessImpact: 'Ongoing brand spoofing exposure and no phishing telemetry.',
          probability: 'medium',
          owasp: ['A05:2021-Security Misconfiguration'],
          remediation: 'Publish a DMARC policy, monitor reports, then tighten to reject.',
          estimatedFixTime: '1 hour',
          exampleCode: `_dmarc.${domain}. IN TXT "v=DMARC1; p=none; rua=mailto:dmarc@${domain}; fo=1"`,
          references: ['https://dmarc.org/'],
        }),
      );
    } else if (dmarcRec) {
      const enforced = /p=(quarantine|reject)/i.test(dmarcRec);
      findings.push(
        enforced
          ? pass(MODULE, 'security', 'dns.dmarc.ok', 'DMARC enforced', dmarcRec, { dmarc: dmarcRec })
          : finding({
              id: 'dns.dmarc.monitor-only',
              module: MODULE,
              category: 'security',
              title: 'DMARC is monitor-only (p=none)',
              severity: 'low',
              status: 'warn',
              risk: 'A p=none policy reports abuse but does not stop spoofed mail.',
              whyItMatters: 'Monitoring is a good first step, but enforcement (quarantine/reject) is what actually blocks impersonation.',
              technical: `DMARC record: ${dmarcRec}. Advance to p=quarantine then p=reject once reports are clean.`,
              businessImpact: 'Spoofing still possible until enforcement is enabled.',
              probability: 'low',
              remediation: 'Progress the policy to p=reject after validating legitimate senders.',
              estimatedFixTime: '30 minutes',
              references: ['https://dmarc.org/'],
              evidence: { dmarc: dmarcRec },
            }),
      );
    }

    // CAA
    if (!caa || caa.length === 0) {
      findings.push(
        finding({
          id: 'dns.caa.missing',
          module: MODULE,
          category: 'security',
          title: 'No CAA record',
          severity: 'low',
          status: 'warn',
          risk: 'Any CA can issue certificates for your domain, widening mis-issuance risk.',
          whyItMatters: 'CAA records restrict which certificate authorities may issue for your domain, reducing the chance of unauthorized certificates.',
          technical: `No CAA record for ${domain}. Publish CAA to pin your CA(s).`,
          businessImpact: 'Slightly elevated risk of fraudulent certificate issuance.',
          probability: 'low',
          remediation: 'Add a CAA record for your CA.',
          estimatedFixTime: '20 minutes',
          exampleCode: `${domain}. IN CAA 0 issue "letsencrypt.org"`,
          references: ['https://letsencrypt.org/docs/caa/'],
        }),
      );
    } else {
      findings.push(pass(MODULE, 'security', 'dns.caa.ok', 'CAA record present', 'Certificate issuance is restricted to specified CAs.', { caa }));
    }

    return {
      module: MODULE,
      category: 'infrastructure',
      ok: true,
      findings,
      durationMs: Math.round(performance.now() - t0),
      data: { a, aaaa, mx, txt: txtFlat, caa, spf, dmarc: dmarcRec, domain },
    };
  },
};
