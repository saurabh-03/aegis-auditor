/** Module 1 — SSL / TLS analysis via a live TLS handshake. */

import tls from 'node:tls';
import { finding, pass } from '../core/finding.js';
import type { Finding, ModuleResult, ScanContext, ScanModule } from '../core/types.js';

const MODULE = 'ssl';

interface TlsInfo {
  protocol: string | null;
  cipher: tls.CipherNameAndProtocol | null;
  cert: tls.PeerCertificate | null;
  authorized: boolean;
  authorizationError?: string;
}

function handshake(host: string, port: number, timeoutMs: number): Promise<TlsInfo> {
  return new Promise((resolve, reject) => {
    const socket = tls.connect(
      { host, port, servername: host, timeout: timeoutMs, rejectUnauthorized: false },
      () => {
        const info: TlsInfo = {
          protocol: socket.getProtocol(),
          cipher: socket.getCipher(),
          cert: socket.getPeerCertificate(true),
          authorized: socket.authorized,
          ...(socket.authorizationError ? { authorizationError: String(socket.authorizationError) } : {}),
        };
        socket.end();
        resolve(info);
      },
    );
    socket.setTimeout(timeoutMs, () => {
      socket.destroy();
      reject(new Error(`TLS handshake timed out after ${timeoutMs}ms`));
    });
    socket.on('error', reject);
  });
}

const WEAK_PROTOCOLS = new Set(['TLSv1', 'TLSv1.1', 'SSLv3', 'SSLv2']);

export const sslModule: ScanModule = {
  name: MODULE,
  title: 'SSL / TLS Analysis',
  category: 'security',
  mode: 'passive',
  description: 'Performs a TLS handshake to inspect certificate, chain, protocol, and cipher.',
  async run(ctx: ScanContext): Promise<ModuleResult> {
    const t0 = performance.now();
    const host = ctx.target.hostname;
    const port = ctx.target.port ? Number(ctx.target.port) : 443;
    const findings: Finding[] = [];

    let info: TlsInfo;
    try {
      info = await handshake(host, port, ctx.options.timeoutMs);
    } catch (err) {
      findings.push(
        finding({
          id: 'ssl.handshake-failed',
          module: MODULE,
          category: 'security',
          title: 'TLS handshake failed',
          severity: 'high',
          status: 'fail',
          risk: 'HTTPS could not be established, indicating a misconfiguration or no TLS at all.',
          whyItMatters: 'If TLS cannot be negotiated, the site either lacks HTTPS or has a broken configuration blocking secure connections.',
          technical: `tls.connect to ${host}:${port} failed: ${err instanceof Error ? err.message : String(err)}`,
          businessImpact: 'Users cannot connect securely; browsers may block the site entirely.',
          probability: 'high',
          owasp: ['A02:2021-Cryptographic Failures'],
          remediation: 'Verify a valid certificate is installed and TLS is listening on 443.',
          estimatedFixTime: '1-4 hours',
          references: ['https://ssl-config.mozilla.org/'],
        }),
      );
      return { module: MODULE, category: 'security', ok: true, findings, durationMs: Math.round(performance.now() - t0) };
    }

    const cert = info.cert;
    const now = ctx.now.getTime();

    // Certificate validity / expiry
    if (cert && cert.valid_to) {
      const validTo = new Date(cert.valid_to).getTime();
      const daysLeft = Math.round((validTo - now) / 86_400_000);
      if (daysLeft < 0) {
        findings.push(certFinding('ssl.expired', 'Certificate has expired', 'critical', `The certificate expired ${-daysLeft} day(s) ago (valid_to ${cert.valid_to}).`, 'Browsers will show a full-page security error and block access.', 'Renew and deploy a valid certificate immediately; automate renewal.', cert));
      } else if (daysLeft < 15) {
        findings.push(certFinding('ssl.expiring', 'Certificate expires soon', 'high', `Only ${daysLeft} day(s) until expiry (valid_to ${cert.valid_to}).`, 'An expiring cert risks a hard outage the moment it lapses.', 'Renew now and enable automated renewal (e.g. ACME/Let’s Encrypt or ACM).', cert));
      } else if (daysLeft < 30) {
        findings.push(certFinding('ssl.expiring-soon', 'Certificate expires within 30 days', 'medium', `${daysLeft} day(s) remaining.`, 'Approaching expiry — ensure renewal automation is in place.', 'Confirm auto-renewal or schedule a manual renewal.', cert));
      } else {
        findings.push(pass(MODULE, 'security', 'ssl.validity.ok', 'Certificate validity healthy', `${daysLeft} days until expiry.`, { valid_to: cert.valid_to, daysLeft }));
      }
    }

    // Chain / trust
    if (!info.authorized) {
      findings.push(
        finding({
          id: 'ssl.untrusted-chain',
          module: MODULE,
          category: 'security',
          title: 'Certificate chain is not trusted',
          severity: 'high',
          status: 'fail',
          risk: 'Browsers may reject the certificate, or it may be self-signed / missing intermediates.',
          whyItMatters: 'An untrusted chain triggers security warnings and erodes user trust; it can also indicate a misissued or misconfigured certificate.',
          technical: `TLS authorizationError: ${info.authorizationError ?? 'unknown'}. Ensure the full intermediate chain is served.`,
          businessImpact: 'Blocked visitors, lost conversions, and trust damage.',
          probability: 'high',
          owasp: ['A02:2021-Cryptographic Failures'],
          remediation: 'Serve the complete certificate chain including intermediates; use a publicly trusted CA.',
          estimatedFixTime: '1-2 hours',
          references: ['https://whatsmychaincert.com/', 'https://ssl-config.mozilla.org/'],
          evidence: { authorizationError: info.authorizationError },
        }),
      );
    } else {
      findings.push(pass(MODULE, 'security', 'ssl.chain.ok', 'Certificate chain is trusted', `Issued by ${cert?.issuer?.O ?? cert?.issuer?.CN ?? 'a trusted CA'}.`, { issuer: cert?.issuer }));
    }

    // Protocol version
    const proto = info.protocol ?? '';
    if (WEAK_PROTOCOLS.has(proto)) {
      findings.push(
        finding({
          id: 'ssl.weak-protocol',
          module: MODULE,
          category: 'security',
          title: `Weak TLS protocol negotiated (${proto})`,
          severity: 'high',
          status: 'fail',
          risk: 'Deprecated TLS versions have known cryptographic weaknesses (BEAST, POODLE).',
          whyItMatters: 'TLS 1.0/1.1 and SSL are deprecated and disallowed by PCI-DSS and modern browsers.',
          technical: `The server negotiated ${proto}. Disable everything below TLS 1.2; prefer TLS 1.3.`,
          businessImpact: 'Compliance failure and exposure to downgrade/interception attacks.',
          probability: 'medium',
          owasp: ['A02:2021-Cryptographic Failures'],
          remediation: 'Restrict to TLS 1.2 and 1.3 only.',
          estimatedFixTime: '1-2 hours',
          exampleCode: '# nginx\nssl_protocols TLSv1.2 TLSv1.3;',
          references: ['https://ssl-config.mozilla.org/'],
          evidence: { protocol: proto },
        }),
      );
    } else {
      findings.push(pass(MODULE, 'security', 'ssl.protocol.ok', `Modern TLS protocol (${proto})`, `Negotiated ${proto}, which is current.`, { protocol: proto }));
    }

    // Cipher / forward secrecy hint
    const cipherName = info.cipher?.name ?? '';
    const fs = /ECDHE|DHE/i.test(cipherName) || proto === 'TLSv1.3';
    if (cipherName && !fs) {
      findings.push(
        finding({
          id: 'ssl.no-forward-secrecy',
          module: MODULE,
          category: 'security',
          title: 'Cipher suite may lack forward secrecy',
          severity: 'medium',
          status: 'warn',
          risk: 'Without forward secrecy, a future key compromise can decrypt past recorded traffic.',
          whyItMatters: 'ECDHE/DHE key exchange ensures each session key is ephemeral, so stealing the server key later cannot retroactively decrypt sessions.',
          technical: `Negotiated cipher: ${cipherName}. Prefer ECDHE-based suites or TLS 1.3 (which is forward-secret by design).`,
          businessImpact: 'Long-term confidentiality risk for intercepted traffic.',
          probability: 'low',
          owasp: ['A02:2021-Cryptographic Failures'],
          remediation: 'Prioritize ECDHE cipher suites; enable TLS 1.3.',
          estimatedFixTime: '1-2 hours',
          references: ['https://ssl-config.mozilla.org/'],
          evidence: { cipher: cipherName },
        }),
      );
    } else if (cipherName) {
      findings.push(pass(MODULE, 'security', 'ssl.cipher.ok', 'Forward-secret cipher in use', `Cipher ${cipherName} provides forward secrecy.`, { cipher: cipherName }));
    }

    return {
      module: MODULE,
      category: 'security',
      ok: true,
      findings,
      durationMs: Math.round(performance.now() - t0),
      data: {
        protocol: info.protocol,
        cipher: info.cipher,
        subject: cert?.subject,
        issuer: cert?.issuer,
        valid_from: cert?.valid_from,
        valid_to: cert?.valid_to,
        subjectaltname: cert?.subjectaltname,
        authorized: info.authorized,
      },
    };
  },
};

function certFinding(
  id: string,
  title: string,
  severity: Finding['severity'],
  technical: string,
  businessImpact: string,
  remediation: string,
  cert: tls.PeerCertificate,
): Finding {
  return finding({
    id,
    module: MODULE,
    category: 'security',
    title,
    severity,
    status: 'fail',
    risk: 'Certificate lifecycle problem that can break HTTPS availability.',
    whyItMatters: 'An invalid or expiring certificate leads to browser blocking and outages.',
    technical,
    businessImpact,
    probability: 'high',
    owasp: ['A02:2021-Cryptographic Failures'],
    remediation,
    estimatedFixTime: '1-2 hours',
    references: ['https://letsencrypt.org/', 'https://ssl-config.mozilla.org/'],
    evidence: { valid_from: cert.valid_from, valid_to: cert.valid_to, subject: cert.subject },
  });
}
