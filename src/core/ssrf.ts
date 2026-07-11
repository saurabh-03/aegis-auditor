/**
 * SSRF protection for scan targets.
 *
 * A publicly-exposed scanner must never be usable to reach internal services
 * (loopback, RFC1918/private ranges, link-local, cloud metadata at
 * 169.254.169.254, etc.). Before a scan runs we resolve the target hostname and
 * reject it if any resolved address is non-public.
 *
 * Limitation: this checks at scan-entry. It does not fully defeat DNS rebinding
 * (a host that resolves public here but private at fetch time). For that, pin
 * the resolved IP through every request — a heavier change noted in
 * docs/DEPLOY-PUBLIC.md. Entry-checking blocks the overwhelming majority of
 * abuse and is the standard baseline.
 */

import { Resolver } from 'node:dns/promises';
import net from 'node:net';
import { config } from './config.js';

export class BlockedTargetError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'BlockedTargetError';
  }
}

/** Hostnames that must never be scanned regardless of resolution. */
const BLOCKED_HOSTNAMES = /^(localhost|.*\.local|.*\.internal|.*\.localhost|ip6-localhost|metadata\.google\.internal)$/i;

/** Return true if an IPv4/IPv6 literal is private, reserved, or otherwise non-public. */
export function isBlockedIp(ip: string): boolean {
  const type = net.isIP(ip);
  if (type === 4) return isBlockedIpv4(ip);
  if (type === 6) return isBlockedIpv6(ip);
  return false;
}

function isBlockedIpv4(ip: string): boolean {
  const p = ip.split('.').map(Number);
  if (p.length !== 4 || p.some((n) => !Number.isInteger(n) || n < 0 || n > 255)) return true;
  const [a, b] = p as [number, number, number, number];
  if (a === 0) return true; // 0.0.0.0/8
  if (a === 10) return true; // private
  if (a === 127) return true; // loopback
  if (a === 169 && b === 254) return true; // link-local incl. cloud metadata
  if (a === 172 && b >= 16 && b <= 31) return true; // private
  if (a === 192 && b === 168) return true; // private
  if (a === 100 && b >= 64 && b <= 127) return true; // CGNAT 100.64/10
  if (a === 192 && b === 0) return true; // 192.0.0/24, 192.0.2/24 (test)
  if (a === 198 && (b === 18 || b === 19)) return true; // benchmarking
  if (a >= 224) return true; // multicast + reserved (224.0.0.0+)
  return false;
}

function isBlockedIpv6(ip: string): boolean {
  const lower = ip.toLowerCase().split('%')[0] ?? '';
  if (lower === '::1' || lower === '::') return true; // loopback / unspecified
  if (lower.startsWith('fe80')) return true; // link-local
  if (lower.startsWith('fc') || lower.startsWith('fd')) return true; // unique local fc00::/7
  if (lower.startsWith('ff')) return true; // multicast
  // IPv4-mapped (::ffff:a.b.c.d) — validate the embedded v4.
  const mapped = /::ffff:(\d+\.\d+\.\d+\.\d+)$/.exec(lower);
  if (mapped) return isBlockedIpv4(mapped[1] as string);
  return false;
}

/**
 * Throw {@link BlockedTargetError} if `hostname` is (or resolves to) a
 * non-public address. No-op when `config.security.blockPrivateTargets` is off
 * (e.g. local development scanning localhost).
 */
export async function assertPublicHost(hostname: string, timeoutMs = config.defaultTimeoutMs): Promise<void> {
  if (!config.security.blockPrivateTargets) return;

  const host = hostname.replace(/^\[|\]$/g, ''); // strip IPv6 brackets
  if (BLOCKED_HOSTNAMES.test(host)) {
    throw new BlockedTargetError(`Target "${hostname}" is not a public host and cannot be scanned.`);
  }

  // IP literal — check directly, no DNS.
  if (net.isIP(host)) {
    if (isBlockedIp(host)) throw new BlockedTargetError(`Target IP "${host}" is private/reserved and cannot be scanned.`);
    return;
  }

  // Resolve and check every address.
  const resolver = new Resolver({ timeout: timeoutMs, tries: 2 });
  const [v4, v6] = await Promise.all([
    resolver.resolve4(host).catch(() => [] as string[]),
    resolver.resolve6(host).catch(() => [] as string[]),
  ]);
  const all = [...v4, ...v6];
  if (all.length === 0) {
    throw new BlockedTargetError(`Target "${hostname}" could not be resolved.`);
  }
  const blocked = all.find((ip) => isBlockedIp(ip));
  if (blocked) {
    throw new BlockedTargetError(`Target "${hostname}" resolves to a private/reserved address (${blocked}) and cannot be scanned.`);
  }
}
