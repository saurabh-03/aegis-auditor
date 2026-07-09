/** Minimal semver parsing and range comparison (no dependency). */

export interface SemVer {
  major: number;
  minor: number;
  patch: number;
}

export function parse(version: string): SemVer | null {
  const m = /^v?(\d+)(?:\.(\d+))?(?:\.(\d+))?/.exec(version.trim());
  if (!m) return null;
  return {
    major: Number(m[1] ?? 0),
    minor: Number(m[2] ?? 0),
    patch: Number(m[3] ?? 0),
  };
}

/** Returns -1, 0, or 1 comparing a to b. */
export function compare(a: SemVer, b: SemVer): number {
  if (a.major !== b.major) return a.major < b.major ? -1 : 1;
  if (a.minor !== b.minor) return a.minor < b.minor ? -1 : 1;
  if (a.patch !== b.patch) return a.patch < b.patch ? -1 : 1;
  return 0;
}

export function lt(a: string, b: string): boolean {
  const pa = parse(a);
  const pb = parse(b);
  return pa && pb ? compare(pa, pb) < 0 : false;
}

export function gte(a: string, b: string): boolean {
  const pa = parse(a);
  const pb = parse(b);
  return pa && pb ? compare(pa, pb) >= 0 : false;
}

/**
 * True if `version` falls in [introduced, fixed) — i.e. >= introduced (default 0.0.0)
 * and < fixed. This is the standard "affected up to but not including the fix" range.
 */
export function inVulnerableRange(version: string, fixed: string, introduced = '0.0.0'): boolean {
  return gte(version, introduced) && lt(version, fixed);
}
