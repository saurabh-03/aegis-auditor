/**
 * Dependency-manifest parsers for software-composition analysis (SCA).
 *
 * Turns real lockfiles/manifests into a flat list of {name, version, ecosystem}
 * that feeds the OSV + local CVE matcher. Lockfiles give exact versions (best);
 * package.json ranges are coerced best-effort.
 *
 * Supported: npm package-lock.json (v1/v2/v3), npm package.json, yarn.lock,
 * PHP composer.lock. Format is auto-detected from content.
 */

export interface ManifestPackage {
  name: string;
  version: string;
  ecosystem: string; // OSV ecosystem, e.g. 'npm', 'Packagist'
}

export interface ParsedManifest {
  format: string;
  ecosystem: string;
  packages: ManifestPackage[];
}

/** Coerce a semver range ("^1.2.3", ">=4.0.0 <5") to a concrete-ish version. */
function coerceVersion(raw: string): string | null {
  const m = /(\d+(?:\.\d+){0,2})/.exec(raw);
  return m ? (m[1] as string) : null;
}

function dedupe(pkgs: ManifestPackage[]): ManifestPackage[] {
  const seen = new Set<string>();
  const out: ManifestPackage[] = [];
  for (const p of pkgs) {
    if (!p.name || !p.version) continue;
    const key = `${p.ecosystem}:${p.name}@${p.version}`;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(p);
  }
  return out;
}

// ---------- npm package-lock.json ----------
function parsePackageLock(json: any): ManifestPackage[] {
  const out: ManifestPackage[] = [];
  // v2/v3: `packages` keyed by install path.
  if (json.packages && typeof json.packages === 'object') {
    for (const [path, meta] of Object.entries<any>(json.packages)) {
      if (!path) continue; // "" is the root project
      const name = path.split('node_modules/').pop();
      if (name && meta?.version) out.push({ name, version: meta.version, ecosystem: 'npm' });
    }
  }
  // v1: recursive `dependencies`.
  const walk = (deps: any) => {
    if (!deps || typeof deps !== 'object') return;
    for (const [name, meta] of Object.entries<any>(deps)) {
      if (meta?.version) out.push({ name, version: meta.version, ecosystem: 'npm' });
      if (meta?.dependencies) walk(meta.dependencies);
    }
  };
  if (json.dependencies && !json.packages) walk(json.dependencies);
  return out;
}

// ---------- npm package.json (best-effort, ranges) ----------
function parsePackageJson(json: any): ManifestPackage[] {
  const out: ManifestPackage[] = [];
  for (const field of ['dependencies', 'devDependencies', 'optionalDependencies']) {
    const deps = json[field];
    if (!deps || typeof deps !== 'object') continue;
    for (const [name, range] of Object.entries<string>(deps)) {
      const v = coerceVersion(String(range));
      if (v) out.push({ name, version: v, ecosystem: 'npm' });
    }
  }
  return out;
}

// ---------- composer.lock (Packagist) ----------
function parseComposerLock(json: any): ManifestPackage[] {
  const out: ManifestPackage[] = [];
  for (const field of ['packages', 'packages-dev']) {
    const arr = json[field];
    if (!Array.isArray(arr)) continue;
    for (const p of arr) {
      if (p?.name && p?.version) {
        out.push({ name: p.name, version: String(p.version).replace(/^v/, ''), ecosystem: 'Packagist' });
      }
    }
  }
  return out;
}

// ---------- yarn.lock (classic v1) ----------
function parseYarnLock(text: string): ManifestPackage[] {
  const out: ManifestPackage[] = [];
  const blocks = text.split(/\n(?=\S)/); // new block starts at a non-indented line
  for (const block of blocks) {
    const firstLine = block.split('\n')[0] ?? '';
    if (!firstLine.includes('@') || firstLine.startsWith('#')) continue;
    // spec like:  "@scope/name@^1.0.0", name@~2:
    const spec = firstLine.split(',')[0]!.trim().replace(/:$/, '').replace(/^"|"$/g, '');
    const at = spec.lastIndexOf('@');
    const name = at > 0 ? spec.slice(0, at) : spec;
    const vm = /\n\s+version:?\s+"?([^"\n]+)"?/.exec(block);
    if (name && vm?.[1]) out.push({ name, version: vm[1].trim(), ecosystem: 'npm' });
  }
  return out;
}

/** Auto-detect the manifest format and parse it. Throws on unrecognized input. */
export function parseManifest(content: string, filename?: string): ParsedManifest {
  const name = (filename ?? '').toLowerCase();

  // Try JSON first.
  let json: any = null;
  try {
    json = JSON.parse(content);
  } catch {
    /* not JSON */
  }

  if (json) {
    if (json.lockfileVersion !== undefined || (json.packages && !Array.isArray(json.packages))) {
      return { format: 'package-lock.json', ecosystem: 'npm', packages: dedupe(parsePackageLock(json)) };
    }
    if (Array.isArray(json.packages) || Array.isArray(json['packages-dev'])) {
      return { format: 'composer.lock', ecosystem: 'Packagist', packages: dedupe(parseComposerLock(json)) };
    }
    if (json.dependencies || json.devDependencies) {
      return { format: 'package.json', ecosystem: 'npm', packages: dedupe(parsePackageJson(json)) };
    }
  }

  if (/# yarn lockfile|__metadata:|\n\s+version:? "/.test(content) || name.includes('yarn.lock')) {
    return { format: 'yarn.lock', ecosystem: 'npm', packages: dedupe(parseYarnLock(content)) };
  }

  throw new Error('Unrecognized manifest format. Supported: package-lock.json, package.json, yarn.lock, composer.lock');
}
