/** In-memory Store implementation. Default when no DATABASE_URL is configured. */

import { randomBytes, randomUUID } from 'node:crypto';
import type {
  Membership,
  NewUser,
  OAuthAccount,
  Organization,
  Project,
  Role,
  ScanRecord,
  Store,
  Team,
  User,
} from './types.js';

function slugify(name: string): string {
  return name.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '') || 'org';
}

export class MemoryStore implements Store {
  readonly kind = 'memory' as const;

  private users = new Map<string, User>();
  private usersByEmail = new Map<string, string>();
  private oauth = new Map<string, string>(); // `${provider}:${id}` -> userId
  private orgs = new Map<string, Organization>();
  private memberships: Membership[] = [];
  private teams = new Map<string, Team>();
  private projects = new Map<string, Project>();
  private scans = new Map<string, ScanRecord>();
  private orgSlugs = new Set<string>();

  async init(): Promise<void> {}
  async close(): Promise<void> {}

  async createUser(u: NewUser): Promise<User> {
    const email = u.email.toLowerCase();
    if (this.usersByEmail.has(email)) throw new Error('email_taken');
    const user: User = {
      id: randomUUID(),
      email,
      name: u.name ?? null,
      passwordHash: u.passwordHash ?? null,
      createdAt: new Date().toISOString(),
    };
    this.users.set(user.id, user);
    this.usersByEmail.set(email, user.id);
    return user;
  }

  async getUserByEmail(email: string): Promise<User | null> {
    const id = this.usersByEmail.get(email.toLowerCase());
    return id ? this.users.get(id) ?? null : null;
  }

  async getUserById(id: string): Promise<User | null> {
    return this.users.get(id) ?? null;
  }

  async linkOAuth(acc: OAuthAccount): Promise<void> {
    this.oauth.set(`${acc.provider}:${acc.providerUserId}`, acc.userId);
  }

  async getUserByOAuth(provider: string, providerUserId: string): Promise<User | null> {
    const id = this.oauth.get(`${provider}:${providerUserId}`);
    return id ? this.users.get(id) ?? null : null;
  }

  async createOrganization(name: string, ownerUserId: string): Promise<Organization> {
    let slug = slugify(name);
    while (this.orgSlugs.has(slug)) slug = `${slugify(name)}-${randomBytes(2).toString('hex')}`;
    this.orgSlugs.add(slug);
    const org: Organization = { id: randomUUID(), name, slug, plan: 'FREE', createdAt: new Date().toISOString() };
    this.orgs.set(org.id, org);
    await this.addMember(org.id, ownerUserId, 'OWNER');
    return org;
  }

  async getOrganization(orgId: string): Promise<Organization | null> {
    return this.orgs.get(orgId) ?? null;
  }

  async listOrganizationsForUser(userId: string): Promise<Array<Organization & { role: Role }>> {
    return this.memberships
      .filter((m) => m.userId === userId)
      .map((m) => {
        const org = this.orgs.get(m.orgId)!;
        return { ...org, role: m.role };
      });
  }

  async getMembership(userId: string, orgId: string): Promise<Membership | null> {
    return this.memberships.find((m) => m.userId === userId && m.orgId === orgId) ?? null;
  }

  async addMember(orgId: string, userId: string, role: Role): Promise<Membership> {
    const existing = await this.getMembership(userId, orgId);
    if (existing) return existing;
    const m: Membership = { id: randomUUID(), orgId, userId, role };
    this.memberships.push(m);
    return m;
  }

  async createTeam(orgId: string, name: string): Promise<Team> {
    const t: Team = { id: randomUUID(), orgId, name };
    this.teams.set(t.id, t);
    return t;
  }

  async listTeams(orgId: string): Promise<Team[]> {
    return [...this.teams.values()].filter((t) => t.orgId === orgId);
  }

  async createProject(orgId: string, name: string, target: string, ownershipToken: string): Promise<Project> {
    const p: Project = {
      id: randomUUID(),
      orgId,
      name,
      target,
      ownershipToken,
      verifiedAt: null,
      createdAt: new Date().toISOString(),
    };
    this.projects.set(p.id, p);
    return p;
  }

  async getProject(projectId: string): Promise<Project | null> {
    return this.projects.get(projectId) ?? null;
  }

  async listProjects(orgId: string): Promise<Project[]> {
    return [...this.projects.values()].filter((p) => p.orgId === orgId);
  }

  async markProjectVerified(projectId: string): Promise<Project | null> {
    const p = this.projects.get(projectId);
    if (!p) return null;
    p.verifiedAt = new Date().toISOString();
    return p;
  }

  async saveScan(rec: Omit<ScanRecord, 'id' | 'createdAt'>): Promise<ScanRecord> {
    const s: ScanRecord = { ...rec, id: randomUUID(), createdAt: new Date().toISOString() };
    this.scans.set(s.id, s);
    return s;
  }

  async updateScan(
    id: string,
    patch: Partial<Pick<ScanRecord, 'status' | 'overall' | 'grade' | 'report'>>,
  ): Promise<ScanRecord | null> {
    const s = this.scans.get(id);
    if (!s) return null;
    Object.assign(s, patch);
    return s;
  }

  async getScan(id: string): Promise<ScanRecord | null> {
    return this.scans.get(id) ?? null;
  }

  async listScans(opts: { orgId?: string; projectId?: string; limit: number; offset: number }) {
    let all = [...this.scans.values()].reverse();
    if (opts.orgId) all = all.filter((s) => s.orgId === opts.orgId);
    if (opts.projectId) all = all.filter((s) => s.projectId === opts.projectId);
    return { total: all.length, items: all.slice(opts.offset, opts.offset + opts.limit) };
  }

  async scanHistoryForTarget(target: string, orgId?: string) {
    return [...this.scans.values()]
      .filter((s) => s.target === target && (!orgId || s.orgId === orgId) && s.overall != null)
      .map((s) => ({ id: s.id, createdAt: s.createdAt, score: s.overall as number }))
      .sort((a, b) => a.createdAt.localeCompare(b.createdAt));
  }
}
