/** In-memory Store implementation. Default when no DATABASE_URL is configured. */

import { randomBytes, randomUUID } from 'node:crypto';
import {
  nextRunFrom,
  type ApiKey,
  type Membership,
  type NewApiKey,
  type NewNotification,
  type NewSchedule,
  type NewUser,
  type Notification,
  type OAuthAccount,
  type Organization,
  type Project,
  type Role,
  type ScanRecord,
  type Schedule,
  type Store,
  type Team,
  type User,
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
  private schedules = new Map<string, Schedule>();
  private notifications = new Map<string, Notification>();
  private apiKeys = new Map<string, ApiKey & { hashedKey: string }>();
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

  async previousScanForProject(projectId: string, excludeScanId: string): Promise<ScanRecord | null> {
    return (
      [...this.scans.values()]
        .filter((s) => s.projectId === projectId && s.id !== excludeScanId && s.status === 'COMPLETED')
        .sort((a, b) => b.createdAt.localeCompare(a.createdAt))[0] ?? null
    );
  }

  // ---- Schedules ----
  async createSchedule(s: NewSchedule): Promise<Schedule> {
    const sched: Schedule = {
      id: randomUUID(),
      projectId: s.projectId,
      orgId: s.orgId,
      cadence: s.cadence,
      includeActive: s.includeActive ?? false,
      enabled: true,
      webhookUrl: s.webhookUrl ?? null,
      nextRunAt: nextRunFrom(s.cadence),
      lastRunAt: null,
      createdAt: new Date().toISOString(),
    };
    this.schedules.set(sched.id, sched);
    return sched;
  }

  async getSchedule(id: string): Promise<Schedule | null> {
    return this.schedules.get(id) ?? null;
  }

  async listSchedules(opts: { orgId?: string; projectId?: string }): Promise<Schedule[]> {
    return [...this.schedules.values()].filter(
      (s) => (!opts.orgId || s.orgId === opts.orgId) && (!opts.projectId || s.projectId === opts.projectId),
    );
  }

  async updateSchedule(
    id: string,
    patch: Partial<Pick<Schedule, 'cadence' | 'enabled' | 'includeActive' | 'webhookUrl' | 'nextRunAt' | 'lastRunAt'>>,
  ): Promise<Schedule | null> {
    const s = this.schedules.get(id);
    if (!s) return null;
    Object.assign(s, patch);
    return s;
  }

  async deleteSchedule(id: string): Promise<boolean> {
    return this.schedules.delete(id);
  }

  async listDueSchedules(nowISO: string): Promise<Schedule[]> {
    return [...this.schedules.values()].filter((s) => s.enabled && s.nextRunAt <= nowISO);
  }

  // ---- Notifications ----
  async createNotification(n: NewNotification): Promise<Notification> {
    const notif: Notification = {
      id: randomUUID(),
      orgId: n.orgId,
      type: n.type,
      scanId: n.scanId ?? null,
      projectId: n.projectId ?? null,
      title: n.title,
      body: n.body,
      severity: n.severity,
      read: false,
      createdAt: new Date().toISOString(),
    };
    this.notifications.set(notif.id, notif);
    return notif;
  }

  async listNotifications(orgId: string, opts: { limit: number; unreadOnly?: boolean }): Promise<Notification[]> {
    return [...this.notifications.values()]
      .filter((n) => n.orgId === orgId && (!opts.unreadOnly || !n.read))
      .sort((a, b) => b.createdAt.localeCompare(a.createdAt))
      .slice(0, opts.limit);
  }

  async markNotificationRead(id: string): Promise<boolean> {
    const n = this.notifications.get(id);
    if (!n) return false;
    n.read = true;
    return true;
  }

  // ---- API keys ----
  private toApiKey(k: ApiKey & { hashedKey: string }): ApiKey {
    const { hashedKey, ...pub } = k;
    void hashedKey;
    return pub;
  }

  async createApiKey(k: NewApiKey): Promise<ApiKey> {
    const rec: ApiKey & { hashedKey: string } = {
      id: randomUUID(),
      orgId: k.orgId,
      userId: k.userId,
      name: k.name,
      keyPrefix: k.keyPrefix,
      hashedKey: k.hashedKey,
      lastUsedAt: null,
      createdAt: new Date().toISOString(),
      revokedAt: null,
    };
    this.apiKeys.set(rec.id, rec);
    return this.toApiKey(rec);
  }

  async getApiKey(id: string): Promise<ApiKey | null> {
    const k = this.apiKeys.get(id);
    return k ? this.toApiKey(k) : null;
  }

  async listApiKeys(orgId: string): Promise<ApiKey[]> {
    return [...this.apiKeys.values()]
      .filter((k) => k.orgId === orgId)
      .sort((a, b) => b.createdAt.localeCompare(a.createdAt))
      .map((k) => this.toApiKey(k));
  }

  async getApiKeyByHash(hashedKey: string): Promise<ApiKey | null> {
    const k = [...this.apiKeys.values()].find((x) => x.hashedKey === hashedKey);
    return k ? this.toApiKey(k) : null;
  }

  async touchApiKey(id: string): Promise<void> {
    const k = this.apiKeys.get(id);
    if (k) k.lastUsedAt = new Date().toISOString();
  }

  async revokeApiKey(id: string): Promise<boolean> {
    const k = this.apiKeys.get(id);
    if (!k) return false;
    k.revokedAt = new Date().toISOString();
    return true;
  }
}
