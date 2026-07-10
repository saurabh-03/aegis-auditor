/**
 * PostgreSQL-backed Store via Prisma. Activated when DATABASE_URL is set.
 *
 * For Phase 1 the full AuditReport is persisted as JSON on Scan.resultJson for
 * fast retrieval/history. Normalized Finding/CategoryScore rows (in the schema)
 * are reserved for Phase 3 analytics.
 */

import { PrismaClient, type Prisma } from '@prisma/client';
import type { AuditReport } from '../core/types.js';
import {
  nextRunFrom,
  type ApiKey,
  type Cadence,
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

export class PrismaStore implements Store {
  readonly kind = 'prisma' as const;
  private prisma: PrismaClient;

  constructor(client?: PrismaClient) {
    this.prisma = client ?? new PrismaClient();
  }

  async init(): Promise<void> {
    await this.prisma.$connect();
  }
  async close(): Promise<void> {
    await this.prisma.$disconnect();
  }

  async createUser(u: NewUser): Promise<User> {
    const created = await this.prisma.user.create({
      data: { email: u.email.toLowerCase(), name: u.name ?? null, passwordHash: u.passwordHash ?? null },
    });
    return this.toUser(created);
  }

  async getUserByEmail(email: string): Promise<User | null> {
    const u = await this.prisma.user.findUnique({ where: { email: email.toLowerCase() } });
    return u ? this.toUser(u) : null;
  }

  async getUserById(id: string): Promise<User | null> {
    const u = await this.prisma.user.findUnique({ where: { id } });
    return u ? this.toUser(u) : null;
  }

  async linkOAuth(acc: OAuthAccount): Promise<void> {
    await this.prisma.oAuthAccount.upsert({
      where: { provider_providerUserId: { provider: acc.provider, providerUserId: acc.providerUserId } },
      update: { userId: acc.userId },
      create: { provider: acc.provider, providerUserId: acc.providerUserId, userId: acc.userId },
    });
  }

  async getUserByOAuth(provider: string, providerUserId: string): Promise<User | null> {
    const acc = await this.prisma.oAuthAccount.findUnique({
      where: { provider_providerUserId: { provider, providerUserId } },
      include: { user: true },
    });
    return acc ? this.toUser(acc.user) : null;
  }

  async createOrganization(name: string, ownerUserId: string): Promise<Organization> {
    let slug = slugify(name);
    // Ensure unique slug.
    if (await this.prisma.organization.findUnique({ where: { slug } })) {
      slug = `${slug}-${Math.random().toString(16).slice(2, 6)}`;
    }
    const org = await this.prisma.organization.create({
      data: {
        name,
        slug,
        members: { create: { userId: ownerUserId, role: 'OWNER' } },
      },
    });
    return this.toOrg(org);
  }

  async getOrganization(orgId: string): Promise<Organization | null> {
    const o = await this.prisma.organization.findUnique({ where: { id: orgId } });
    return o ? this.toOrg(o) : null;
  }

  async listOrganizationsForUser(userId: string): Promise<Array<Organization & { role: Role }>> {
    const memberships = await this.prisma.membership.findMany({
      where: { userId },
      include: { org: true },
    });
    return memberships.map((m) => ({ ...this.toOrg(m.org), role: m.role as Role }));
  }

  async getMembership(userId: string, orgId: string): Promise<Membership | null> {
    const m = await this.prisma.membership.findUnique({ where: { userId_orgId: { userId, orgId } } });
    return m ? { id: m.id, userId: m.userId, orgId: m.orgId, role: m.role as Role } : null;
  }

  async addMember(orgId: string, userId: string, role: Role): Promise<Membership> {
    const m = await this.prisma.membership.upsert({
      where: { userId_orgId: { userId, orgId } },
      update: { role },
      create: { orgId, userId, role },
    });
    return { id: m.id, userId: m.userId, orgId: m.orgId, role: m.role as Role };
  }

  async createTeam(orgId: string, name: string): Promise<Team> {
    const t = await this.prisma.team.create({ data: { orgId, name } });
    return { id: t.id, orgId: t.orgId, name: t.name };
  }

  async listTeams(orgId: string): Promise<Team[]> {
    const teams = await this.prisma.team.findMany({ where: { orgId } });
    return teams.map((t) => ({ id: t.id, orgId: t.orgId, name: t.name }));
  }

  async createProject(orgId: string, name: string, target: string, ownershipToken: string): Promise<Project> {
    const p = await this.prisma.project.create({ data: { orgId, name, target, ownershipToken } });
    return this.toProject(p);
  }

  async getProject(projectId: string): Promise<Project | null> {
    const p = await this.prisma.project.findUnique({ where: { id: projectId } });
    return p ? this.toProject(p) : null;
  }

  async listProjects(orgId: string): Promise<Project[]> {
    const ps = await this.prisma.project.findMany({ where: { orgId } });
    return ps.map((p) => this.toProject(p));
  }

  async markProjectVerified(projectId: string): Promise<Project | null> {
    const p = await this.prisma.project.update({ where: { id: projectId }, data: { verifiedAt: new Date() } });
    return this.toProject(p);
  }

  async saveScan(rec: Omit<ScanRecord, 'id' | 'createdAt'>): Promise<ScanRecord> {
    const s = await this.prisma.scan.create({
      data: {
        projectId: rec.projectId,
        orgId: rec.orgId,
        userId: rec.userId,
        status: rec.status,
        authorized: rec.authorized,
        overall: rec.overall,
        grade: rec.grade,
        resultJson: (rec.report ?? undefined) as unknown as Prisma.InputJsonValue,
      },
    });
    return this.toScan(s, rec.target);
  }

  async updateScan(
    id: string,
    patch: Partial<Pick<ScanRecord, 'status' | 'overall' | 'grade' | 'report'>>,
  ): Promise<ScanRecord | null> {
    const data: Prisma.ScanUpdateInput = {};
    if (patch.status !== undefined) data.status = patch.status;
    if (patch.overall !== undefined) data.overall = patch.overall;
    if (patch.grade !== undefined) data.grade = patch.grade;
    if (patch.report !== undefined) data.resultJson = (patch.report ?? undefined) as unknown as Prisma.InputJsonValue;
    const s = await this.prisma.scan.update({ where: { id }, data });
    const report = (s.resultJson as unknown as AuditReport | null) ?? null;
    return this.toScan(s, report?.target ?? '', report);
  }

  async getScan(id: string): Promise<ScanRecord | null> {
    const s = await this.prisma.scan.findUnique({ where: { id } });
    if (!s) return null;
    const report = (s.resultJson as unknown as AuditReport | null) ?? null;
    return this.toScan(s, report?.target ?? '', report);
  }

  async listScans(opts: { orgId?: string; projectId?: string; limit: number; offset: number }) {
    const where: Prisma.ScanWhereInput = {};
    if (opts.orgId) where.orgId = opts.orgId;
    if (opts.projectId) where.projectId = opts.projectId;
    const [total, rows] = await this.prisma.$transaction([
      this.prisma.scan.count({ where }),
      this.prisma.scan.findMany({ where, orderBy: { createdAt: 'desc' }, take: opts.limit, skip: opts.offset }),
    ]);
    return {
      total,
      items: rows.map((s) => {
        const report = (s.resultJson as unknown as AuditReport | null) ?? null;
        return this.toScan(s, report?.target ?? '', report);
      }),
    };
  }

  async scanHistoryForTarget(target: string, orgId?: string) {
    const rows = await this.prisma.scan.findMany({
      where: { ...(orgId ? { orgId } : {}), overall: { not: null } },
      orderBy: { createdAt: 'asc' },
    });
    return rows
      .filter((s) => {
        const report = s.resultJson as unknown as AuditReport | null;
        return report?.target === target;
      })
      .map((s) => ({ id: s.id, createdAt: s.createdAt.toISOString(), score: s.overall as number }));
  }

  async previousScanForProject(projectId: string, excludeScanId: string): Promise<ScanRecord | null> {
    const s = await this.prisma.scan.findFirst({
      where: { projectId, status: 'COMPLETED', id: { not: excludeScanId } },
      orderBy: { createdAt: 'desc' },
    });
    if (!s) return null;
    const report = (s.resultJson as unknown as AuditReport | null) ?? null;
    return this.toScan(s, report?.target ?? '', report);
  }

  // ---- Schedules ----
  async createSchedule(s: NewSchedule): Promise<Schedule> {
    const created = await this.prisma.schedule.create({
      data: {
        projectId: s.projectId,
        orgId: s.orgId,
        cadence: s.cadence,
        includeActive: s.includeActive ?? false,
        webhookUrl: s.webhookUrl ?? null,
        nextRunAt: new Date(nextRunFrom(s.cadence)),
      },
    });
    return this.toSchedule(created);
  }

  async getSchedule(id: string): Promise<Schedule | null> {
    const s = await this.prisma.schedule.findUnique({ where: { id } });
    return s ? this.toSchedule(s) : null;
  }

  async listSchedules(opts: { orgId?: string; projectId?: string }): Promise<Schedule[]> {
    const where: Prisma.ScheduleWhereInput = {};
    if (opts.orgId) where.orgId = opts.orgId;
    if (opts.projectId) where.projectId = opts.projectId;
    const rows = await this.prisma.schedule.findMany({ where, orderBy: { createdAt: 'desc' } });
    return rows.map((s) => this.toSchedule(s));
  }

  async updateSchedule(
    id: string,
    patch: Partial<Pick<Schedule, 'cadence' | 'enabled' | 'includeActive' | 'webhookUrl' | 'nextRunAt' | 'lastRunAt'>>,
  ): Promise<Schedule | null> {
    const data: Prisma.ScheduleUpdateInput = {};
    if (patch.cadence !== undefined) data.cadence = patch.cadence;
    if (patch.enabled !== undefined) data.enabled = patch.enabled;
    if (patch.includeActive !== undefined) data.includeActive = patch.includeActive;
    if (patch.webhookUrl !== undefined) data.webhookUrl = patch.webhookUrl;
    if (patch.nextRunAt !== undefined) data.nextRunAt = new Date(patch.nextRunAt);
    if (patch.lastRunAt !== undefined) data.lastRunAt = patch.lastRunAt ? new Date(patch.lastRunAt) : null;
    const s = await this.prisma.schedule.update({ where: { id }, data });
    return this.toSchedule(s);
  }

  async deleteSchedule(id: string): Promise<boolean> {
    await this.prisma.schedule.delete({ where: { id } }).catch(() => null);
    return true;
  }

  async listDueSchedules(nowISO: string): Promise<Schedule[]> {
    const rows = await this.prisma.schedule.findMany({
      where: { enabled: true, nextRunAt: { lte: new Date(nowISO) } },
    });
    return rows.map((s) => this.toSchedule(s));
  }

  // ---- Notifications ----
  async createNotification(n: NewNotification): Promise<Notification> {
    const created = await this.prisma.notification.create({
      data: {
        orgId: n.orgId,
        type: n.type,
        scanId: n.scanId ?? null,
        projectId: n.projectId ?? null,
        title: n.title,
        body: n.body,
        severity: n.severity,
      },
    });
    return this.toNotification(created);
  }

  async listNotifications(orgId: string, opts: { limit: number; unreadOnly?: boolean }): Promise<Notification[]> {
    const rows = await this.prisma.notification.findMany({
      where: { orgId, ...(opts.unreadOnly ? { read: false } : {}) },
      orderBy: { createdAt: 'desc' },
      take: opts.limit,
    });
    return rows.map((n) => this.toNotification(n));
  }

  async markNotificationRead(id: string): Promise<boolean> {
    await this.prisma.notification.update({ where: { id }, data: { read: true } }).catch(() => null);
    return true;
  }

  // ---- API keys ----
  async createApiKey(k: NewApiKey): Promise<ApiKey> {
    const created = await this.prisma.apiKey.create({
      data: { orgId: k.orgId, userId: k.userId, name: k.name, hashedKey: k.hashedKey, keyPrefix: k.keyPrefix },
    });
    return this.toApiKey(created);
  }

  async getApiKey(id: string): Promise<ApiKey | null> {
    const k = await this.prisma.apiKey.findUnique({ where: { id } });
    return k ? this.toApiKey(k) : null;
  }

  async listApiKeys(orgId: string): Promise<ApiKey[]> {
    const rows = await this.prisma.apiKey.findMany({ where: { orgId }, orderBy: { createdAt: 'desc' } });
    return rows.map((k) => this.toApiKey(k));
  }

  async getApiKeyByHash(hashedKey: string): Promise<ApiKey | null> {
    const k = await this.prisma.apiKey.findUnique({ where: { hashedKey } });
    return k ? this.toApiKey(k) : null;
  }

  async touchApiKey(id: string): Promise<void> {
    await this.prisma.apiKey.update({ where: { id }, data: { lastUsedAt: new Date() } }).catch(() => null);
  }

  async revokeApiKey(id: string): Promise<boolean> {
    await this.prisma.apiKey.update({ where: { id }, data: { revokedAt: new Date() } }).catch(() => null);
    return true;
  }

  // ---- mappers ----
  private toApiKey(k: {
    id: string;
    orgId: string;
    userId: string;
    name: string;
    keyPrefix: string;
    lastUsedAt: Date | null;
    createdAt: Date;
    revokedAt: Date | null;
  }): ApiKey {
    return {
      id: k.id,
      orgId: k.orgId,
      userId: k.userId,
      name: k.name,
      keyPrefix: k.keyPrefix,
      lastUsedAt: k.lastUsedAt ? k.lastUsedAt.toISOString() : null,
      createdAt: k.createdAt.toISOString(),
      revokedAt: k.revokedAt ? k.revokedAt.toISOString() : null,
    };
  }
  private toSchedule(s: {
    id: string;
    projectId: string;
    orgId: string;
    cadence: string;
    includeActive: boolean;
    enabled: boolean;
    webhookUrl: string | null;
    nextRunAt: Date;
    lastRunAt: Date | null;
    createdAt: Date;
  }): Schedule {
    return {
      id: s.id,
      projectId: s.projectId,
      orgId: s.orgId,
      cadence: s.cadence as Cadence,
      includeActive: s.includeActive,
      enabled: s.enabled,
      webhookUrl: s.webhookUrl,
      nextRunAt: s.nextRunAt.toISOString(),
      lastRunAt: s.lastRunAt ? s.lastRunAt.toISOString() : null,
      createdAt: s.createdAt.toISOString(),
    };
  }
  private toNotification(n: {
    id: string;
    orgId: string;
    type: string;
    scanId: string | null;
    projectId: string | null;
    title: string;
    body: string;
    severity: string;
    read: boolean;
    createdAt: Date;
  }): Notification {
    return {
      id: n.id,
      orgId: n.orgId,
      type: n.type as Notification['type'],
      scanId: n.scanId,
      projectId: n.projectId,
      title: n.title,
      body: n.body,
      severity: n.severity as Notification['severity'],
      read: n.read,
      createdAt: n.createdAt.toISOString(),
    };
  }
  private toUser(u: { id: string; email: string; name: string | null; passwordHash: string | null; createdAt: Date }): User {
    return { id: u.id, email: u.email, name: u.name, passwordHash: u.passwordHash, createdAt: u.createdAt.toISOString() };
  }
  private toOrg(o: { id: string; name: string; slug: string; plan: string; createdAt: Date }): Organization {
    return { id: o.id, name: o.name, slug: o.slug, plan: o.plan as Organization['plan'], createdAt: o.createdAt.toISOString() };
  }
  private toProject(p: { id: string; orgId: string; name: string; target: string; ownershipToken: string | null; verifiedAt: Date | null; createdAt: Date }): Project {
    return {
      id: p.id,
      orgId: p.orgId,
      name: p.name,
      target: p.target,
      ownershipToken: p.ownershipToken ?? '',
      verifiedAt: p.verifiedAt ? p.verifiedAt.toISOString() : null,
      createdAt: p.createdAt.toISOString(),
    };
  }
  private toScan(
    s: { id: string; projectId: string | null; orgId: string | null; userId: string | null; status: string; authorized: boolean; overall: number | null; grade: string | null; createdAt: Date },
    target: string,
    report: AuditReport | null = null,
  ): ScanRecord {
    return {
      id: s.id,
      projectId: s.projectId,
      orgId: s.orgId,
      userId: s.userId,
      target,
      status: s.status as ScanRecord['status'],
      authorized: s.authorized,
      overall: s.overall,
      grade: s.grade,
      createdAt: s.createdAt.toISOString(),
      report,
    };
  }
}
