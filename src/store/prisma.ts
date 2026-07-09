/**
 * PostgreSQL-backed Store via Prisma. Activated when DATABASE_URL is set.
 *
 * For Phase 1 the full AuditReport is persisted as JSON on Scan.resultJson for
 * fast retrieval/history. Normalized Finding/CategoryScore rows (in the schema)
 * are reserved for Phase 3 analytics.
 */

import { PrismaClient, type Prisma } from '@prisma/client';
import type { AuditReport } from '../core/types.js';
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

  // ---- mappers ----
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
