/**
 * Persistence abstraction. The API depends only on the `Store` interface;
 * `MemoryStore` (default) and `PrismaStore` (when DATABASE_URL is set) implement it.
 * This keeps the swap from in-memory to PostgreSQL mechanical — see docs/DATABASE.md.
 */

import type { AuditReport } from '../core/types.js';

export type Role = 'OWNER' | 'ADMIN' | 'MEMBER' | 'VIEWER';
export type Plan = 'FREE' | 'PRO' | 'ENTERPRISE';
export type ScanStatus = 'QUEUED' | 'RUNNING' | 'COMPLETED' | 'FAILED';

export interface User {
  id: string;
  email: string;
  name: string | null;
  passwordHash: string | null;
  createdAt: string;
}

export interface OAuthAccount {
  provider: 'google' | 'github';
  providerUserId: string;
  userId: string;
}

export interface Organization {
  id: string;
  name: string;
  slug: string;
  plan: Plan;
  createdAt: string;
}

export interface Membership {
  id: string;
  userId: string;
  orgId: string;
  role: Role;
}

export interface Team {
  id: string;
  orgId: string;
  name: string;
}

export interface Project {
  id: string;
  orgId: string;
  name: string;
  target: string;
  /** Token the owner must publish (DNS TXT or /.well-known/aegis-verify) to prove control. */
  ownershipToken: string;
  verifiedAt: string | null;
  createdAt: string;
}

export interface ScanRecord {
  id: string;
  projectId: string | null;
  orgId: string | null;
  userId: string | null;
  target: string;
  status: ScanStatus;
  authorized: boolean;
  overall: number | null;
  grade: string | null;
  createdAt: string;
  /** Full report payload (JSON). */
  report: AuditReport | null;
}

export interface NewUser {
  email: string;
  name?: string | null;
  passwordHash?: string | null;
}

export interface ApiKey {
  id: string;
  orgId: string;
  userId: string;
  name: string;
  keyPrefix: string;
  lastUsedAt: string | null;
  createdAt: string;
  revokedAt: string | null;
}

export interface NewApiKey {
  orgId: string;
  userId: string;
  name: string;
  hashedKey: string;
  keyPrefix: string;
}

export type WebhookEvent = 'regression' | 'scan_complete';

/** Public webhook shape (secret never included). */
export interface Webhook {
  id: string;
  orgId: string;
  url: string;
  events: WebhookEvent[];
  active: boolean;
  createdAt: string;
}

export interface NewWebhook {
  orgId: string;
  url: string;
  events: WebhookEvent[];
  secret: string;
}

/** Internal shape including the signing secret (for delivery only). */
export interface WebhookWithSecret extends Webhook {
  secret: string;
}

export type Cadence = 'daily' | 'weekly' | 'monthly';

export interface Schedule {
  id: string;
  projectId: string;
  orgId: string;
  cadence: Cadence;
  includeActive: boolean;
  enabled: boolean;
  /** Optional outbound webhook fired on regression. */
  webhookUrl: string | null;
  nextRunAt: string;
  lastRunAt: string | null;
  createdAt: string;
}

export interface NewSchedule {
  projectId: string;
  orgId: string;
  cadence: Cadence;
  includeActive?: boolean;
  webhookUrl?: string | null;
}

export type NotificationType = 'regression' | 'scan_complete';

export interface Notification {
  id: string;
  orgId: string;
  type: NotificationType;
  scanId: string | null;
  projectId: string | null;
  title: string;
  body: string;
  severity: 'info' | 'warning' | 'critical';
  read: boolean;
  createdAt: string;
}

export interface NewNotification {
  orgId: string;
  type: NotificationType;
  scanId?: string | null;
  projectId?: string | null;
  title: string;
  body: string;
  severity: 'info' | 'warning' | 'critical';
}

/** Compute the next run time for a cadence, from a base instant. */
export function nextRunFrom(cadence: Cadence, from = new Date()): string {
  const d = new Date(from);
  if (cadence === 'daily') d.setUTCDate(d.getUTCDate() + 1);
  else if (cadence === 'weekly') d.setUTCDate(d.getUTCDate() + 7);
  else d.setUTCMonth(d.getUTCMonth() + 1);
  return d.toISOString();
}

/** The contract every backing store implements. */
export interface Store {
  readonly kind: 'memory' | 'prisma';
  init(): Promise<void>;
  close(): Promise<void>;

  // Users & OAuth
  createUser(u: NewUser): Promise<User>;
  getUserByEmail(email: string): Promise<User | null>;
  getUserById(id: string): Promise<User | null>;
  linkOAuth(acc: OAuthAccount): Promise<void>;
  getUserByOAuth(provider: string, providerUserId: string): Promise<User | null>;

  // Organizations & membership
  createOrganization(name: string, ownerUserId: string): Promise<Organization>;
  getOrganization(orgId: string): Promise<Organization | null>;
  listOrganizationsForUser(userId: string): Promise<Array<Organization & { role: Role }>>;
  getMembership(userId: string, orgId: string): Promise<Membership | null>;
  addMember(orgId: string, userId: string, role: Role): Promise<Membership>;

  // Teams
  createTeam(orgId: string, name: string): Promise<Team>;
  listTeams(orgId: string): Promise<Team[]>;

  // Projects
  createProject(orgId: string, name: string, target: string, ownershipToken: string): Promise<Project>;
  getProject(projectId: string): Promise<Project | null>;
  listProjects(orgId: string): Promise<Project[]>;
  markProjectVerified(projectId: string): Promise<Project | null>;

  // Scans
  saveScan(rec: Omit<ScanRecord, 'id' | 'createdAt'>): Promise<ScanRecord>;
  /** Patch a scan record (status transitions, result). Returns the updated record. */
  updateScan(id: string, patch: Partial<Pick<ScanRecord, 'status' | 'overall' | 'grade' | 'report'>>): Promise<ScanRecord | null>;
  getScan(id: string): Promise<ScanRecord | null>;
  listScans(opts: { orgId?: string; projectId?: string; limit: number; offset: number }): Promise<{ total: number; items: ScanRecord[] }>;
  scanHistoryForTarget(target: string, orgId?: string): Promise<Array<{ id: string; createdAt: string; score: number }>>;
  /** Most recent COMPLETED scan for a project, excluding `excludeScanId`. For regression baselines. */
  previousScanForProject(projectId: string, excludeScanId: string): Promise<ScanRecord | null>;

  // Schedules
  createSchedule(s: NewSchedule): Promise<Schedule>;
  getSchedule(id: string): Promise<Schedule | null>;
  listSchedules(opts: { orgId?: string; projectId?: string }): Promise<Schedule[]>;
  updateSchedule(id: string, patch: Partial<Pick<Schedule, 'cadence' | 'enabled' | 'includeActive' | 'webhookUrl' | 'nextRunAt' | 'lastRunAt'>>): Promise<Schedule | null>;
  deleteSchedule(id: string): Promise<boolean>;
  /** Enabled schedules whose nextRunAt is at or before `nowISO`. */
  listDueSchedules(nowISO: string): Promise<Schedule[]>;

  // Notifications
  createNotification(n: NewNotification): Promise<Notification>;
  listNotifications(orgId: string, opts: { limit: number; unreadOnly?: boolean }): Promise<Notification[]>;
  markNotificationRead(id: string): Promise<boolean>;

  // API keys (only a hash is stored; plaintext is returned to the caller once)
  createApiKey(k: NewApiKey): Promise<ApiKey>;
  getApiKey(id: string): Promise<ApiKey | null>;
  listApiKeys(orgId: string): Promise<ApiKey[]>;
  /** Resolve an incoming key by its hash. Returns null if unknown. */
  getApiKeyByHash(hashedKey: string): Promise<ApiKey | null>;
  touchApiKey(id: string): Promise<void>;
  revokeApiKey(id: string): Promise<boolean>;

  // Webhooks (org-level, HMAC-signed delivery)
  createWebhook(w: NewWebhook): Promise<Webhook>;
  getWebhook(id: string): Promise<Webhook | null>;
  listWebhooks(orgId: string): Promise<Webhook[]>;
  /** Active webhooks (with secret) for an org subscribed to `event`. Internal use. */
  webhooksForEvent(orgId: string, event: WebhookEvent): Promise<WebhookWithSecret[]>;
  deleteWebhook(id: string): Promise<boolean>;
}
