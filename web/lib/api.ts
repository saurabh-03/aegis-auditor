/** Thin API client. Same-origin: Next rewrites /api/* to the Aegis backend. */

'use client';

import type {
  AdvisorOutput,
  ApiKey,
  AppNotification,
  AuditReport,
  Cadence,
  Organization,
  Project,
  RegressionAssessment,
  ReportDiff,
  Schedule,
  User,
  Webhook,
  WebhookEvent,
} from './types';

const TOKEN_KEY = 'aegis_token';

export function getToken(): string | null {
  if (typeof window === 'undefined') return null;
  return localStorage.getItem(TOKEN_KEY);
}
export function setToken(token: string | null): void {
  if (typeof window === 'undefined') return;
  if (token) localStorage.setItem(TOKEN_KEY, token);
  else localStorage.removeItem(TOKEN_KEY);
}

async function req<T>(path: string, opts: RequestInit = {}, auth = true): Promise<T> {
  const headers: Record<string, string> = { 'content-type': 'application/json', ...(opts.headers as Record<string, string>) };
  const token = getToken();
  if (auth && token) headers.authorization = `Bearer ${token}`;
  const res = await fetch(path, { ...opts, headers });
  const text = await res.text();

  let data: { error?: string; message?: string } & Record<string, unknown> = {};
  if (text) {
    try {
      data = JSON.parse(text);
    } catch {
      // Body isn't JSON — almost always a gateway/HTML error page. On Render's
      // free tier the API sleeps after inactivity, so the first proxied call
      // gets a holding/timeout page (HTML) instead of JSON. Surface a readable
      // error instead of a raw "Unexpected token '<'" SyntaxError.
      const waking = res.status === 502 || res.status === 503 || res.status === 504 || res.status === 408;
      throw new ApiError(
        waking ? 'service_waking' : 'bad_response',
        waking
          ? 'The API is starting up (free-tier services sleep after inactivity; this can take ~30s). Please try again in a moment.'
          : `The server returned an unexpected response (HTTP ${res.status}). Please retry.`,
        res.status,
      );
    }
  }
  if (!res.ok) throw new ApiError(data.error ?? 'request_failed', data.message ?? res.statusText, res.status);
  return data as T;
}

export class ApiError extends Error {
  constructor(public code: string, message: string, public status: number) {
    super(message);
  }
}

export const api = {
  // auth
  register: (email: string, password: string, name: string) =>
    req<{ user: User; accessToken: string }>('/api/auth/register', { method: 'POST', body: JSON.stringify({ email, password, name }) }, false),
  login: (email: string, password: string) =>
    req<{ user: User; accessToken: string }>('/api/auth/login', { method: 'POST', body: JSON.stringify({ email, password }) }, false),
  me: () => req<{ user: User; organizations: Organization[] }>('/api/auth/me'),

  // quick public passive scan (no auth)
  quickScan: (target: string) => req<{ id: string; report: AuditReport }>('/api/scan', { method: 'POST', body: JSON.stringify({ target }) }, false),

  // orgs & projects
  orgs: () => req<{ organizations: Organization[] }>('/api/orgs'),
  projects: (orgId: string) => req<{ projects: Project[] }>(`/api/orgs/${orgId}/projects`),
  createProject: (orgId: string, name: string, target: string) =>
    req<{ project: Project; verification: { token: string; instructions: Record<string, string> } }>(`/api/orgs/${orgId}/projects`, { method: 'POST', body: JSON.stringify({ name, target }) }),
  verifyProject: (projectId: string) => req<{ project: Project }>(`/api/projects/${projectId}/verify`, { method: 'POST' }),
  projectHistory: (projectId: string) => req<{ history: { id: string; createdAt: string; score: number }[] }>(`/api/projects/${projectId}/history`),

  // async scans
  enqueueScan: (body: {
    target?: string;
    projectId?: string;
    includeActive?: boolean;
    authHeaders?: Record<string, string>;
    authCookie?: string;
    excludeUrlPatterns?: string[];
    formLogin?: { loginUrl: string; username: string; password: string };
  }) =>
    req<{ scanId: string; status: string; stream: string }>('/api/scans', { method: 'POST', body: JSON.stringify(body) }),
  scanStatus: (id: string) => req<{ status: string; report: AuditReport | null; overall: number | null; grade: string | null }>(`/api/scans/${id}`),

  // monitoring: schedules, diffs, notifications
  schedules: (projectId: string) => req<{ schedules: Schedule[] }>(`/api/projects/${projectId}/schedules`),
  createSchedule: (projectId: string, body: { cadence: Cadence; includeActive?: boolean; webhookUrl?: string | null }) =>
    req<Schedule>(`/api/projects/${projectId}/schedules`, { method: 'POST', body: JSON.stringify(body) }),
  updateSchedule: (id: string, body: { cadence?: Cadence; enabled?: boolean; includeActive?: boolean; webhookUrl?: string | null }) =>
    req<Schedule>(`/api/schedules/${id}`, { method: 'PATCH', body: JSON.stringify(body) }),
  deleteSchedule: (id: string) => req<unknown>(`/api/schedules/${id}`, { method: 'DELETE' }),
  scanDiff: (id: string) =>
    req<{ diff: ReportDiff | null; regression: RegressionAssessment; baselineScanId: string | null }>(`/api/scans/${id}/diff`),
  notifications: (orgId: string, unreadOnly = false) =>
    req<{ notifications: AppNotification[] }>(`/api/orgs/${orgId}/notifications${unreadOnly ? '?unread=1' : ''}`),
  markNotificationRead: (id: string) => req<{ ok: boolean }>(`/api/notifications/${id}/read`, { method: 'POST' }),

  // API keys
  apiKeys: (orgId: string) => req<{ keys: ApiKey[] }>(`/api/orgs/${orgId}/keys`),
  createApiKey: (orgId: string, name: string) => req<{ apiKey: ApiKey; key: string }>(`/api/orgs/${orgId}/keys`, { method: 'POST', body: JSON.stringify({ name }) }),
  revokeApiKey: (id: string) => req<unknown>(`/api/keys/${id}`, { method: 'DELETE' }),

  // Webhooks
  webhooks: (orgId: string) => req<{ webhooks: Webhook[] }>(`/api/orgs/${orgId}/webhooks`),
  createWebhook: (orgId: string, url: string, events: WebhookEvent[]) =>
    req<{ webhook: Webhook; secret: string }>(`/api/orgs/${orgId}/webhooks`, { method: 'POST', body: JSON.stringify({ url, events }) }),
  deleteWebhook: (id: string) => req<unknown>(`/api/webhooks/${id}`, { method: 'DELETE' }),
  testWebhook: (id: string) => req<{ ok: boolean; delivered: string }>(`/api/webhooks/${id}/test`, { method: 'POST' }),

  // reports & advisor
  report: (id: string) => req<AuditReport>(`/api/reports/${id}`, {}, false),
  advisor: (id: string) => req<AdvisorOutput>(`/api/reports/${id}/advisor`, {}, false),
  tickets: (id: string, format: 'github' | 'jira') =>
    req<{ format: string; tickets: { title: string; body: string; labels: string[]; severity: string }[] }>(`/api/reports/${id}/tickets?format=${format}`, {}, false),
};

/**
 * Build a WebSocket URL for live scan progress. WebSocket upgrades don't proxy
 * reliably through Next rewrites, so connect directly to the backend origin
 * (NEXT_PUBLIC_WS_ORIGIN, default ws://localhost:4000). The backend allows this
 * cross-origin and authenticates via the ?token query param.
 */
export function scanStreamUrl(scanId: string): string {
  const token = getToken();
  const origin = process.env.NEXT_PUBLIC_WS_ORIGIN ?? 'ws://localhost:4000';
  return `${origin}/api/scans/${scanId}/stream${token ? `?token=${token}` : ''}`;
}
