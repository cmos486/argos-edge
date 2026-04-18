// Thin wrapper over fetch for the argos panel API.
//
// Backend issues an httponly session cookie on POST /api/auth/login; the
// browser carries it on every subsequent same-origin request. We never
// touch the cookie from JS. A 401 from any request means the session
// lapsed, so we redirect to /login unless we are already there.

const BASE = import.meta.env.VITE_API_BASE ?? '/api';

export class ApiError extends Error {
  constructor(
    public status: number,
    message: string,
  ) {
    super(message);
    this.name = 'ApiError';
  }
}

export interface User {
  username: string;
}

export interface HealthStatus {
  ok: boolean;
  detail: string;
}

export interface CaddyStatus {
  ok: boolean;
  address: string;
  error?: string;
  has_http: boolean;
}

export type TLSMode = 'auto' | 'none';
export type Protocol = 'http' | 'https';
export type Algorithm = 'round_robin' | 'least_conn' | 'ip_hash' | 'random';
export type HealthCheckMethod = 'GET' | 'HEAD' | 'POST';

export interface TargetGroupSummary {
  id: number;
  name: string;
  protocol: Protocol;
  algorithm: Algorithm;
  targets_count: number;
  targets_enabled_count: number;
}

export interface Target {
  id: number;
  target_group_id: number;
  host: string;
  port: number;
  weight: number;
  enabled: boolean;
  created_at: string;
  updated_at: string;
}

export interface TargetInput {
  host: string;
  port: number;
  weight?: number;
  enabled?: boolean;
}

export interface TargetGroup {
  id: number;
  name: string;
  protocol: Protocol;
  verify_tls: boolean;
  algorithm: Algorithm;
  health_check_enabled: boolean;
  health_check_path: string;
  health_check_method: HealthCheckMethod;
  health_check_expect_status: string;
  health_check_interval_seconds: number;
  health_check_timeout_seconds: number;
  health_check_fails_to_unhealthy: number;
  health_check_passes_to_healthy: number;
  created_at: string;
  updated_at: string;
  targets?: Target[];
  targets_count: number;
  targets_enabled_count: number;
}

export interface TargetGroupInput {
  name: string;
  protocol: Protocol;
  verify_tls?: boolean;
  algorithm: Algorithm;
  health_check_enabled?: boolean;
  health_check_path?: string;
  health_check_method?: HealthCheckMethod;
  health_check_expect_status?: string;
  health_check_interval_seconds?: number;
  health_check_timeout_seconds?: number;
  health_check_fails_to_unhealthy?: number;
  health_check_passes_to_healthy?: number;
  targets?: TargetInput[];
}

export interface Host {
  id: number;
  domain: string;
  target_group_id: number;
  target_group?: TargetGroupSummary;
  tls_mode: TLSMode;
  tls_email: string;
  enabled: boolean;
  rules_count: number;
  created_at: string;
  updated_at: string;
}

export type ActionType = 'forward' | 'redirect' | 'fixed_response' | 'block' | 'rewrite';
export type MatcherType =
  | 'path'
  | 'path_exact'
  | 'method'
  | 'header'
  | 'query'
  | 'remote_ip'
  | 'host_header';
export type HeaderMode = 'exact' | 'regex';

export interface ActionEnv {
  type: ActionType;
  config: unknown;
}

export interface MatcherEnv {
  type: MatcherType;
  config: unknown;
}

export interface Rule {
  id: number;
  host_id: number;
  priority: number;
  name: string;
  enabled: boolean;
  action: ActionEnv;
  matchers: MatcherEnv[];
  created_at: string;
  updated_at: string;
}

export interface RuleInput {
  priority?: number;
  name?: string;
  enabled?: boolean;
  action: ActionEnv;
  matchers: MatcherEnv[];
}

export interface HostInput {
  domain: string;
  target_group_id?: number;
  target_group?: TargetGroupInput;
  tls_mode: TLSMode;
  tls_email: string;
  enabled?: boolean;
}

export interface Cert {
  domain: string;
  issuer: string;
  not_after: string;
  last_checked_at: string;
}

function onUnauthorized(): void {
  if (typeof window === 'undefined') return;
  if (window.location.pathname !== '/login') {
    window.location.assign('/login');
  }
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`${BASE}${path}`, {
    credentials: 'same-origin',
    headers: {
      Accept: 'application/json',
      ...(init?.body ? { 'Content-Type': 'application/json' } : {}),
      ...(init?.headers ?? {}),
    },
    ...init,
  });

  if (res.status === 401) {
    onUnauthorized();
    throw new ApiError(401, 'unauthorized');
  }

  if (res.status === 204) {
    return undefined as T;
  }

  const ct = res.headers.get('content-type') ?? '';
  const isJSON = ct.includes('application/json');
  const body = isJSON ? await res.json().catch(() => null) : await res.text();

  if (!res.ok) {
    const msg =
      isJSON && body && typeof body === 'object' && 'error' in body
        ? String((body as { error: unknown }).error)
        : `request failed: ${res.status}`;
    throw new ApiError(res.status, msg);
  }

  return body as T;
}

export const api = {
  login(username: string, password: string): Promise<User> {
    return request<User>('/auth/login', {
      method: 'POST',
      body: JSON.stringify({ username, password }),
    });
  },

  logout(): Promise<void> {
    return request<void>('/auth/logout', { method: 'POST' });
  },

  me(): Promise<User> {
    return request<User>('/auth/me');
  },

  async health(): Promise<HealthStatus> {
    // /api/healthz returns text/plain "ok". Any non-200 surfaces via
    // ApiError in request(); we translate the body into a simple shape.
    const res = await fetch(`${BASE}/healthz`, {
      credentials: 'same-origin',
      headers: { Accept: 'text/plain' },
    });
    if (res.status === 401) {
      onUnauthorized();
      throw new ApiError(401, 'unauthorized');
    }
    const text = await res.text();
    return { ok: res.ok, detail: text.trim() || `status ${res.status}` };
  },

  caddyStatus(): Promise<CaddyStatus> {
    return request<CaddyStatus>('/caddy/status');
  },

  listHosts(): Promise<Host[]> {
    return request<Host[]>('/hosts');
  },

  createHost(input: HostInput): Promise<Host> {
    return request<Host>('/hosts', {
      method: 'POST',
      body: JSON.stringify(input),
    });
  },

  updateHost(id: number, input: HostInput & { enabled: boolean }): Promise<Host> {
    return request<Host>(`/hosts/${id}`, {
      method: 'PUT',
      body: JSON.stringify(input),
    });
  },

  deleteHost(id: number): Promise<void> {
    return request<void>(`/hosts/${id}`, { method: 'DELETE' });
  },

  toggleHost(id: number): Promise<Host> {
    return request<Host>(`/hosts/${id}/toggle`, { method: 'POST' });
  },

  listCerts(): Promise<Cert[]> {
    return request<Cert[]>('/certs');
  },

  listTargetGroups(): Promise<TargetGroup[]> {
    return request<TargetGroup[]>('/target-groups');
  },

  getTargetGroup(id: number): Promise<TargetGroup> {
    return request<TargetGroup>(`/target-groups/${id}`);
  },

  createTargetGroup(input: TargetGroupInput): Promise<TargetGroup> {
    return request<TargetGroup>('/target-groups', {
      method: 'POST',
      body: JSON.stringify(input),
    });
  },

  updateTargetGroup(id: number, input: TargetGroupInput): Promise<TargetGroup> {
    return request<TargetGroup>(`/target-groups/${id}`, {
      method: 'PUT',
      body: JSON.stringify(input),
    });
  },

  deleteTargetGroup(id: number): Promise<void> {
    return request<void>(`/target-groups/${id}`, { method: 'DELETE' });
  },

  addTarget(tgId: number, input: TargetInput): Promise<Target> {
    return request<Target>(`/target-groups/${tgId}/targets`, {
      method: 'POST',
      body: JSON.stringify(input),
    });
  },

  updateTarget(tgId: number, targetId: number, input: TargetInput): Promise<Target> {
    return request<Target>(`/target-groups/${tgId}/targets/${targetId}`, {
      method: 'PUT',
      body: JSON.stringify(input),
    });
  },

  deleteTarget(tgId: number, targetId: number): Promise<void> {
    return request<void>(`/target-groups/${tgId}/targets/${targetId}`, {
      method: 'DELETE',
    });
  },

  toggleTarget(tgId: number, targetId: number): Promise<Target> {
    return request<Target>(`/target-groups/${tgId}/targets/${targetId}/toggle`, {
      method: 'POST',
    });
  },

  listRules(hostId: number): Promise<Rule[]> {
    return request<Rule[]>(`/hosts/${hostId}/rules`);
  },
  createRule(hostId: number, input: RuleInput): Promise<Rule> {
    return request<Rule>(`/hosts/${hostId}/rules`, {
      method: 'POST',
      body: JSON.stringify(input),
    });
  },
  updateRule(hostId: number, ruleId: number, input: RuleInput & { enabled: boolean }): Promise<Rule> {
    return request<Rule>(`/hosts/${hostId}/rules/${ruleId}`, {
      method: 'PUT',
      body: JSON.stringify(input),
    });
  },
  deleteRule(hostId: number, ruleId: number): Promise<void> {
    return request<void>(`/hosts/${hostId}/rules/${ruleId}`, { method: 'DELETE' });
  },
  toggleRule(hostId: number, ruleId: number): Promise<Rule> {
    return request<Rule>(`/hosts/${hostId}/rules/${ruleId}/toggle`, { method: 'POST' });
  },
  reorderRules(hostId: number, ruleIds: number[]): Promise<Rule[]> {
    return request<Rule[]>(`/hosts/${hostId}/rules/reorder`, {
      method: 'POST',
      body: JSON.stringify({ rule_ids: ruleIds }),
    });
  },

  listLogs(query: Record<string, string | number | undefined>): Promise<LogListResponse> {
    const qs = new URLSearchParams();
    for (const [k, v] of Object.entries(query)) {
      if (v !== undefined && v !== '') qs.set(k, String(v));
    }
    return request<LogListResponse>(`/logs?${qs.toString()}`);
  },
  getLog(id: number): Promise<LogEntry> {
    return request<LogEntry>(`/logs/${id}`);
  },
  logStats(query: Record<string, string | number | undefined>): Promise<LogStats> {
    const qs = new URLSearchParams();
    for (const [k, v] of Object.entries(query)) {
      if (v !== undefined && v !== '') qs.set(k, String(v));
    }
    return request<LogStats>(`/logs/stats?${qs.toString()}`);
  },
  logPresets(): Promise<LogPreset[]> {
    return request<LogPreset[]>(`/logs/presets`);
  },
  purgeLogs(): Promise<{ removed: number }> {
    return request<{ removed: number }>(`/logs/purge`, { method: 'POST' });
  },

  listSettings(prefix?: string): Promise<Setting[]> {
    const qs = prefix ? `?prefix=${encodeURIComponent(prefix)}` : '';
    return request<Setting[]>(`/settings${qs}`);
  },
  updateSetting(key: string, value: string): Promise<Setting> {
    return request<Setting>(`/settings/${encodeURIComponent(key)}`, {
      method: 'PUT',
      body: JSON.stringify({ value }),
    });
  },

  getHostSecurity(hostId: number): Promise<HostSecurityBundle> {
    return request<HostSecurityBundle>(`/hosts/${hostId}/security`);
  },
  updateHostSecurity(
    hostId: number,
    body: Partial<HostSecurity>,
  ): Promise<HostSecurity> {
    return request<HostSecurity>(`/hosts/${hostId}/security`, {
      method: 'PUT',
      body: JSON.stringify(body),
    });
  },
  createExclusion(
    hostId: number,
    body: { crs_rule_id: number; path_pattern?: string; reason?: string },
  ): Promise<WAFExclusion> {
    return request<WAFExclusion>(`/hosts/${hostId}/security/exclusions`, {
      method: 'POST',
      body: JSON.stringify(body),
    });
  },
  deleteExclusion(hostId: number, id: number): Promise<void> {
    return request<void>(`/hosts/${hostId}/security/exclusions/${id}`, {
      method: 'DELETE',
    });
  },
  toggleExclusion(hostId: number, id: number): Promise<WAFExclusion> {
    return request<WAFExclusion>(
      `/hosts/${hostId}/security/exclusions/${id}/toggle`,
      { method: 'POST' },
    );
  },
  createCustomRule(
    hostId: number,
    body: { name: string; secrule: string; enabled?: boolean },
  ): Promise<WAFCustomRule> {
    return request<WAFCustomRule>(`/hosts/${hostId}/security/custom-rules`, {
      method: 'POST',
      body: JSON.stringify(body),
    });
  },
  deleteCustomRule(hostId: number, id: number): Promise<void> {
    return request<void>(`/hosts/${hostId}/security/custom-rules/${id}`, {
      method: 'DELETE',
    });
  },
  toggleCustomRule(hostId: number, id: number): Promise<WAFCustomRule> {
    return request<WAFCustomRule>(
      `/hosts/${hostId}/security/custom-rules/${id}/toggle`,
      { method: 'POST' },
    );
  },
  securityOverview(): Promise<SecurityOverview> {
    return request<SecurityOverview>('/security/overview');
  },
  crsRules(): Promise<CRSRule[]> {
    return request<CRSRule[]>('/crs/rules');
  },

  // --- Phase 5: Notifications ---
  listNotifChannels(): Promise<NotifChannel[]> {
    return request<NotifChannel[]>('/notifications/channels');
  },
  getNotifChannel(id: number): Promise<NotifChannel> {
    return request<NotifChannel>(`/notifications/channels/${id}`);
  },
  createNotifChannel(input: NotifChannelInput): Promise<NotifChannel> {
    return request<NotifChannel>('/notifications/channels', {
      method: 'POST',
      body: JSON.stringify(input),
    });
  },
  updateNotifChannel(id: number, input: NotifChannelInput): Promise<NotifChannel> {
    return request<NotifChannel>(`/notifications/channels/${id}`, {
      method: 'PUT',
      body: JSON.stringify(input),
    });
  },
  deleteNotifChannel(id: number): Promise<void> {
    return request<void>(`/notifications/channels/${id}`, { method: 'DELETE' });
  },
  toggleNotifChannel(id: number): Promise<NotifChannel> {
    return request<NotifChannel>(`/notifications/channels/${id}/toggle`, { method: 'POST' });
  },
  testNotifChannel(id: number): Promise<NotifTestResult> {
    return request<NotifTestResult>(`/notifications/channels/${id}/test`, { method: 'POST' });
  },

  listNotifRules(): Promise<NotifRule[]> {
    return request<NotifRule[]>('/notifications/rules');
  },
  createNotifRule(input: NotifRuleInput): Promise<NotifRule> {
    return request<NotifRule>('/notifications/rules', {
      method: 'POST',
      body: JSON.stringify(input),
    });
  },
  updateNotifRule(id: number, input: NotifRuleInput): Promise<NotifRule> {
    return request<NotifRule>(`/notifications/rules/${id}`, {
      method: 'PUT',
      body: JSON.stringify(input),
    });
  },
  deleteNotifRule(id: number): Promise<void> {
    return request<void>(`/notifications/rules/${id}`, { method: 'DELETE' });
  },
  toggleNotifRule(id: number): Promise<NotifRule> {
    return request<NotifRule>(`/notifications/rules/${id}/toggle`, { method: 'POST' });
  },

  listNotifDeliveries(params?: Record<string, string>): Promise<{ deliveries: NotifDelivery[]; stats?: Record<string, number> }> {
    const qs = params && Object.keys(params).length > 0
      ? '?' + new URLSearchParams(params).toString()
      : '';
    return request<{ deliveries: NotifDelivery[]; stats?: Record<string, number> }>(
      `/notifications/deliveries${qs}`,
    );
  },
  getNotifDelivery(id: number): Promise<NotifDelivery> {
    return request<NotifDelivery>(`/notifications/deliveries/${id}`);
  },
  retryNotifDelivery(id: number): Promise<NotifDelivery> {
    return request<NotifDelivery>(`/notifications/deliveries/${id}/retry`, { method: 'POST' });
  },
  notifEventTypes(): Promise<NotifEventCatalog[]> {
    return request<NotifEventCatalog[]>('/notifications/event-types');
  },
  recentAlerts(limit = 5): Promise<NotifDelivery[]> {
    return request<NotifDelivery[]>(`/notifications/recent-alerts?limit=${limit}`);
  },

  // Web Push
  vapidPublicKey(): Promise<{ public_key: string }> {
    return request<{ public_key: string }>('/push/vapid-public-key');
  },
  subscribePush(input: PushSubscribeInput): Promise<PushSubscription> {
    return request<PushSubscription>('/push/subscribe', {
      method: 'POST',
      body: JSON.stringify(input),
    });
  },
  unsubscribePush(endpoint: string): Promise<void> {
    return request<void>('/push/subscribe', {
      method: 'DELETE',
      body: JSON.stringify({ endpoint }),
    });
  },
  listPushSubscriptions(): Promise<PushSubscription[]> {
    return request<PushSubscription[]>('/push/subscriptions');
  },
};

export type NotifChannelType = 'webhook' | 'email' | 'telegram' | 'browser_push';
export type NotifDeliveryStatus = 'pending' | 'sent' | 'failed' | 'throttled' | 'rate_limited';
export type NotifSeverity = 'info' | 'warning' | 'error' | 'critical';
export const NOTIF_UNCHANGED = '__UNCHANGED__';

export interface NotifChannel {
  id: number;
  name: string;
  type: NotifChannelType;
  enabled: boolean;
  config: Record<string, unknown>;
  template: string;
  rate_limit_per_minute: number;
  created_at: string;
  updated_at: string;
}

export interface NotifChannelInput {
  name: string;
  type: NotifChannelType;
  enabled: boolean;
  config: Record<string, unknown>;
  template: string;
  rate_limit_per_minute: number;
}

export interface NotifRule {
  id: number;
  name: string;
  channel_id: number;
  event_type: string;
  filter_host_ids?: number[] | null;
  filter_severities?: NotifSeverity[] | null;
  enabled: boolean;
  throttle_window_seconds: number;
  created_at: string;
  updated_at: string;
}

export interface NotifRuleInput {
  name: string;
  channel_id: number;
  event_type: string;
  filter_host_ids: number[];
  filter_severities: NotifSeverity[];
  enabled: boolean;
  throttle_window_seconds: number;
}

export interface NotifDelivery {
  id: number;
  rule_id?: number | null;
  channel_id?: number | null;
  event_type: string;
  event_payload: string;
  rendered_payload: string;
  status: NotifDeliveryStatus;
  error_message?: string;
  attempts: number;
  created_at: string;
  sent_at?: string | null;
}

export interface NotifEventCatalog {
  type: string;
  severity: NotifSeverity;
  description: string;
  trigger_condition: string;
  sample_event: Record<string, unknown>;
}

export interface NotifTestResult {
  success: boolean;
  sent_payload: string;
  error_message?: string;
}

export interface PushSubscribeInput {
  endpoint: string;
  p256dh_key: string;
  auth_key: string;
  user_agent: string;
}

export interface PushSubscription {
  id: number;
  user_id: number;
  endpoint: string;
  p256dh_key: string;
  auth_key: string;
  user_agent: string;
  created_at: string;
}

export type LogSource = 'caddy_access' | 'caddy_error' | 'audit' | 'waf_audit';

export interface LogEntry {
  id: number;
  timestamp: string;
  source: LogSource;
  level?: string;
  host_id?: number;
  host_domain?: string;
  rule_id?: number;
  remote_ip?: string;
  method?: string;
  path?: string;
  status?: number;
  duration_ms?: number;
  size_bytes?: number;
  user_agent?: string;
  upstream?: string;
  message?: string;
  raw?: string;
  waf_rule_id?: number;
  waf_rule_message?: string;
  waf_severity?: string;
  waf_anomaly_score?: number;
}

export interface LogListResponse {
  entries: LogEntry[];
  total_count: number;
  has_more: boolean;
}

export interface LogStats {
  total: number;
  by_status_class: Record<string, number>;
  by_source: Record<string, number>;
  avg_duration_ms: number;
  p95_duration_ms: number;
  top_hosts: { label: string; count: number }[];
  top_paths: { label: string; count: number }[];
}

export interface LogPreset {
  id: string;
  name: string;
  description: string;
  filters: Record<string, unknown>;
}

export interface Setting {
  key: string;
  value: string;
  updated_at: string;
}

export type WAFMode = 'detect' | 'block';
export type RateLimitKey = 'ip' | 'header' | 'global';

export interface HostSecurity {
  host_id: number;
  waf_enabled: boolean;
  waf_mode: WAFMode;
  waf_paranoia: number;
  waf_block_status: number;
  waf_block_body: string;
  rate_limit_enabled: boolean;
  rate_limit_requests: number;
  rate_limit_window_seconds: number;
  rate_limit_key: RateLimitKey;
  rate_limit_header_name: string;
  rate_limit_status: number;
  updated_at: string;
}

export interface WAFExclusion {
  id: number;
  host_id: number;
  crs_rule_id: number;
  path_pattern: string;
  reason: string;
  enabled: boolean;
  created_at: string;
  updated_at: string;
}

export interface WAFCustomRule {
  id: number;
  host_id: number;
  name: string;
  secrule: string;
  enabled: boolean;
  created_at: string;
  updated_at: string;
}

export interface HostSecurityBundle extends HostSecurity {
  exclusions: WAFExclusion[];
  custom_rules: WAFCustomRule[];
}

export interface CRSRule {
  id: number;
  paranoia: number;
  category: string;
  description: string;
  file: string;
}

export interface SecurityOverviewRow {
  host_id: number;
  domain: string;
  waf_enabled: boolean;
  waf_mode: WAFMode;
  waf_paranoia: number;
  rate_limit_enabled: boolean;
  blocked_24h: number;
  last_triggered_at?: string;
}

export interface SecurityOverview {
  hosts: SecurityOverviewRow[];
  waf_detect_count: number;
  waf_block_count: number;
  waf_off_count: number;
  rate_limit_on_count: number;
  blocked_24h_total: number;
  alerts_critical_24h: number;
}
