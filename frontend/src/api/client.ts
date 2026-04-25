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

// LoginResult is the union /api/auth/login returns:
//   * User on password-only accounts (session cookie set)
//   * TOTPPending on accounts with 2fa enabled (NO cookie yet; caller
//     must complete /auth/totp/verify or /auth/totp/recovery)
export interface TOTPPending {
  requires_totp: true;
  challenge_id: string;
}
export type LoginResult = User | TOTPPending;

// Narrow helper so callers can branch with a type guard rather than
// field-sniffing.
export function isTOTPPending(v: LoginResult): v is TOTPPending {
  return (v as TOTPPending).requires_totp === true;
}

export interface TOTPStatus {
  enabled: boolean;
  enabled_at?: string;
  setup_pending: boolean;
  recovery_codes_remaining: number;
}

export interface TOTPSetupResponse {
  secret: string;
  otpauth_url: string;
  qr_png_base64: string;
  recovery_codes: string[];
}

export interface TOTPRecoveryResponse {
  username: string;
  recovery_codes_remaining: number;
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

export type TLSMode = 'auto' | 'none' | 'manual';
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

// v1.3.7 target-health wire shape. "unknown" covers both
// never-probed-yet targets and targets whose group is currently
// disabled -- the UI renders both as a grey badge.
export type TargetHealthStatus = 'healthy' | 'unhealthy' | 'unknown';

export interface TargetHealth {
  target_id: number;
  target_group_id: number;
  host: string;
  port: number;
  enabled: boolean;
  status: TargetHealthStatus;
  last_status_code?: number | null;
  last_error?: string;
  last_checked_at?: string | null;
  num_requests: number;
  num_fails: number;
}

export interface TargetsHealthResponse {
  targets: TargetHealth[];
  fetched_at: string;
}

export interface TargetGroup {
  id: number;
  name: string;
  protocol: Protocol;
  verify_tls: boolean;
  preserve_host: boolean;
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
  preserve_host?: boolean;
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
  // Phase C ForwardAuth toggle. When true, Caddy forwards every
  // request through /api/auth/forward before the reverse_proxy
  // fires. Cookie must be the panel's session (or inherited via
  // parent-domain cookie when that is configured).
  auth_required: boolean;
  // v1.3.18: when true, Caddy gates the host with a remote_ip
  // matcher accepting only RFC 1918 + loopback + ULA; public IPs
  // get a 403. Use for admin panels exposed via public DNS but
  // intended for LAN/VPN reach only.
  lan_only: boolean;
  // Per-host override of the acme.ca_url global setting. Empty
  // string => inherit the global (which itself falls back to LE
  // production). ARGOS_ACME_CA_URL env var trumps both.
  tls_acme_ca_url: string;
  // tls_challenge selects which ACME challenge Caddy uses: dns-01
  // via the configured provider, http-01 on :80, or tls-alpn-01 on :443.
  tls_challenge: TLSChallenge;
  // tls_dns_provider names the dns_providers row the reconciler reads
  // credentials from when tls_challenge='dns'. Default 'cloudflare'
  // preserves the pre-v1.3 single-provider behaviour.
  tls_dns_provider: string;
  rules_count: number;
  created_at: string;
  updated_at: string;
}

export type TLSChallenge = 'dns' | 'http' | 'tls-alpn';

// --- v1.3: DNS providers catalogue ---

// DNS_PROVIDER_UNCHANGED is the sentinel a secret field sends when
// the operator did not retype the value. The backend keeps the
// previously-stored ciphertext intact for that field; it is the same
// convention used by OIDC + notification channels.
export const DNS_PROVIDER_UNCHANGED = '__UNCHANGED__';

export interface DNSProviderField {
  key: string;
  label: string;
  required: boolean;
  placeholder?: string;
  secret?: boolean;
}

export interface DNSProvider {
  name: string;
  display_name: string;
  enabled: boolean;
  configured: boolean;
  fields: DNSProviderField[];
  caddy_module: string;
  docs_url?: string;
  updated_at?: string;
}

export interface DNSProviderUpdate {
  enabled?: boolean;
  credentials?: Record<string, string>;
}

// DNSProviderUpdateResult is the shape PUT /api/dns-providers/{name}
// returns. On a successful save where reconcile ALSO succeeded, the
// full DNSProvider is returned. On saved-but-reconcile-failed, the
// partial `{saved, reconcile_error}` shape surfaces so the UI can
// show both "DB OK" and "Caddy NOT applied" to the operator.
export type DNSProviderUpdateResult =
  | DNSProvider
  | { saved: true; reconcile_error: string };

export function isReconcileError(
  r: DNSProviderUpdateResult,
): r is { saved: true; reconcile_error: string } {
  return 'reconcile_error' in r;
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
  auth_required?: boolean;
  lan_only?: boolean;
  tls_acme_ca_url?: string;
  tls_challenge?: TLSChallenge;
  tls_dns_provider?: string;
}

export interface Cert {
  domain: string;
  host_id: number;
  issuer: string;
  not_after: string;
  last_checked_at: string;
  days_left: number;
  status: 'ok' | 'warning' | 'critical' | 'expired' | 'unknown';
  next_renewal_estimate: string;
  last_renewal_event?: CertEvent;
  challenge?: TLSChallenge;
}

export interface CertEvent {
  timestamp: string;
  message: string;
  success: boolean;
}

export interface CertRenewResult {
  queued: boolean;
  domain: string;
  message: string;
}

export interface ManualCert {
  host_id: number;
  domain: string;
  issuer?: string;
  subject_cn?: string;
  sans: string[];
  not_before: string;
  not_after: string;
  days_left: number;
  status: 'ok' | 'warning' | 'critical' | 'expired' | 'unknown';
  fingerprint_sha256: string;
  uploaded_at: string;
  uploaded_by: number;
  has_chain: boolean;
}

export interface ManualCertUploadResult {
  cert: ManualCert;
  warnings: string[] | null;
  host: Host;
}

function onUnauthorized(): void {
  if (typeof window === 'undefined') return;
  if (window.location.pathname !== '/login') {
    window.location.assign('/login');
  }
}

// RequestOpts is request()'s extra options beyond RequestInit. The only
// one we use today is suppressAuthRedirect: certain endpoints (TOTP
// verify, TOTP disable) legitimately return 401 on a bad code even
// when the session cookie is perfectly valid. Without this flag the
// global onUnauthorized() would yank the user back to /login on every
// typo, which is worse than useless.
interface RequestOpts {
  suppressAuthRedirect?: boolean;
}

async function request<T>(
  path: string,
  init?: RequestInit,
  opts?: RequestOpts,
): Promise<T> {
  const res = await fetch(`${BASE}${path}`, {
    credentials: 'same-origin',
    headers: {
      Accept: 'application/json',
      ...(init?.body ? { 'Content-Type': 'application/json' } : {}),
      ...(init?.headers ?? {}),
    },
    ...init,
  });
  return handleResponse<T>(res, opts);
}

// rawRequest is for non-JSON bodies (e.g. multipart uploads). It does
// NOT set Content-Type so the browser can add the right boundary.
async function rawRequest<T>(path: string, init: RequestInit): Promise<T> {
  const res = await fetch(`${BASE}${path}`, {
    credentials: 'same-origin',
    ...init,
  });
  return handleResponse<T>(res);
}

async function handleResponse<T>(res: Response, opts?: RequestOpts): Promise<T> {

  if (res.status === 401) {
    if (!opts?.suppressAuthRedirect) {
      onUnauthorized();
    }
    // Surface the backend's 'invalid code' / 'challenge not found' etc.
    // so the TOTP pages can render them inline.
    const ct = res.headers.get('content-type') ?? '';
    const isJSON = ct.includes('application/json');
    const body = isJSON ? await res.json().catch(() => null) : null;
    const msg =
      isJSON && body && typeof body === 'object' && 'error' in body
        ? String((body as { error: unknown }).error)
        : 'unauthorized';
    throw new ApiError(401, msg);
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
  login(username: string, password: string): Promise<LoginResult> {
    return request<LoginResult>('/auth/login', {
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

  // ----- TOTP -----
  // verify + recovery are pre-session and MUST NOT trigger the global
  // redirect on 401; a wrong code is an inline error, not a logout.
  // setup/activate/disable/status all run inside an authed session
  // (the 401 that CAN legitimately happen there is "bad TOTP code on
  // disable", which we also suppress so the modal shows the error).
  totpStatus(): Promise<TOTPStatus> {
    return request<TOTPStatus>('/auth/totp/status');
  },
  totpSetup(): Promise<TOTPSetupResponse> {
    return request<TOTPSetupResponse>('/auth/totp/setup', { method: 'POST' });
  },
  totpActivate(code: string): Promise<{ ok: boolean }> {
    return request<{ ok: boolean }>(
      '/auth/totp/activate',
      { method: 'POST', body: JSON.stringify({ code }) },
      { suppressAuthRedirect: true },
    );
  },
  totpDisable(password: string, code: string): Promise<{ ok: boolean }> {
    return request<{ ok: boolean }>(
      '/auth/totp/disable',
      { method: 'POST', body: JSON.stringify({ password, code }) },
      { suppressAuthRedirect: true },
    );
  },
  // totpRegenerateRecovery: password-gated, shows-once response.
  // 401 "invalid credentials" is expected for a typo so we suppress
  // the global redirect -- the modal renders the error inline and
  // lets the user retry without losing their place.
  totpRegenerateRecovery(password: string): Promise<{ codes: string[] }> {
    return request<{ codes: string[] }>(
      '/auth/totp/recovery/regenerate',
      { method: 'POST', body: JSON.stringify({ password }) },
      { suppressAuthRedirect: true },
    );
  },
  totpVerify(challengeId: string, code: string): Promise<User> {
    return request<User>(
      '/auth/totp/verify',
      {
        method: 'POST',
        body: JSON.stringify({ challenge_id: challengeId, code }),
      },
      { suppressAuthRedirect: true },
    );
  },
  totpRecovery(
    challengeId: string,
    recoveryCode: string,
  ): Promise<TOTPRecoveryResponse> {
    return request<TOTPRecoveryResponse>(
      '/auth/totp/recovery',
      {
        method: 'POST',
        body: JSON.stringify({
          challenge_id: challengeId,
          recovery_code: recoveryCode,
        }),
      },
      { suppressAuthRedirect: true },
    );
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

  renewCert(hostID: number): Promise<CertRenewResult> {
    return request<CertRenewResult>(`/certs/${hostID}/renew`, { method: 'POST' });
  },

  // --- v1.1 Fase 2: manual certs ---
  listManualCerts(): Promise<ManualCert[]> {
    return request<ManualCert[]>('/manual-certs');
  },
  getManualCert(hostID: number): Promise<ManualCert> {
    return request<ManualCert>(`/manual-certs/${hostID}`);
  },
  async uploadManualCert(
    hostID: number,
    fields: { cert: File | string; key: File | string; chain?: File | string },
  ): Promise<ManualCertUploadResult> {
    const fd = new FormData();
    const add = (name: string, v: File | string | undefined) => {
      if (v === undefined) return;
      if (v instanceof File) fd.append(name, v);
      else fd.append(name, new Blob([v], { type: 'application/x-pem-file' }), `${name}.pem`);
    };
    add('cert_pem', fields.cert);
    add('key_pem', fields.key);
    add('chain_pem', fields.chain);
    return rawRequest<ManualCertUploadResult>(`/manual-certs/${hostID}`, {
      method: 'POST',
      body: fd,
    });
  },
  deleteManualCert(hostID: number, revert: 'auto' | 'none' = 'auto'): Promise<{ ok: boolean; host: Host }> {
    return request<{ ok: boolean; host: Host }>(
      `/manual-certs/${hostID}?revert=${revert}`,
      { method: 'DELETE' },
    );
  },
  manualCertDownloadURL(hostID: number): string {
    return `${BASE}/manual-certs/${hostID}/download`;
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

  targetsHealth(): Promise<TargetsHealthResponse> {
    return request<TargetsHealthResponse>('/targets/health');
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

  // --- v1.3: DNS providers ---
  // Credentials never travel in the GET responses, only in the PUT
  // body. The GET shape exposes {enabled, configured, fields[...]} so
  // the Settings page can render every supported provider as a card
  // regardless of whether it has credentials yet.
  listDNSProviders(): Promise<DNSProvider[]> {
    return request<DNSProvider[]>('/dns-providers');
  },
  getDNSProvider(name: string): Promise<DNSProvider> {
    return request<DNSProvider>(`/dns-providers/${encodeURIComponent(name)}`);
  },
  updateDNSProvider(
    name: string,
    body: DNSProviderUpdate,
  ): Promise<DNSProviderUpdateResult> {
    return request<DNSProviderUpdateResult>(
      `/dns-providers/${encodeURIComponent(name)}`,
      { method: 'PUT', body: JSON.stringify(body) },
    );
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

  // --- Phase 9a: backups + config I/O ---
  listBackups(): Promise<BackupRow[]> {
    return request<BackupRow[]>('/backups');
  },
  createBackup(note?: string): Promise<BackupRow> {
    return request<BackupRow>('/backups', {
      method: 'POST',
      body: JSON.stringify({ note: note ?? '' }),
    });
  },
  deleteBackup(id: number): Promise<void> {
    return request<void>(`/backups/${id}`, { method: 'DELETE' });
  },
  // Returns the relative URL a <a download> should hit. The cookie
  // carries the session automatically.
  backupDownloadURL(id: number): string {
    return `${BASE}/backups/${id}/download`;
  },
  restoreBackup(id: number): Promise<RestoreScheduled> {
    return request<RestoreScheduled>(`/backups/${id}/restore`, {
      method: 'POST',
      body: JSON.stringify({ confirm: true }),
    });
  },
  uploadAndRestore(file: File): Promise<RestoreScheduled> {
    const fd = new FormData();
    fd.append('file', file);
    fd.append('confirm', 'true');
    return rawRequest<RestoreScheduled>('/backups/upload-and-restore', {
      method: 'POST',
      body: fd,
    });
  },

  exportConfigURL(): string {
    return `${BASE}/config/export.yaml`;
  },
  validateImport(yaml: string, mode: 'replace' | 'merge'): Promise<ImportPlan> {
    return request<ImportPlan>('/config/import/validate', {
      method: 'POST',
      body: JSON.stringify({ yaml, mode }),
    });
  },
  applyImport(yaml: string, mode: 'replace' | 'merge'): Promise<ImportPlan> {
    return request<ImportPlan>('/config/import/apply', {
      method: 'POST',
      body: JSON.stringify({ yaml, mode }),
    });
  },

  // --- Phase 6 dashboard ---
  dashboardOverview(): Promise<DashOverview> {
    return request<DashOverview>('/dashboard/overview');
  },
  dashboardTraffic(range: DashRange, hostID?: number): Promise<DashTraffic> {
    const q = hostID ? `?range=${range}&host_id=${hostID}` : `?range=${range}`;
    return request<DashTraffic>(`/dashboard/traffic${q}`);
  },
  dashboardSecurity(range: DashRange): Promise<DashSecurity> {
    return request<DashSecurity>(`/dashboard/security?range=${range}`);
  },
  dashboardHealth(): Promise<DashHealth> {
    return request<DashHealth>('/dashboard/health');
  },

  // --- Phase 9b system ---
  systemHealth(): Promise<SystemHealth> {
    return request<SystemHealth>('/system/health');
  },

  // --- GeoIP (DB-IP Lite) ---
  geoipStatus(): Promise<GeoIPStatus> {
    return request<GeoIPStatus>('/geoip/status');
  },
  geoipRefresh(): Promise<GeoIPRefreshResult> {
    return request<GeoIPRefreshResult>('/geoip/refresh', { method: 'POST' });
  },

  // --- Phase 7 threats (CrowdSec) ---
  threatsStatus(): Promise<ThreatsStatus> {
    return request<ThreatsStatus>('/threats/status');
  },
  threatsDecisions(params?: { origin?: string; type?: string; search?: string }): Promise<ThreatDecision[]> {
    const q = params
      ? '?' + new URLSearchParams(Object.entries(params).filter(([, v]) => v) as [string, string][]).toString()
      : '';
    return request<ThreatDecision[]>(`/threats/decisions${q}`);
  },
  addThreatDecision(input: { ip: string; duration_hours: number; reason?: string }): Promise<{ ip: string }> {
    return request<{ ip: string }>('/threats/decisions', {
      method: 'POST',
      body: JSON.stringify(input),
    });
  },
  deleteThreatDecision(ip: string): Promise<{ ip: string; removed: number }> {
    return request<{ ip: string; removed: number }>(`/threats/decisions?ip=${encodeURIComponent(ip)}`, {
      method: 'DELETE',
    });
  },
  threatsStats(): Promise<ThreatsStats> {
    return request<ThreatsStats>('/threats/stats');
  },
  threatsScenarios(): Promise<ThreatCollection[]> {
    return request<ThreatCollection[]>('/threats/scenarios');
  },

  // v1.3.6: operator-triggered CrowdSec machine-credentials
  // re-verification. Backend verifies stored creds against LAPI and
  // purges on 401. Four status outcomes (valid / purged /
  // no_credentials / bad_gateway). UI shows the returned `message`
  // as a toast.
  crowdsecRegenerateCredentials(): Promise<CrowdSecRegenerateResult> {
    return request<CrowdSecRegenerateResult>('/crowdsec/regenerate-credentials', {
      method: 'POST',
    });
  },

  // ---- AppSec (WAF inline) ----
  appsecStatus(): Promise<AppSecStatus> {
    return request<AppSecStatus>('/appsec/status');
  },
  appsecMetrics(window: AppSecWindow = '24h'): Promise<AppSecMetrics> {
    return request<AppSecMetrics>(`/appsec/metrics?window=${window}`);
  },
  appsecSetMode(mode: AppSecMode): Promise<AppSecModePatchResult> {
    return request<AppSecModePatchResult>('/appsec/mode', {
      method: 'PATCH',
      body: JSON.stringify({ mode }),
    });
  },

  // ---- OIDC SSO ----
  // oidcAvailable is the pre-session probe the Login page uses to
  // decide whether to render the "Sign in with SSO" button. Leaks
  // nothing beyond the boolean. oidcStatus() (authed) returns the
  // full admin view for the System > SSO page.
  oidcAvailable(): Promise<{ enabled: boolean }> {
    return request<{ enabled: boolean }>('/auth/oidc/available');
  },
  oidcStatus(): Promise<OIDCStatus> {
    return request<OIDCStatus>('/auth/oidc/status');
  },
  oidcSaveConfig(body: OIDCConfigInput): Promise<OIDCStatus> {
    return request<OIDCStatus>('/auth/oidc/config', {
      method: 'PUT',
      body: JSON.stringify(body),
    });
  },
  oidcTest(issuerUrl?: string): Promise<OIDCTestResult> {
    return request<OIDCTestResult>('/auth/oidc/test', {
      method: 'POST',
      body: JSON.stringify(issuerUrl ? { issuer_url: issuerUrl } : {}),
    });
  },
  // safeRedirect asks the backend to run the open-redirect
  // allowlist against an rd=<url> value. Returns the sanitized URL
  // (or "/" when not allowed). Used by the post-login flow so the
  // frontend never has to encode the same rules.
  safeRedirect(rd: string): Promise<{ url: string }> {
    return request<{ url: string }>(
      '/auth/safe-redirect?rd=' + encodeURIComponent(rd),
    );
  },

  // v1.3.19 minimal security surface (self-block escape hatch).
  // Full security panel API ships in v1.3.20+.
  securityCheckSelf(): Promise<SecurityCheckSelfResponse> {
    return request<SecurityCheckSelfResponse>('/security/check-self');
  },
  securityUnbanIP(ip: string): Promise<{ unbanned: number; ip: string }> {
    return request<{ unbanned: number; ip: string }>(
      '/security/decisions/unban-ip',
      { method: 'POST', body: JSON.stringify({ ip }) },
    );
  },
  securityWhitelistAdd(
    scope: 'ip' | 'range',
    value: string,
    reason?: string,
  ): Promise<SecurityWhitelistAddResponse> {
    return request<SecurityWhitelistAddResponse>('/security/whitelist', {
      method: 'POST',
      body: JSON.stringify({ scope, value, reason: reason ?? '' }),
    });
  },

  // v1.3.21 country-ban expansion. The panel translates one
  // operator-issued country ban into N scope=Range LAPI decisions
  // (the upstream caddy-crowdsec-bouncer plugin does not handle
  // scope=Country in either stream or live mode).
  securityCountriesList(): Promise<CountryExpansion[]> {
    return request<CountryExpansion[]>('/security/countries');
  },
  securityCountriesExpand(
    country_code: string,
    duration: string,
    reason?: string,
  ): Promise<CountryExpansionResult> {
    return request<CountryExpansionResult>('/security/countries/expand', {
      method: 'POST',
      body: JSON.stringify({
        country_code,
        duration,
        reason: reason ?? '',
      }),
    });
  },
  securityCountriesRevoke(
    country_code: string,
  ): Promise<{ country_code: string; removed_decision_count: number }> {
    return request<{ country_code: string; removed_decision_count: number }>(
      `/security/countries/${encodeURIComponent(country_code)}`,
      { method: 'DELETE' },
    );
  },
};

// v1.3.21 country-ban types. Mirror the Go shape in
// backend/internal/security/country/expander.go.
export interface CountryExpansion {
  id: number;
  country_code: string;
  cidrs: string[];
  cidr_count: number;
  reason: string;
  duration: string;
  created_at: string;
  created_by: string;
  mmdb_version_at_creation: string;
}

export interface CountryExpansionResult {
  country_code: string;
  cidr_count: number;
  // v1.3.22: requested_count is the full MMDB count; cidr_count is
  // what LAPI accepted. failed_chunks > 0 means partial success
  // (continue-on-error semantics over chunked /v1/alerts batches).
  requested_count?: number;
  failed_chunks?: number;
  mmdb_version: string;
  expansion_id: number;
  origin_tag: string;
  replaced_rows?: number;
}

export interface OIDCStatus {
  enabled: boolean;
  issuer_url: string;
  client_id: string;
  client_secret_set: boolean;
  scopes: string;
  cookie_parent_domain: string;
  auto_provision: boolean;
  require_email_verified: boolean;
  allowed_emails: string[];
  allowed_domains: string[];
  redirect_uri: string;
}

export interface OIDCConfigInput {
  enabled?: boolean;
  issuer_url?: string;
  client_id?: string;
  client_secret?: string; // empty => keep previous
  scopes?: string;
  cookie_parent_domain?: string;
  auto_provision?: boolean;
  require_email_verified?: boolean;
  allowed_emails?: string[];
  allowed_domains?: string[];
}

export interface OIDCTestResult {
  issuer: string;
  authorization_endpoint: string;
  token_endpoint: string;
  userinfo_endpoint?: string;
  jwks_uri?: string;
  id_token_signing_alg_values_supported?: string[];
}

export type AppSecMode = 'detect' | 'block' | 'disabled';
export type AppSecWindow = '1h' | '6h' | '12h' | '24h';

export interface AppSecStatus {
  mode: AppSecMode;
  collections_installed?: string[];
  total_rules?: number;
  last_mode_change_at?: string;
  last_mode_change_by?: string;
}

export interface AppSecCategoryCount {
  category: string;
  count: number;
}

export interface AppSecTopIP {
  ip: string;
  count: number;
  last_seen: string;
  geo?: {
    country_code?: string;
    country_name?: string;
    asn?: number;
    asn_org?: string;
    is_private?: boolean;
  };
}

export interface AppSecTopPath {
  host?: string;
  path: string;
  count: number;
}

export interface AppSecTopRule {
  rule: string;
  message?: string;
  count: number;
}

export interface AppSecTimeBucket {
  time: string;
  hits: number;
  blocked: number;
}

export interface AppSecDegradedReason {
  code: 'machine_credentials_missing' | 'crowdsec_unreachable' | 'lapi_error';
  message: string;
}

export interface AppSecMetrics {
  window: string;
  mode: AppSecMode;
  total_hits: number;
  blocked: number;
  logged: number;
  by_category: AppSecCategoryCount[];
  top_ips: AppSecTopIP[];
  top_paths: AppSecTopPath[];
  top_rules: AppSecTopRule[];
  hits_over_time: AppSecTimeBucket[];
  // v1.3.4: non-null when the panel returned a partial response
  // instead of failing the whole metrics call. Most common cause:
  // machine credentials are not configured, so /v1/alerts returns
  // ErrNotConfigured; the AppSec endpoint itself is still fine.
  degraded?: AppSecDegradedReason | null;
}

export interface AppSecModePatchResult {
  ok: boolean;
  mode: AppSecMode;
  previous: AppSecMode;
  reconciled_at: string;
}

export interface CrowdSecRegenerateResult {
  status: 'valid' | 'purged' | 'no_credentials';
  message: string;
  machine_user?: string;
  next_action?: string;
}

export interface ThreatsStatus {
  state: 'not_configured' | 'connected' | 'disconnected' | 'degraded';
  lapi_version?: string;
  lapi_url?: string;
  last_heartbeat?: string | null;
  bouncer_ok: boolean;
  machine_ok: boolean;
  error?: string;
}

export interface ThreatDecision {
  id: number;
  origin: string;
  type: string;
  scope: string;
  value: string;
  scenario: string;
  duration: string;
  until: string;
  geo?: GeoEnrichment;
}

export interface ThreatsStats {
  range: string;
  active_decisions: number;
  by_origin: Record<string, number>;
  by_scenario: Record<string, number>;
  by_scope: Record<string, number>;
  last_updated: string;
}

export interface ThreatCollection {
  name: string;
  version?: string;
  parsers?: string[];
  scenarios?: string[];
}

// SettingRow is an alias used by Phase 9b callers. Kept separate from
// the older `Setting` alias to avoid touching the old list/update
// methods above.
export type SettingRow = Setting;

export interface GeoIPStatus {
  country_db_version: string;
  asn_db_version: string;
  loaded_at: string;
  last_refresh_at: string;
  last_refresh_error: string;
  country_db_path: string;
  asn_db_path: string;
  country_db_size_bytes: number;
  asn_db_size_bytes: number;
  attribution: string;
  cache_size: number;
  cache_hits: number;
  cache_misses: number;
  next_refresh_at: string;
}

export interface GeoIPRefreshResult {
  ok: boolean;
  country_version: string;
  asn_version: string;
  loaded_at: string;
  last_refresh_at: string;
  country_db_size: number;
  asn_db_size: number;
  error?: string;
}

export interface SystemHealth {
  memory: { alloc_mb: number; sys_mb: number; num_gc: number };
  goroutines: number;
  db: {
    size_bytes: number;
    wal_size_bytes: number;
    open_connections: number;
    idle_connections: number;
    in_use_connections: number;
  };
  workers: {
    notification_queue_depth: number;
    notification_queue_cap: number;
    notification_dropped_total: number;
  };
  scheduler: {
    last_backup_attempt?: string | null;
    last_backup_status: 'ok' | 'stale' | 'missing';
    last_backup_kind?: string;
  };
  uptime_seconds: number;
  panel_mode: 'lan' | 'behind_caddy';
  panel_domain?: string;
}


export type DashRange = '1h' | '6h' | '24h' | '7d';

export interface DashOverview {
  total_requests_24h: number;
  blocked_requests_24h: number;
  error_requests_24h: number;
  active_hosts: number;
  unhealthy_targets: number;
  certs_expiring_soon: number;
  last_backup_at?: string | null;
  last_backup_status: 'ok' | 'stale' | 'missing';
}

export interface DashTrafficBucket {
  time: string;
  c2xx: number;
  c3xx: number;
  c4xx: number;
  c5xx: number;
}
export interface DashResponseTimeBucket {
  time: string;
  p50_ms: number;
  p95_ms: number;
  p99_ms: number;
  n: number;
}
export interface DashHostVolume {
  host_domain: string;
  count: number;
}
export interface DashPathVolume {
  host_domain: string;
  path: string;
  count: number;
}
export interface DashTraffic {
  range: DashRange;
  granularity: string;
  timeseries: DashTrafficBucket[];
  response_times: DashResponseTimeBucket[];
  top_hosts: DashHostVolume[];
  top_paths: DashPathVolume[];
  bandwidth_out_bytes: number;
}

export interface DashWafBucket {
  time: string;
  detected: number;
  blocked: number;
}
export interface DashAttackType {
  rule_id: number;
  message: string;
  count: number;
}
export interface DashAttackIP {
  remote_ip: string;
  count: number;
  distinct_hosts: number;
  last_seen: string;
  geo?: GeoEnrichment;
}

export interface GeoEnrichment {
  country_code?: string;
  country_name?: string;
  asn?: number;
  asn_org?: string;
  is_private?: boolean;
}
export interface DashAttackPath {
  host_domain: string;
  path: string;
  count: number;
}
export interface DashCountryCount {
  country_code: string;
  country_name: string;
  count: number;
}

export interface DashSecurity {
  range: DashRange;
  granularity: string;
  waf_timeseries: DashWafBucket[];
  top_attack_types: DashAttackType[];
  top_attack_ips: DashAttackIP[];
  top_attacked_paths: DashAttackPath[];
  rate_limit_hits: number;
  by_country: DashCountryCount[];
  private_hits: number;
}

export interface DashTargetGroupHealth {
  name: string;
  total: number;
  enabled: number;
  status: 'ok' | 'degraded' | 'down';
}
export interface DashCertSummary {
  domain: string;
  not_after: string;
  days_left: number;
  status: 'ok' | 'warning' | 'critical' | 'unknown';
}
export interface DashBackupSummary {
  filename: string;
  created_at: string;
  size_bytes: number;
  kind: string;
}
export interface DashRecentError {
  timestamp: string;
  source: string;
  level?: string;
  message: string;
}
export interface DashHealth {
  target_groups: DashTargetGroupHealth[];
  certs: DashCertSummary[];
  last_backup?: DashBackupSummary | null;
  panel_uptime: string;
  caddy_status: 'ok' | 'unreachable' | 'degraded' | 'unknown';
  recent_errors: DashRecentError[];
}

export interface BackupRow {
  id: number;
  filename: string;
  size_bytes: number;
  sha256: string;
  kind: 'manual' | 'scheduled';
  trigger_user_id?: number | null;
  created_at: string;
  note?: string;
}

export interface RestoreScheduled {
  scheduled: boolean;
  backup?: BackupRow;
  warnings?: string[];
  message: string;
}

export interface ImportPlan {
  mode: 'replace' | 'merge';
  counts: Record<string, number>;
  creates?: string[];
  updates?: string[];
  conflicts?: string[];
  warnings?: string[];
}

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

// v1.3.19 security wire types.
export interface SecurityDecision {
  id: number;
  origin: string;
  type: string;
  scope: string;
  value: string;
  scenario: string;
  duration: string;
  until: string;
  created_at?: string;
}

export interface SecurityCheckSelfResponse {
  client_ip: string;
  banned: boolean;
  decisions: SecurityDecision[];
}

export interface SecurityWhitelistAddResponse {
  scope: 'ip' | 'range';
  value: string;
  reason: string;
  persisted: boolean;
  reload_needed: boolean;
  reload_command: string;
}
