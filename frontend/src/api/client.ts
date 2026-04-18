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

export interface Host {
  id: number;
  domain: string;
  upstream_url: string;
  upstream_verify_tls: boolean;
  tls_mode: TLSMode;
  tls_email: string;
  enabled: boolean;
  created_at: string;
  updated_at: string;
}

export interface HostInput {
  domain: string;
  upstream_url: string;
  upstream_verify_tls?: boolean;
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
};
