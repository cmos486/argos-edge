// SSOSection renders the System > "Single Sign-On" panel: fetches
// the current OIDC config on mount, lets the admin edit the fields,
// run a connectivity test (discovery probe, no token exchange), and
// save. client_secret is a write-only field with placeholder
// "unchanged" when one is already stored; leaving it blank on save
// keeps the previous value, which is what the backend does too.
//
// Deliberately a standalone component rather than inline on the
// System page: this one panel owns ~150 lines of form + state, and
// putting it in System.tsx would double that file's size without
// sharing state with the rest.

import { FormEvent, useCallback, useEffect, useState } from 'react';
import {
  AlertTriangle,
  Check,
  Copy,
  KeyRound,
  Loader2,
  PlugZap,
} from 'lucide-react';
import {
  ApiError,
  OIDCStatus,
  OIDCTestResult,
  api,
} from '../api/client';

type FormState = {
  enabled: boolean;
  issuer_url: string;
  client_id: string;
  client_secret: string;          // "" = unchanged
  scopes: string;
  cookie_parent_domain: string;
  auto_provision: boolean;
  require_email_verified: boolean;
  allowed_emails: string;         // comma/newline separated textarea
  allowed_domains: string;
};

function toForm(s: OIDCStatus): FormState {
  // Defensive (?? []) even though the backend now always sends []: an
  // older server that predates the fix, or a middleware that strips
  // empty arrays, would otherwise crash on .join(). Cheap belt-and-
  // suspenders.
  return {
    enabled: s.enabled,
    issuer_url: s.issuer_url ?? '',
    client_id: s.client_id ?? '',
    client_secret: '',
    scopes: s.scopes ?? '',
    cookie_parent_domain: s.cookie_parent_domain ?? '',
    auto_provision: s.auto_provision,
    require_email_verified: s.require_email_verified ?? false,
    allowed_emails: (s.allowed_emails ?? []).join('\n'),
    allowed_domains: (s.allowed_domains ?? []).join('\n'),
  };
}

function parseList(s: string): string[] {
  return s
    .split(/[\s,]+/)
    .map((x) => x.trim())
    .filter((x) => x !== '');
}

export default function SSOSection() {
  const [state, setState] = useState<OIDCStatus | null>(null);
  const [form, setForm] = useState<FormState | null>(null);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [testResult, setTestResult] = useState<OIDCTestResult | null>(null);
  const [testErr, setTestErr] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);

  const load = useCallback(async () => {
    try {
      const s = await api.oidcStatus();
      setState(s);
      setForm(toForm(s));
      setErr(null);
    } catch (e) {
      setErr(e instanceof ApiError ? e.message : 'failed to load');
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  async function onTest() {
    if (!form) return;
    setBusy(true);
    setTestErr(null);
    setTestResult(null);
    try {
      const r = await api.oidcTest(form.issuer_url.trim() || undefined);
      setTestResult(r);
    } catch (e) {
      setTestErr(e instanceof ApiError ? e.message : 'probe failed');
    } finally {
      setBusy(false);
    }
  }

  async function onSave(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    if (!form) return;
    setBusy(true);
    setErr(null);
    try {
      const body = {
        enabled: form.enabled,
        issuer_url: form.issuer_url.trim(),
        client_id: form.client_id.trim(),
        // Empty string tells the backend "keep previous" per the
        // spec. Explicit "" is intentional -- it differs from not
        // sending the field because the backend does a JSON merge.
        ...(form.client_secret ? { client_secret: form.client_secret } : {}),
        scopes: form.scopes.trim(),
        cookie_parent_domain: form.cookie_parent_domain.trim(),
        auto_provision: form.auto_provision,
        require_email_verified: form.require_email_verified,
        allowed_emails: parseList(form.allowed_emails),
        allowed_domains: parseList(form.allowed_domains),
      };
      const s = await api.oidcSaveConfig(body);
      setState(s);
      setForm(toForm(s));
    } catch (e2) {
      setErr(e2 instanceof ApiError ? e2.message : 'save failed');
    } finally {
      setBusy(false);
    }
  }

  function copyRedirect() {
    if (!state) return;
    navigator.clipboard?.writeText(state.redirect_uri).catch(() => undefined);
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  }

  if (!form || !state) {
    return (
      <section className="bg-slate-900 border border-slate-800 rounded-lg p-4">
        <div className="text-sm text-slate-400">
          {err ?? 'loading SSO config...'}
        </div>
      </section>
    );
  }

  return (
    <section className="bg-slate-900 border border-slate-800 rounded-lg p-4 space-y-3">
      <div className="flex items-center justify-between gap-4 flex-wrap">
        <div className="flex items-center gap-2 text-slate-300">
          <KeyRound className="w-4 h-4" />
          <span className="font-medium">Single sign-on (OIDC)</span>
          <Badge enabled={state.enabled} configured={state.client_secret_set} />
        </div>
      </div>

      <div className="flex items-start gap-2 bg-amber-950/40 border border-amber-900 rounded px-3 py-2 text-xs text-amber-200">
        <AlertTriangle className="w-4 h-4 mt-0.5 flex-shrink-0" />
        <span>
          OIDC users bypass local two-factor authentication. Make sure the
          provider enforces MFA itself (Authentik / Authelia / Keycloak all
          support it out of the box).
        </span>
      </div>

      <div className="bg-slate-950 border border-slate-800 rounded px-3 py-2 text-xs text-slate-300">
        <div className="mb-1 text-slate-400">Redirect URI to register in your provider:</div>
        <div className="flex items-center gap-2">
          <code className="flex-1 font-mono text-[11px] break-all">{state.redirect_uri}</code>
          <button
            type="button"
            onClick={copyRedirect}
            className="p-1.5 rounded border border-slate-700 hover:bg-slate-800"
            title="copy"
          >
            {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
          </button>
        </div>
      </div>

      <form onSubmit={onSave} className="space-y-3">
        <label className="flex items-center gap-2 text-sm text-slate-300">
          <input
            type="checkbox"
            checked={form.enabled}
            onChange={(e) => setForm({ ...form, enabled: e.target.checked })}
            className="accent-sky-500"
          />
          Enable single sign-on
        </label>

        <Field label="Issuer URL" hint="e.g. https://auth.example.com or https://accounts.google.com">
          <input
            type="url"
            value={form.issuer_url}
            onChange={(e) => setForm({ ...form, issuer_url: e.target.value })}
            placeholder="https://..."
            className="w-full px-3 py-2 rounded bg-slate-800 border border-slate-700 focus:outline-none focus:border-sky-500"
          />
        </Field>

        <Field label="Client ID">
          <input
            type="text"
            value={form.client_id}
            onChange={(e) => setForm({ ...form, client_id: e.target.value })}
            className="w-full px-3 py-2 rounded bg-slate-800 border border-slate-700 font-mono text-xs focus:outline-none focus:border-sky-500"
          />
        </Field>

        <Field
          label="Client secret"
          hint={
            state.client_secret_set
              ? 'Leave blank to keep the stored secret.'
              : 'Required on first save.'
          }
        >
          <input
            type="password"
            value={form.client_secret}
            onChange={(e) => setForm({ ...form, client_secret: e.target.value })}
            placeholder={state.client_secret_set ? '(unchanged)' : ''}
            autoComplete="new-password"
            className="w-full px-3 py-2 rounded bg-slate-800 border border-slate-700 focus:outline-none focus:border-sky-500"
          />
        </Field>

        <Field label="Scopes" hint='Space-separated. "openid" is required and will be added if missing.'>
          <input
            type="text"
            value={form.scopes}
            onChange={(e) => setForm({ ...form, scopes: e.target.value })}
            className="w-full px-3 py-2 rounded bg-slate-800 border border-slate-700 font-mono text-xs focus:outline-none focus:border-sky-500"
          />
        </Field>

        <Field
          label="Cookie parent domain"
          hint='For ForwardAuth on subdomains. Example: "cmos486.es" makes the session cookie visible to every host under that domain. Leave blank to scope to the panel host only.'
        >
          <input
            type="text"
            value={form.cookie_parent_domain}
            onChange={(e) => setForm({ ...form, cookie_parent_domain: e.target.value })}
            placeholder="example.com"
            className="w-full px-3 py-2 rounded bg-slate-800 border border-slate-700 font-mono text-xs focus:outline-none focus:border-sky-500"
          />
        </Field>

        <label className="flex items-center gap-2 text-sm text-slate-300">
          <input
            type="checkbox"
            checked={form.auto_provision}
            onChange={(e) => setForm({ ...form, auto_provision: e.target.checked })}
            className="accent-sky-500"
          />
          Auto-provision new users on first login
        </label>

        <label
          className="flex items-start gap-2 text-sm text-slate-300"
          title="Reject logins where the identity provider has not verified the user's email address. Enable if your provider supports email verification (Google, Microsoft, most SSO products)."
        >
          <input
            type="checkbox"
            checked={form.require_email_verified}
            onChange={(e) => setForm({ ...form, require_email_verified: e.target.checked })}
            className="accent-sky-500 mt-0.5"
          />
          <span>
            Require verified email from provider
            <span className="block text-xs text-slate-500">
              Rejects logins where the id_token has email_verified=false or omits the claim.
              Safe to enable with Google, Microsoft, Keycloak, Authentik, Authelia.
            </span>
          </span>
        </label>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
          <Field label="Allowed emails" hint="One per line; empty = allow all">
            <textarea
              value={form.allowed_emails}
              onChange={(e) => setForm({ ...form, allowed_emails: e.target.value })}
              rows={3}
              placeholder="alice@example.com"
              className="w-full px-3 py-2 rounded bg-slate-800 border border-slate-700 font-mono text-xs focus:outline-none focus:border-sky-500"
            />
          </Field>
          <Field label="Allowed domains" hint="Exact match; one per line">
            <textarea
              value={form.allowed_domains}
              onChange={(e) => setForm({ ...form, allowed_domains: e.target.value })}
              rows={3}
              placeholder="example.com"
              className="w-full px-3 py-2 rounded bg-slate-800 border border-slate-700 font-mono text-xs focus:outline-none focus:border-sky-500"
            />
          </Field>
        </div>

        {err && (
          <div className="text-sm text-red-400 bg-red-950/40 border border-red-900 rounded px-3 py-2">
            {err}
          </div>
        )}

        <div className="flex items-center gap-2 justify-end">
          <button
            type="button"
            onClick={onTest}
            disabled={busy || !form.issuer_url.trim()}
            className="flex items-center gap-1 px-3 py-1.5 text-sm rounded border border-slate-700 hover:bg-slate-800 disabled:opacity-50"
          >
            {busy ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <PlugZap className="w-3.5 h-3.5" />}
            Test connection
          </button>
          <button
            type="submit"
            disabled={busy}
            className="px-3 py-1.5 text-sm rounded bg-sky-600 hover:bg-sky-500 disabled:bg-slate-700 font-medium"
          >
            {busy ? 'saving...' : 'Save'}
          </button>
        </div>
      </form>

      {testErr && (
        <div className="text-xs text-red-400 bg-red-950/40 border border-red-900 rounded px-3 py-2">
          Connectivity test failed: {testErr}
        </div>
      )}
      {testResult && (
        <div className="text-xs bg-emerald-950/40 border border-emerald-900 rounded px-3 py-2 text-emerald-200 space-y-0.5">
          <div>Discovery OK. Provider advertised:</div>
          <div className="font-mono text-[11px] space-y-0.5 mt-1">
            <div>issuer:     {testResult.issuer}</div>
            <div>auth:       {testResult.authorization_endpoint}</div>
            <div>token:      {testResult.token_endpoint}</div>
            {testResult.userinfo_endpoint && <div>userinfo:   {testResult.userinfo_endpoint}</div>}
            {testResult.jwks_uri && <div>jwks:       {testResult.jwks_uri}</div>}
          </div>
        </div>
      )}
    </section>
  );
}

function Field({
  label,
  hint,
  children,
}: {
  label: string;
  hint?: string;
  children: React.ReactNode;
}) {
  return (
    <label className="block text-sm text-slate-300">
      <span className="mb-1 block">{label}</span>
      {children}
      {hint && <span className="mt-1 block text-xs text-slate-500">{hint}</span>}
    </label>
  );
}

function Badge({ enabled, configured }: { enabled: boolean; configured: boolean }) {
  if (!configured) {
    return (
      <span className="ml-1 text-xs px-2 py-0.5 rounded bg-slate-800 text-slate-400 border border-slate-700">
        not configured
      </span>
    );
  }
  const cls = enabled
    ? 'bg-emerald-900 text-emerald-200 border-emerald-800'
    : 'bg-slate-800 text-slate-400 border-slate-700';
  return (
    <span className={`ml-1 text-xs px-2 py-0.5 rounded border ${cls}`}>
      {enabled ? 'enabled' : 'disabled'}
    </span>
  );
}
