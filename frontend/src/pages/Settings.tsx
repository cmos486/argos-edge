import { FormEvent, useCallback, useEffect, useState } from 'react';
import {
  ApiError,
  DNS_PROVIDER_UNCHANGED,
  DNSProvider,
  DNSProviderField,
  Setting,
  SystemHealth,
  api,
  isReconcileError,
} from '../api/client';
import { useToasts } from '../components/toastsContext';

export default function Settings() {
  const toasts = useToasts();
  const [settings, setSettings] = useState<Setting[]>([]);
  const [retention, setRetention] = useState('30');
  const [maxEntries, setMaxEntries] = useState('500000');
  const [total, setTotal] = useState<number | null>(null);
  const [saving, setSaving] = useState(false);

  const load = useCallback(async () => {
    try {
      const items = await api.listSettings('logs.');
      setSettings(items);
      for (const s of items) {
        if (s.key === 'logs.retention_days') setRetention(s.value);
        if (s.key === 'logs.max_entries') setMaxEntries(s.value);
      }
      const st = await api.logStats({});
      setTotal(st.total);
    } catch (e) {
      toasts.push(e instanceof ApiError ? e.message : 'load failed', 'error');
    }
  }, [toasts]);

  useEffect(() => {
    load();
  }, [load]);

  async function onSave(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    setSaving(true);
    try {
      await api.updateSetting('logs.retention_days', retention);
      await api.updateSetting('logs.max_entries', maxEntries);
      toasts.push('settings saved', 'success');
      await load();
    } catch (err) {
      toasts.push(err instanceof ApiError ? err.message : 'save failed', 'error');
    } finally {
      setSaving(false);
    }
  }

  async function onPurge() {
    if (!window.confirm('Run retention purge now?')) return;
    try {
      const r = await api.purgeLogs();
      toasts.push(`purged ${r.removed} entries`, 'success');
      await load();
    } catch (e) {
      toasts.push(e instanceof ApiError ? e.message : 'purge failed', 'error');
    }
  }

  return (
    <div className="p-6 max-w-2xl mx-auto space-y-4">
      <h1 className="text-2xl font-semibold mb-4">Settings</h1>

      <SecuritySection />

      <ACMESection />

      <DNSProvidersSection />

      <section className="bg-slate-900 border border-slate-800 rounded-lg p-4">
        <h2 className="text-lg font-semibold mb-3">Logs</h2>
        <form onSubmit={onSave} className="space-y-3 text-sm">
          <div>
            <label className="block text-slate-300 mb-1">Retention (days)</label>
            <input
              type="number"
              min={1}
              max={365}
              value={retention}
              onChange={(e) => setRetention(e.target.value)}
              className="w-40 px-3 py-2 rounded bg-slate-800 border border-slate-700 font-mono"
            />
          </div>
          <div>
            <label className="block text-slate-300 mb-1">Max entries</label>
            <input
              type="number"
              min={10000}
              max={5000000}
              value={maxEntries}
              onChange={(e) => setMaxEntries(e.target.value)}
              className="w-40 px-3 py-2 rounded bg-slate-800 border border-slate-700 font-mono"
            />
          </div>
          <div className="flex items-center gap-2 pt-1">
            <button
              type="submit"
              disabled={saving}
              className="px-3 py-1.5 rounded bg-sky-600 hover:bg-sky-500 disabled:bg-slate-700 text-sm font-medium"
            >
              {saving ? 'saving...' : 'Save'}
            </button>
            <button
              type="button"
              onClick={onPurge}
              className="px-3 py-1.5 rounded border border-slate-700 hover:bg-slate-800 text-sm"
            >
              Purge now
            </button>
            {total != null && (
              <span className="text-xs text-slate-500 ml-auto">Current: {total} entries</span>
            )}
          </div>
        </form>
        <details className="mt-4 text-xs text-slate-500">
          <summary className="cursor-pointer">Raw settings</summary>
          <pre className="mt-2 p-2 rounded bg-slate-950 border border-slate-800 overflow-auto">
            {JSON.stringify(settings, null, 2)}
          </pre>
        </details>
      </section>
    </div>
  );
}

function SecuritySection() {
  const toasts = useToasts();
  const [absHours, setAbsHours] = useState('168');
  const [idleHours, setIdleHours] = useState('24');
  const [sys, setSys] = useState<SystemHealth | null>(null);
  const [saving, setSaving] = useState(false);

  const load = useCallback(async () => {
    try {
      const items = await api.listSettings('session.');
      for (const s of items) {
        if (s.key === 'session.absolute_timeout_hours') setAbsHours(s.value);
        if (s.key === 'session.idle_timeout_hours') setIdleHours(s.value);
      }
      const h = await api.systemHealth();
      setSys(h);
    } catch (e) {
      toasts.push(e instanceof ApiError ? e.message : 'load failed', 'error');
    }
  }, [toasts]);

  useEffect(() => {
    load();
  }, [load]);

  async function onSave(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    const a = Number(absHours);
    const i = Number(idleHours);
    if (!(a >= 1 && a <= 720)) {
      toasts.push('absolute_timeout must be 1..720 hours', 'error');
      return;
    }
    if (!(i >= 1 && i <= a)) {
      toasts.push('idle_timeout must be 1..absolute', 'error');
      return;
    }
    setSaving(true);
    try {
      await api.updateSetting('session.absolute_timeout_hours', absHours);
      await api.updateSetting('session.idle_timeout_hours', idleHours);
      toasts.push('session settings saved', 'success');
      await load();
    } catch (err) {
      toasts.push(err instanceof ApiError ? err.message : 'save failed', 'error');
    } finally {
      setSaving(false);
    }
  }

  return (
    <section className="bg-slate-900 border border-slate-800 rounded-lg p-4">
      <h2 className="text-lg font-semibold mb-3">Security</h2>
      <form onSubmit={onSave} className="space-y-3 text-sm">
        <div>
          <label className="block text-slate-300 mb-1">Session absolute timeout (hours, 1..720)</label>
          <input
            type="number"
            min={1}
            max={720}
            value={absHours}
            onChange={(e) => setAbsHours(e.target.value)}
            className="w-40 px-3 py-2 rounded bg-slate-800 border border-slate-700 font-mono"
          />
        </div>
        <div>
          <label className="block text-slate-300 mb-1">Session idle timeout (hours, &le; absolute)</label>
          <input
            type="number"
            min={1}
            max={720}
            value={idleHours}
            onChange={(e) => setIdleHours(e.target.value)}
            className="w-40 px-3 py-2 rounded bg-slate-800 border border-slate-700 font-mono"
          />
        </div>
        <button
          type="submit"
          disabled={saving}
          className="px-3 py-1.5 rounded bg-sky-600 hover:bg-sky-500 disabled:bg-slate-700 text-sm font-medium"
        >
          {saving ? 'saving...' : 'Save'}
        </button>
      </form>
      {sys && (
        <div className="mt-4 text-xs text-slate-400 space-y-1 border-t border-slate-800 pt-3">
          <div>Panel mode: <code className="font-mono">{sys.panel_mode}</code></div>
          {sys.panel_domain && <div>Panel domain: <code className="font-mono">{sys.panel_domain}</code></div>}
          <div>Secure cookies: <code className="font-mono">{sys.panel_mode === 'behind_caddy' ? 'true' : 'false'}</code></div>
        </div>
      )}
    </section>
  );
}

// ACMESection controls the global acme.ca_url setting. Three modes:
//   * production (empty string) -- caddy default, LE prod, trusted
//     certs. Applies to every tls_mode=auto host that has no per-host
//     override.
//   * staging -- LE staging CA. Certs chain to a fake root, browsers
//     will warn. Valuable during development and when debugging
//     issuance without burning production rate limits.
//   * custom -- free-text https URL. For internal / private ACME
//     deployments.
const LE_PROD_URL = 'https://acme-v02.api.letsencrypt.org/directory';
const LE_STAGING_URL = 'https://acme-staging-v02.api.letsencrypt.org/directory';

type ACMEPreset = 'production' | 'staging' | 'custom';

function detectPreset(value: string): ACMEPreset {
  if (value === '' || value === LE_PROD_URL) return 'production';
  if (value === LE_STAGING_URL) return 'staging';
  return 'custom';
}

function ACMESection() {
  const toasts = useToasts();
  const [current, setCurrent] = useState<string>('');
  const [preset, setPreset] = useState<ACMEPreset>('production');
  const [customURL, setCustomURL] = useState('');
  const [saving, setSaving] = useState(false);

  const load = useCallback(async () => {
    try {
      const items = await api.listSettings('acme.');
      const row = items.find((s) => s.key === 'acme.ca_url');
      const value = row?.value ?? '';
      setCurrent(value);
      const p = detectPreset(value);
      setPreset(p);
      if (p === 'custom') setCustomURL(value);
    } catch (e) {
      toasts.push(e instanceof ApiError ? e.message : 'load failed', 'error');
    }
  }, [toasts]);

  useEffect(() => {
    load();
  }, [load]);

  async function onSave(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    let value = '';
    if (preset === 'staging') value = LE_STAGING_URL;
    else if (preset === 'custom') value = customURL.trim();
    setSaving(true);
    try {
      await api.updateSetting('acme.ca_url', value);
      toasts.push('ACME CA saved', 'success');
      await load();
    } catch (err) {
      toasts.push(err instanceof ApiError ? err.message : 'save failed', 'error');
    } finally {
      setSaving(false);
    }
  }

  const effective = preset === 'production' ? 'Let\'s Encrypt production (default)'
    : preset === 'staging' ? 'Let\'s Encrypt staging'
    : customURL.trim() || '(empty => production)';

  return (
    <section className="bg-slate-900 border border-slate-800 rounded-lg p-4">
      <h2 className="text-lg font-semibold mb-3">ACME CA</h2>
      <p className="text-xs text-slate-500 mb-3">
        Directory URL every tls_mode=auto host talks to. Per-host override
        on the host form takes precedence. ARGOS_ACME_CA_URL env var on
        the panel container trumps both.
      </p>
      <form onSubmit={onSave} className="space-y-3 text-sm">
        <label className="flex items-start gap-2">
          <input
            type="radio"
            name="acme-preset"
            checked={preset === 'production'}
            onChange={() => setPreset('production')}
            className="mt-1 accent-sky-600"
          />
          <span>
            <span className="text-slate-200">Let's Encrypt production (default)</span>
            <span className="block text-xs text-slate-500">Trusted certs. Rate-limited: 50 certs/registered domain/week.</span>
          </span>
        </label>
        <label className="flex items-start gap-2">
          <input
            type="radio"
            name="acme-preset"
            checked={preset === 'staging'}
            onChange={() => setPreset('staging')}
            className="mt-1 accent-sky-600"
          />
          <span>
            <span className="text-slate-200">Let's Encrypt staging (test)</span>
            <span className="block text-xs text-slate-500">Untrusted root; browsers will show a warning. Much higher rate limits for debugging.</span>
          </span>
        </label>
        <label className="flex items-start gap-2">
          <input
            type="radio"
            name="acme-preset"
            checked={preset === 'custom'}
            onChange={() => setPreset('custom')}
            className="mt-1 accent-sky-600"
          />
          <span className="flex-1">
            <span className="text-slate-200">Custom URL</span>
            <input
              type="url"
              placeholder="https://acme.internal.example/directory"
              value={customURL}
              onChange={(e) => setCustomURL(e.target.value)}
              disabled={preset !== 'custom'}
              className="mt-1 w-full px-3 py-2 rounded bg-slate-800 border border-slate-700 font-mono disabled:opacity-40"
            />
            <span className="block text-xs text-slate-500 mt-1">HTTPS only. Validated server-side before save.</span>
          </span>
        </label>

        {preset === 'staging' && (
          <div className="flex items-start gap-2 bg-amber-950/40 border border-amber-900 rounded px-3 py-2 text-xs text-amber-200">
            <span>
              Staging certs are <strong>not trusted by browsers</strong>. Flip every tls_mode=auto
              host to staging; users will see scary warnings on each. Use only for development
              or targeted per-host debugging via the host form override.
            </span>
          </div>
        )}

        <div className="flex items-center justify-between pt-1">
          <button
            type="submit"
            disabled={saving}
            className="px-3 py-1.5 rounded bg-sky-600 hover:bg-sky-500 disabled:bg-slate-700 text-sm font-medium"
          >
            {saving ? 'saving...' : 'Save'}
          </button>
          <div className="text-xs text-slate-500">
            <span className="uppercase tracking-wide">active:</span>{' '}
            <span className="font-mono text-slate-300">{effective}</span>
          </div>
        </div>
      </form>
      {current !== '' && (
        <div className="mt-3 text-xs text-slate-500 border-t border-slate-800 pt-3">
          Saved value: <code className="font-mono">{current}</code>
        </div>
      )}
    </section>
  );
}

// DNSProvidersSection (v1.3) owns the catalogue of native DNS-01
// providers and their encrypted credentials. The backend stores
// credentials AES-GCM-encrypted under ARGOS_MASTER_KEY and streams
// them inline into Caddy's /load JSON on every reconcile — no env
// vars to rotate, no container restart on credential change.
//
// Sub-phase A shipped the backend + API; this is the sub-phase B UI.
// Sub-phase C will expand the catalogue to gandi / desec / ovh /
// duckdns / porkbun / hetzner / digitalocean / acmedns.
function DNSProvidersSection() {
  const [providers, setProviders] = useState<DNSProvider[] | null>(null);
  const [loadError, setLoadError] = useState<string | null>(null);

  const load = useCallback(async () => {
    try {
      const list = await api.listDNSProviders();
      setProviders(list);
      setLoadError(null);
    } catch (e) {
      setLoadError(e instanceof ApiError ? e.message : 'load failed');
    }
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  return (
    <section className="bg-slate-900 border border-slate-800 rounded-lg p-4">
      <h2 className="text-lg font-semibold mb-1">DNS providers</h2>
      <p className="text-xs text-slate-500 mb-3">
        Credentials for DNS-01 ACME challenge. Used by every host with{' '}
        <code className="font-mono">tls_challenge=dns</code>. Stored
        encrypted in the panel DB and sent inline to Caddy's admin API
        on each reconcile — rotation is hot, no container restart.
      </p>
      <div className="mb-4 flex items-start gap-2 bg-sky-950/40 border border-sky-900 rounded px-3 py-2 text-xs text-sky-200">
        <span>
          Credentials are streamed to Caddy's admin API in plaintext.
          The admin endpoint lives only inside the argos_net Docker
          network and is never published to the host. See{' '}
          <a
            href="/docs/operations/persistence/"
            className="underline hover:text-sky-100"
          >
            Persistence documentation
          </a>{' '}
          for the full trust-boundary note.
        </span>
      </div>
      {loadError && (
        <div className="px-3 py-2 rounded bg-red-950/40 border border-red-900 text-red-300 text-sm">
          {loadError}
        </div>
      )}
      {providers === null && !loadError && (
        <div className="text-sm text-slate-400">loading...</div>
      )}
      {providers && providers.length === 0 && (
        <div className="text-sm text-slate-400">
          No providers in the catalogue. This should not happen in a
          normal installation — check that migrations 024/025 ran.
        </div>
      )}
      {providers && providers.length > 0 && (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-3">
          {providers.map((p) => (
            <DNSProviderCard key={p.name} provider={p} onChanged={load} />
          ))}
        </div>
      )}
    </section>
  );
}

// DNSProviderCard is one catalogue entry. Renders the enable toggle,
// the credentials form (secret fields start empty with the
// __UNCHANGED__ sentinel once the provider is configured so operators
// can flip other fields without retyping secrets), Save button, and
// inline error / success feedback.
function DNSProviderCard({
  provider,
  onChanged,
}: {
  provider: DNSProvider;
  onChanged: () => Promise<void>;
}) {
  const toasts = useToasts();
  const [enabled, setEnabled] = useState(provider.enabled);
  const [values, setValues] = useState<Record<string, string>>(() =>
    initialValues(provider),
  );
  const [touched, setTouched] = useState<Record<string, boolean>>({});
  const [saving, setSaving] = useState(false);
  const [lastError, setLastError] = useState<string | null>(null);
  const [reconcileWarn, setReconcileWarn] = useState<string | null>(null);

  // Refresh the local form state whenever the parent reloads (e.g.
  // after a sibling card's save bumped updated_at for this one).
  useEffect(() => {
    setEnabled(provider.enabled);
    setValues(initialValues(provider));
    setTouched({});
    setLastError(null);
    setReconcileWarn(null);
  }, [provider]);

  function setField(key: string, value: string) {
    setValues((prev) => ({ ...prev, [key]: value }));
    setTouched((prev) => ({ ...prev, [key]: true }));
  }

  async function onSubmit(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    setLastError(null);
    setReconcileWarn(null);

    // Decide whether we are sending credentials. We only send them
    // when the caller touched at least one field OR when the provider
    // has no credentials yet (first-time setup -- the caller must
    // fill in every required field). Toggle-enabled-only saves skip
    // the credentials payload entirely.
    const sendCreds = provider.configured
      ? Object.keys(touched).length > 0
      : enabled; // first-time enable requires credentials

    const body: { enabled: boolean; credentials?: Record<string, string> } = {
      enabled,
    };
    if (sendCreds) {
      // Required-field client-side gate. The backend validates too
      // (same catalogue), but catching here keeps a clean UX.
      for (const f of provider.fields) {
        if (!f.required) continue;
        const v = values[f.key] ?? '';
        const isPlaceholder =
          f.secret && !touched[f.key] && provider.configured && v === DNS_PROVIDER_UNCHANGED;
        if (isPlaceholder) continue;
        if (v.trim() === '') {
          setLastError(`${f.label} is required`);
          return;
        }
      }
      const creds: Record<string, string> = {};
      for (const f of provider.fields) {
        const v = values[f.key] ?? '';
        // Secret fields that were NOT edited send the sentinel so the
        // backend preserves the existing ciphertext. Non-secret fields
        // always send their (possibly empty) value.
        if (f.secret && !touched[f.key] && provider.configured) {
          creds[f.key] = DNS_PROVIDER_UNCHANGED;
        } else {
          creds[f.key] = v;
        }
      }
      body.credentials = creds;
    }

    setSaving(true);
    try {
      const res = await api.updateDNSProvider(provider.name, body);
      if (isReconcileError(res)) {
        setReconcileWarn(res.reconcile_error);
        toasts.push(
          `${provider.display_name}: saved but reconcile failed`,
          'error',
        );
      } else {
        toasts.push(`${provider.display_name} saved`, 'success');
      }
      await onChanged();
    } catch (err) {
      const msg = err instanceof ApiError ? err.message : 'save failed';
      setLastError(msg);
      toasts.push(msg, 'error');
    } finally {
      setSaving(false);
    }
  }

  return (
    <div className="bg-slate-950/40 border border-slate-800 rounded-lg p-4">
      <div className="flex items-start justify-between gap-3 mb-3">
        <div>
          <h3 className="font-semibold text-slate-100">{provider.display_name}</h3>
          <div className="flex items-center gap-2 mt-1 text-xs">
            {provider.configured ? (
              <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded bg-emerald-950/60 border border-emerald-900 text-emerald-300">
                Configured
              </span>
            ) : (
              <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded bg-amber-950/60 border border-amber-900 text-amber-300">
                Not configured
              </span>
            )}
            {provider.enabled && (
              <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded bg-sky-950/60 border border-sky-900 text-sky-300">
                Enabled
              </span>
            )}
          </div>
        </div>
        <label className="inline-flex items-center gap-2 text-sm cursor-pointer select-none">
          <input
            type="checkbox"
            checked={enabled}
            onChange={(e) => setEnabled(e.target.checked)}
            className="accent-sky-600"
          />
          <span className="text-slate-300">Enabled</span>
        </label>
      </div>

      <form onSubmit={onSubmit} className="space-y-3 text-sm">
        {enabled &&
          provider.fields.map((f) => (
            <DNSProviderFieldInput
              key={f.key}
              field={f}
              value={values[f.key] ?? ''}
              touched={touched[f.key] === true}
              providerConfigured={provider.configured}
              onChange={(v) => setField(f.key, v)}
              onReveal={() => {
                // When the operator clicks "edit" on a secret field,
                // clear the sentinel so they can type the new value.
                setValues((prev) => ({ ...prev, [f.key]: '' }));
                setTouched((prev) => ({ ...prev, [f.key]: true }));
              }}
            />
          ))}

        {lastError && (
          <div className="px-3 py-2 rounded bg-red-950/40 border border-red-900 text-red-300 text-xs">
            {lastError}
          </div>
        )}
        {reconcileWarn && (
          <div className="px-3 py-2 rounded bg-amber-950/40 border border-amber-900 text-amber-200 text-xs">
            Saved to DB, but the next Caddy reconcile failed:
            <pre className="mt-1 whitespace-pre-wrap font-mono text-[11px]">
              {reconcileWarn}
            </pre>
          </div>
        )}

        <div className="flex items-center justify-between pt-1">
          <button
            type="submit"
            disabled={saving}
            className="px-3 py-1.5 rounded bg-sky-600 hover:bg-sky-500 disabled:bg-slate-700 text-sm font-medium"
          >
            {saving ? 'saving...' : 'Save'}
          </button>
          {provider.docs_url && (
            <a
              href={provider.docs_url}
              target="_blank"
              rel="noreferrer noopener"
              className="text-xs text-sky-400 hover:text-sky-300 underline"
            >
              How to get credentials →
            </a>
          )}
        </div>
      </form>
    </div>
  );
}

// initialValues seeds the form. Secret fields for an already-configured
// provider start as the __UNCHANGED__ sentinel so the operator sees an
// obvious "keep current" marker and can flip it to edit mode.
function initialValues(p: DNSProvider): Record<string, string> {
  const out: Record<string, string> = {};
  for (const f of p.fields) {
    if (f.secret && p.configured) {
      out[f.key] = DNS_PROVIDER_UNCHANGED;
    } else {
      out[f.key] = '';
    }
  }
  return out;
}

function DNSProviderFieldInput({
  field,
  value,
  touched,
  providerConfigured,
  onChange,
  onReveal,
}: {
  field: DNSProviderField;
  value: string;
  touched: boolean;
  providerConfigured: boolean;
  onChange: (v: string) => void;
  onReveal: () => void;
}) {
  const isPlaceholderedSecret =
    field.secret && !touched && providerConfigured && value === DNS_PROVIDER_UNCHANGED;

  return (
    <div>
      <label className="block text-slate-300 mb-1">
        {field.label}
        {field.required && <span className="text-red-400 ml-1">*</span>}
      </label>
      {isPlaceholderedSecret ? (
        <div className="flex items-center gap-2">
          <input
            type="password"
            value="__________"
            readOnly
            className="flex-1 px-3 py-2 rounded bg-slate-800 border border-slate-700 font-mono text-slate-500"
          />
          <button
            type="button"
            onClick={onReveal}
            className="px-3 py-1.5 rounded border border-slate-700 hover:bg-slate-800 text-xs"
          >
            Edit
          </button>
        </div>
      ) : (
        <input
          type={field.secret ? 'password' : 'text'}
          value={value}
          onChange={(e) => onChange(e.target.value)}
          placeholder={field.placeholder}
          autoComplete="off"
          className="w-full px-3 py-2 rounded bg-slate-800 border border-slate-700 focus:outline-none focus:border-sky-500 font-mono"
        />
      )}
    </div>
  );
}
