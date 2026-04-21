import { FormEvent, useCallback, useEffect, useState } from 'react';
import { ApiError, Setting, SystemHealth, api } from '../api/client';
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
