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
