import { FormEvent, useCallback, useEffect, useState } from 'react';
import { ApiError, Setting, api } from '../api/client';
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
    <div className="p-6 max-w-2xl mx-auto">
      <h1 className="text-2xl font-semibold mb-4">Settings</h1>

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
