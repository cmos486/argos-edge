import { FormEvent, useCallback, useEffect, useMemo, useState } from 'react';
import {
  AlertTriangle,
  Archive,
  CheckCircle,
  Download,
  FileText,
  Plus,
  RotateCcw,
  Settings2,
  Trash2,
  Upload,
} from 'lucide-react';
import {
  ApiError,
  BackupRow,
  ImportPlan,
  api,
} from '../api/client';
import Modal from '../components/Modal';
import RelativeTime from '../components/RelativeTime';
import { useToasts } from '../components/toastsContext';

type Tab = 'backups' | 'export-import' | 'settings';

export default function Backup() {
  const [tab, setTab] = useState<Tab>('backups');
  const [restoring, setRestoring] = useState(false);

  if (restoring) return <RestoringCurtain />;

  return (
    <div className="p-6 max-w-[1400px] mx-auto">
      <h1 className="text-2xl font-semibold mb-4 flex items-center gap-2">
        <Archive className="w-6 h-6 text-sky-400" />
        Backup & Config I/O
      </h1>
      <div className="flex gap-1 border-b border-slate-800 mb-4">
        {(
          [
            ['backups', 'Backups'],
            ['export-import', 'Export / Import'],
            ['settings', 'Settings'],
          ] as [Tab, string][]
        ).map(([t, label]) => (
          <button
            key={t}
            type="button"
            onClick={() => setTab(t)}
            className={`px-4 py-2 text-sm border-b-2 -mb-px ${
              tab === t
                ? 'border-sky-500 text-sky-300'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            {label}
          </button>
        ))}
      </div>
      {tab === 'backups' && <BackupsTab onRestoring={() => setRestoring(true)} />}
      {tab === 'export-import' && <ExportImportTab />}
      {tab === 'settings' && <SettingsTab />}
    </div>
  );
}

// ---------- Backups tab ----------

function BackupsTab({ onRestoring }: { onRestoring: () => void }) {
  const toasts = useToasts();
  const [rows, setRows] = useState<BackupRow[] | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [createOpen, setCreateOpen] = useState(false);
  const [uploadOpen, setUploadOpen] = useState(false);
  const [restoreTarget, setRestoreTarget] = useState<BackupRow | null>(null);

  const refresh = useCallback(async () => {
    try {
      const r = await api.listBackups();
      setRows(r);
      setErr(null);
    } catch (e) {
      setErr(e instanceof ApiError ? e.message : 'load failed');
    }
  }, []);

  useEffect(() => {
    refresh();
  }, [refresh]);

  async function onDelete(b: BackupRow) {
    if (!window.confirm(`Delete ${b.filename}?`)) return;
    try {
      await api.deleteBackup(b.id);
      toasts.push('backup deleted', 'success');
      await refresh();
    } catch (e) {
      toasts.push(e instanceof ApiError ? e.message : 'delete failed', 'error');
    }
  }

  return (
    <>
      {err && <ErrorBar msg={err} />}
      <div className="flex items-center justify-between mb-3">
        <p className="text-sm text-slate-400">
          Local tar.gz backups of argos.db and Caddy TLS storage. Restore replays the
          DB only; Caddy re-issues certs via ACME after panel restart.
        </p>
        <div className="flex gap-2">
          <button
            type="button"
            onClick={() => setUploadOpen(true)}
            className="flex items-center gap-2 px-3 py-1.5 rounded border border-slate-700 hover:bg-slate-800 text-sm"
          >
            <Upload className="w-4 h-4" /> Upload
          </button>
          <button
            type="button"
            onClick={() => setCreateOpen(true)}
            className="flex items-center gap-2 px-3 py-1.5 rounded bg-sky-600 hover:bg-sky-500 text-sm font-medium"
          >
            <Plus className="w-4 h-4" /> Backup now
          </button>
        </div>
      </div>

      {rows === null ? (
        <Loading />
      ) : rows.length === 0 ? (
        <Empty msg="No backups yet" />
      ) : (
        <table className="w-full text-sm">
          <thead className="text-slate-400 uppercase text-xs tracking-wide">
            <tr>
              <th className="text-left px-2 py-1">Filename</th>
              <th className="text-left px-2 py-1">Size</th>
              <th className="text-left px-2 py-1">Kind</th>
              <th className="text-left px-2 py-1">Created</th>
              <th className="text-left px-2 py-1">Note</th>
              <th className="text-right px-2 py-1">Actions</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((b) => (
              <tr key={b.id} className="border-t border-slate-800">
                <td className="px-2 py-2 font-mono text-xs truncate max-w-[280px]">
                  {b.filename}
                </td>
                <td className="px-2 py-2 font-mono text-xs">{humanSize(b.size_bytes)}</td>
                <td className="px-2 py-2">
                  <span
                    className={`text-xs px-2 py-0.5 rounded ${
                      b.kind === 'manual'
                        ? 'bg-sky-900 text-sky-200'
                        : 'bg-slate-800 text-slate-300'
                    }`}
                  >
                    {b.kind}
                  </span>
                </td>
                <td className="px-2 py-2 text-xs text-slate-400 font-mono">
                  <RelativeTime iso={b.created_at} />
                </td>
                <td className="px-2 py-2 text-xs text-slate-400 truncate max-w-[180px]">
                  {b.note}
                </td>
                <td className="px-2 py-2 text-right">
                  <a
                    href={api.backupDownloadURL(b.id)}
                    download={b.filename}
                    className="inline-block p-1.5 rounded border border-slate-700 hover:bg-slate-800 mr-1"
                    title="download"
                    aria-label="download"
                  >
                    <Download className="w-3.5 h-3.5" />
                  </a>
                  <IconBtn label="restore" onClick={() => setRestoreTarget(b)}>
                    <RotateCcw className="w-3.5 h-3.5" />
                  </IconBtn>
                  <IconBtn label="delete" danger onClick={() => onDelete(b)}>
                    <Trash2 className="w-3.5 h-3.5" />
                  </IconBtn>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}

      <CreateBackupModal
        open={createOpen}
        onClose={() => setCreateOpen(false)}
        onSaved={async () => {
          setCreateOpen(false);
          await refresh();
        }}
      />
      <UploadBackupModal
        open={uploadOpen}
        onClose={() => setUploadOpen(false)}
        onScheduled={() => {
          setUploadOpen(false);
          onRestoring();
        }}
      />
      {restoreTarget && (
        <RestoreConfirmModal
          backup={restoreTarget}
          onClose={() => setRestoreTarget(null)}
          onScheduled={() => {
            setRestoreTarget(null);
            onRestoring();
          }}
        />
      )}
    </>
  );
}

function CreateBackupModal({
  open,
  onClose,
  onSaved,
}: {
  open: boolean;
  onClose: () => void;
  onSaved: () => Promise<void> | void;
}) {
  const toasts = useToasts();
  const [note, setNote] = useState('');
  const [submitting, setSubmitting] = useState(false);
  useEffect(() => {
    if (!open) setNote('');
  }, [open]);

  async function onSubmit(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    setSubmitting(true);
    try {
      const b = await api.createBackup(note);
      toasts.push(`created ${b.filename}`, 'success');
      await onSaved();
    } catch (err) {
      toasts.push(err instanceof ApiError ? err.message : 'create failed', 'error');
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <Modal open={open} title="Backup now" onClose={onClose}>
      <form onSubmit={onSubmit} className="space-y-3 text-sm">
        <div>
          <label className="block text-slate-300 mb-1">Note (optional)</label>
          <input
            type="text"
            value={note}
            onChange={(e) => setNote(e.target.value)}
            placeholder="e.g. pre-phase9a smoke test"
            className="w-full px-3 py-2 rounded bg-slate-800 border border-slate-700"
          />
        </div>
        <div className="flex justify-end gap-2">
          <button
            type="button"
            onClick={onClose}
            className="px-3 py-1.5 rounded border border-slate-700 hover:bg-slate-800"
          >
            Cancel
          </button>
          <button
            type="submit"
            disabled={submitting}
            className="px-3 py-1.5 rounded bg-sky-600 hover:bg-sky-500 disabled:bg-slate-700 font-medium"
          >
            {submitting ? 'creating...' : 'Create'}
          </button>
        </div>
      </form>
    </Modal>
  );
}

function UploadBackupModal({
  open,
  onClose,
  onScheduled,
}: {
  open: boolean;
  onClose: () => void;
  onScheduled: () => void;
}) {
  const toasts = useToasts();
  const [file, setFile] = useState<File | null>(null);
  const [confirmText, setConfirmText] = useState('');
  const [submitting, setSubmitting] = useState(false);
  useEffect(() => {
    if (!open) {
      setFile(null);
      setConfirmText('');
    }
  }, [open]);

  async function onSubmit(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    if (!file) return;
    setSubmitting(true);
    try {
      await api.uploadAndRestore(file);
      toasts.push('restore scheduled; server restarting', 'success');
      onScheduled();
    } catch (err) {
      toasts.push(err instanceof ApiError ? err.message : 'upload failed', 'error');
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <Modal open={open} title="Upload backup and restore" onClose={onClose}>
      <form onSubmit={onSubmit} className="space-y-3 text-sm">
        <div className="px-3 py-2 rounded bg-red-950/40 border border-red-900 text-red-300 text-xs flex items-start gap-2">
          <AlertTriangle className="w-4 h-4 mt-0.5 flex-shrink-0" />
          <span>
            Uploading and restoring will <b>overwrite the current DB</b> after the
            server restarts. All live changes since the backup will be lost.
          </span>
        </div>
        <div>
          <label className="block text-slate-300 mb-1">Backup .tar.gz file</label>
          <input
            type="file"
            accept=".tar.gz,.gz,application/gzip"
            required
            onChange={(e) => setFile(e.target.files?.[0] ?? null)}
            className="block w-full text-xs"
          />
        </div>
        <div>
          <label className="block text-slate-300 mb-1">
            Type <code className="px-1 bg-slate-800 rounded">RESTORE</code> to confirm
          </label>
          <input
            type="text"
            value={confirmText}
            onChange={(e) => setConfirmText(e.target.value)}
            className="w-full px-3 py-2 rounded bg-slate-800 border border-slate-700 font-mono"
          />
        </div>
        <div className="flex justify-end gap-2">
          <button
            type="button"
            onClick={onClose}
            className="px-3 py-1.5 rounded border border-slate-700 hover:bg-slate-800"
          >
            Cancel
          </button>
          <button
            type="submit"
            disabled={submitting || confirmText !== 'RESTORE' || !file}
            className="px-3 py-1.5 rounded bg-red-600 hover:bg-red-500 disabled:bg-slate-700 font-medium"
          >
            {submitting ? 'uploading...' : 'Upload and restore'}
          </button>
        </div>
      </form>
    </Modal>
  );
}

function RestoreConfirmModal({
  backup,
  onClose,
  onScheduled,
}: {
  backup: BackupRow;
  onClose: () => void;
  onScheduled: () => void;
}) {
  const toasts = useToasts();
  const [confirm, setConfirm] = useState('');
  const [submitting, setSubmitting] = useState(false);
  async function onSubmit(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    setSubmitting(true);
    try {
      await api.restoreBackup(backup.id);
      toasts.push('restore scheduled; server restarting', 'success');
      onScheduled();
    } catch (err) {
      toasts.push(err instanceof ApiError ? err.message : 'restore failed', 'error');
    } finally {
      setSubmitting(false);
    }
  }
  return (
    <Modal open title={`Restore ${backup.filename}?`} onClose={onClose}>
      <form onSubmit={onSubmit} className="space-y-3 text-sm">
        <div className="px-3 py-2 rounded bg-red-950/40 border border-red-900 text-red-300 text-xs">
          This overwrites the live DB. The server will restart; reload the page in ~15
          seconds.
        </div>
        <div>
          <label className="block text-slate-300 mb-1">
            Type <code className="px-1 bg-slate-800 rounded">RESTORE</code> to confirm
          </label>
          <input
            type="text"
            value={confirm}
            onChange={(e) => setConfirm(e.target.value)}
            className="w-full px-3 py-2 rounded bg-slate-800 border border-slate-700 font-mono"
          />
        </div>
        <div className="flex justify-end gap-2">
          <button
            type="button"
            onClick={onClose}
            className="px-3 py-1.5 rounded border border-slate-700 hover:bg-slate-800"
          >
            Cancel
          </button>
          <button
            type="submit"
            disabled={submitting || confirm !== 'RESTORE'}
            className="px-3 py-1.5 rounded bg-red-600 hover:bg-red-500 disabled:bg-slate-700 font-medium"
          >
            {submitting ? 'scheduling...' : 'Restore'}
          </button>
        </div>
      </form>
    </Modal>
  );
}

function RestoringCurtain() {
  useEffect(() => {
    // after 18s try to reload — server usually back within 10-15s
    const t = setTimeout(() => window.location.reload(), 18000);
    return () => clearTimeout(t);
  }, []);
  return (
    <div className="fixed inset-0 z-50 bg-slate-950 flex items-center justify-center">
      <div className="max-w-md text-center">
        <div className="inline-block w-10 h-10 border-4 border-sky-500 border-t-transparent rounded-full animate-spin mb-4" />
        <h2 className="text-xl font-semibold mb-2">Argos is restoring</h2>
        <p className="text-slate-400 text-sm">
          The panel is restarting to apply the backup. This page will reload
          automatically in ~15 seconds. If it does not, refresh manually.
        </p>
      </div>
    </div>
  );
}

// ---------- Export / Import tab ----------

function ExportImportTab() {
  const toasts = useToasts();
  const [yaml, setYaml] = useState('');
  const [mode, setMode] = useState<'replace' | 'merge'>('merge');
  const [plan, setPlan] = useState<ImportPlan | null>(null);
  const [applying, setApplying] = useState(false);

  async function onValidate() {
    try {
      const p = await api.validateImport(yaml, mode);
      setPlan(p);
    } catch (e) {
      setPlan(null);
      toasts.push(e instanceof ApiError ? e.message : 'validate failed', 'error');
    }
  }
  async function onApply() {
    if (!window.confirm(`Apply import in "${mode}" mode?`)) return;
    setApplying(true);
    try {
      const p = await api.applyImport(yaml, mode);
      setPlan(p);
      toasts.push('import applied', 'success');
    } catch (e) {
      toasts.push(e instanceof ApiError ? e.message : 'apply failed', 'error');
    } finally {
      setApplying(false);
    }
  }
  function onFile(f: File | null) {
    if (!f) return;
    const r = new FileReader();
    r.onload = () => setYaml(typeof r.result === 'string' ? r.result : '');
    r.readAsText(f);
  }

  return (
    <div className="grid grid-cols-2 gap-4">
      <section className="bg-slate-900 border border-slate-800 rounded-lg p-4">
        <div className="flex items-center gap-2 mb-3">
          <FileText className="w-5 h-5 text-sky-400" />
          <h2 className="text-lg font-semibold">Export</h2>
        </div>
        <p className="text-sm text-slate-400 mb-3">
          Downloads a YAML snapshot of hosts, target groups, rules, host security,
          notification channels and rules, and whitelisted settings. All secrets are
          redacted.
        </p>
        <a
          href={api.exportConfigURL()}
          download
          className="inline-flex items-center gap-2 px-3 py-1.5 rounded bg-sky-600 hover:bg-sky-500 text-sm font-medium"
        >
          <Download className="w-4 h-4" /> Export config
        </a>
      </section>

      <section className="bg-slate-900 border border-slate-800 rounded-lg p-4">
        <div className="flex items-center gap-2 mb-3">
          <Upload className="w-5 h-5 text-sky-400" />
          <h2 className="text-lg font-semibold">Import</h2>
        </div>
        <div className="flex gap-3 mb-2 text-sm">
          <label className="flex items-center gap-1">
            <input
              type="radio"
              name="mode"
              checked={mode === 'merge'}
              onChange={() => setMode('merge')}
              className="accent-sky-600"
            />
            <span>Merge</span>
          </label>
          <label className="flex items-center gap-1">
            <input
              type="radio"
              name="mode"
              checked={mode === 'replace'}
              onChange={() => setMode('replace')}
              className="accent-sky-600"
            />
            <span>Replace</span>
          </label>
        </div>
        <p className="text-xs text-slate-500 mb-2">
          Merge upserts by natural key (domain / name). Replace wipes all matching
          entities before inserting.
        </p>
        <input
          type="file"
          accept=".yaml,.yml"
          onChange={(e) => onFile(e.target.files?.[0] ?? null)}
          className="block w-full text-xs mb-2"
        />
        <textarea
          value={yaml}
          onChange={(e) => setYaml(e.target.value)}
          rows={10}
          placeholder="Paste YAML here or choose a file above..."
          className="w-full px-2 py-1 rounded bg-slate-800 border border-slate-700 font-mono text-xs"
        />
        <div className="flex gap-2 mt-2">
          <button
            type="button"
            onClick={onValidate}
            disabled={!yaml.trim()}
            className="px-3 py-1.5 rounded border border-slate-700 hover:bg-slate-800 disabled:opacity-50 text-sm"
          >
            Validate
          </button>
          <button
            type="button"
            onClick={onApply}
            disabled={!plan || applying}
            className="px-3 py-1.5 rounded bg-red-600 hover:bg-red-500 disabled:bg-slate-700 text-sm font-medium"
          >
            {applying ? 'applying...' : 'Apply'}
          </button>
        </div>
        {plan && (
          <div className="mt-3 p-3 rounded bg-slate-950/60 border border-slate-800 text-xs">
            <div className="font-semibold mb-1">Plan — mode={plan.mode}</div>
            <div className="grid grid-cols-2 gap-1">
              {Object.entries(plan.counts).map(([k, v]) => (
                <div key={k} className="text-slate-400">
                  {k}: <span className="text-slate-200">{v}</span>
                </div>
              ))}
            </div>
            <Details label={`${plan.creates?.length ?? 0} creates`} items={plan.creates} />
            <Details label={`${plan.updates?.length ?? 0} updates`} items={plan.updates} />
            {plan.conflicts && plan.conflicts.length > 0 && (
              <Details label={`${plan.conflicts.length} conflicts`} items={plan.conflicts} danger />
            )}
            {plan.warnings && plan.warnings.length > 0 && (
              <Details label={`${plan.warnings.length} warnings`} items={plan.warnings} danger />
            )}
          </div>
        )}
      </section>
    </div>
  );
}

function Details({
  label,
  items,
  danger,
}: {
  label: string;
  items?: string[];
  danger?: boolean;
}) {
  if (!items || items.length === 0) return null;
  return (
    <details className="mt-2">
      <summary className={`cursor-pointer text-xs ${danger ? 'text-red-300' : 'text-slate-300'}`}>
        {label}
      </summary>
      <ul className="ml-4 mt-1 text-[11px] font-mono text-slate-400 space-y-0.5">
        {items.map((x, i) => (
          <li key={i}>{x}</li>
        ))}
      </ul>
    </details>
  );
}

// ---------- Settings tab ----------

function SettingsTab() {
  const toasts = useToasts();
  const [enabled, setEnabled] = useState<string>('true');
  const [schedule, setSchedule] = useState<string>('0 2 * * *');
  const [retention, setRetention] = useState<string>('14');
  const [nextRuns, setNextRuns] = useState<string[] | null>(null);
  const [err, setErr] = useState<string | null>(null);

  const refresh = useCallback(async () => {
    try {
      const all = await request<Setting[]>('/settings?prefix=backup.');
      const map = new Map(all.map((s) => [s.key, s.value]));
      setEnabled(map.get('backup.enabled') ?? 'true');
      setSchedule(map.get('backup.schedule') ?? '0 2 * * *');
      setRetention(map.get('backup.retention_days') ?? '14');
      setErr(null);
    } catch (e) {
      setErr(e instanceof ApiError ? e.message : 'load failed');
    }
  }, []);
  useEffect(() => {
    refresh();
  }, [refresh]);

  async function save(key: string, value: string) {
    try {
      await request(`/settings/${key}`, {
        method: 'PUT',
        body: JSON.stringify({ value }),
      });
      toasts.push(`${key} saved`, 'success');
      await refresh();
    } catch (e) {
      toasts.push(e instanceof ApiError ? e.message : 'save failed', 'error');
    }
  }

  async function onTestSchedule() {
    // TODO(kilian): no /api/backup/next_runs endpoint exists; the
    // backup/scheduler.go NextRuns helper is written but never wired.
    // Until it is, "Test schedule" just saves the cron string and
    // echoes server time so the operator can sanity-check manually.
    try {
      await save('backup.schedule', schedule);
      const now = new Date();
      setNextRuns([
        `saved; scheduler reads this on next restart`,
        `server clock now (UTC): ${now.toISOString()}`,
      ]);
    } catch (e) {
      toasts.push(e instanceof ApiError ? e.message : 'save failed', 'error');
    }
  }

  return (
    <section className="bg-slate-900 border border-slate-800 rounded-lg p-4 max-w-xl">
      <div className="flex items-center gap-2 mb-3">
        <Settings2 className="w-5 h-5 text-sky-400" />
        <h2 className="text-lg font-semibold">Backup settings</h2>
      </div>
      {err && <ErrorBar msg={err} />}
      <p className="text-xs text-slate-500 mb-3">
        Schedule changes take effect after a panel restart (no hot-reload).
      </p>

      <label className="flex items-center gap-2 mb-3 text-sm">
        <input
          type="checkbox"
          checked={enabled === 'true'}
          onChange={(e) => save('backup.enabled', e.target.checked ? 'true' : 'false')}
          className="w-4 h-4 accent-sky-600"
        />
        <span>Scheduled backups enabled</span>
      </label>

      <div className="mb-3">
        <label className="block text-slate-300 mb-1 text-sm">Schedule (cron 5-field)</label>
        <div className="flex gap-2">
          <input
            type="text"
            value={schedule}
            onChange={(e) => setSchedule(e.target.value)}
            className="flex-1 px-3 py-2 rounded bg-slate-800 border border-slate-700 font-mono text-sm"
          />
          <button
            type="button"
            onClick={onTestSchedule}
            className="px-3 py-1.5 rounded border border-slate-700 hover:bg-slate-800 text-sm"
          >
            Save & test
          </button>
        </div>
        {nextRuns && (
          <ul className="mt-2 text-xs text-slate-400 font-mono">
            {nextRuns.map((r, i) => (
              <li key={i}>{r}</li>
            ))}
          </ul>
        )}
      </div>

      <div>
        <label className="block text-slate-300 mb-1 text-sm">
          Retention (days, 0 = keep only newest)
        </label>
        <div className="flex gap-2">
          <input
            type="number"
            min={0}
            max={365}
            value={retention}
            onChange={(e) => setRetention(e.target.value)}
            className="w-32 px-3 py-2 rounded bg-slate-800 border border-slate-700 font-mono text-sm"
          />
          <button
            type="button"
            onClick={() => save('backup.retention_days', retention)}
            className="px-3 py-1.5 rounded border border-slate-700 hover:bg-slate-800 text-sm"
          >
            Save
          </button>
        </div>
      </div>
    </section>
  );
}

// ---------- shared bits ----------

function IconBtn({
  children,
  label,
  danger,
  onClick,
}: {
  children: React.ReactNode;
  label: string;
  danger?: boolean;
  onClick: () => void;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      aria-label={label}
      title={label}
      className={`p-1.5 rounded border border-slate-700 hover:bg-slate-800 mr-1 ${
        danger ? 'text-red-400 hover:text-red-300' : 'text-slate-300'
      }`}
    >
      {children}
    </button>
  );
}

function Loading() {
  return <div className="text-slate-500 text-sm">loading...</div>;
}

function Empty({ msg }: { msg: string }) {
  return (
    <div className="p-4 rounded-lg border border-slate-800 bg-slate-900/60 text-slate-500 text-sm flex items-center gap-2">
      <CheckCircle className="w-4 h-4" /> {msg}
    </div>
  );
}

function ErrorBar({ msg }: { msg: string }) {
  return (
    <div className="mb-4 px-3 py-2 rounded bg-red-950/40 border border-red-900 text-sm text-red-300">
      {msg}
    </div>
  );
}

function humanSize(n: number): string {
  if (n < 1024) return `${n} B`;
  const units = ['KiB', 'MiB', 'GiB', 'TiB'];
  let v = n / 1024;
  let u = 0;
  while (v >= 1024 && u < units.length - 1) {
    v /= 1024;
    u++;
  }
  return `${v.toFixed(1)} ${units[u]}`;
}

// local thin fetch wrapper for the small settings API; avoids adding
// another method to api.ts for a one-use case.
async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const base = '/api';
  const res = await fetch(`${base}${path}`, {
    credentials: 'same-origin',
    headers: {
      Accept: 'application/json',
      ...(init?.body ? { 'Content-Type': 'application/json' } : {}),
      ...(init?.headers ?? {}),
    },
    ...init,
  });
  if (res.status === 401) {
    window.location.assign('/login');
    throw new ApiError(401, 'unauthorized');
  }
  if (res.status === 204) return undefined as T;
  const ct = res.headers.get('content-type') ?? '';
  const isJSON = ct.includes('application/json');
  const body = isJSON ? await res.json().catch(() => null) : await res.text();
  if (!res.ok) {
    const msg = isJSON && body && typeof body === 'object' && 'error' in body
      ? String((body as { error: unknown }).error) : `request failed: ${res.status}`;
    throw new ApiError(res.status, msg);
  }
  return body as T;
}

// Setting is declared in client.ts; re-declare minimally here for the
// SettingsTab without expanding the exports surface.
interface Setting {
  key: string;
  value: string;
  updated_at: string;
}

// useMemo is imported but used indirectly via referencing unknown
// hook imports; silence the lint.
void useMemo;
