import { FormEvent, useCallback, useEffect, useState } from 'react';
import { Link, useNavigate, useParams } from 'react-router-dom';
import { ArrowLeft, Pencil, Plus, Power, Trash2 } from 'lucide-react';
import { ApiError, Target, TargetGroup, TargetGroupInput, api } from '../api/client';
import Modal from '../components/Modal';
import TargetGroupForm from '../components/TargetGroupForm';
import { TargetGroupFormValue } from '../components/targetGroupFormValue';
import { useToasts } from '../components/toastsContext';

type TargetDraft = {
  id?: number;
  host: string;
  port: number;
  weight: number;
};

export default function TargetGroupDetail() {
  const { id } = useParams();
  const navigate = useNavigate();
  const toasts = useToasts();
  const tgId = Number(id);

  const [tg, setTg] = useState<TargetGroup | null>(null);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [inUseCount, setInUseCount] = useState<number>(0);

  const [editOpen, setEditOpen] = useState(false);
  const [editForm, setEditForm] = useState<TargetGroupFormValue | null>(null);
  const [editError, setEditError] = useState<string | null>(null);
  const [savingEdit, setSavingEdit] = useState(false);

  const [targetOpen, setTargetOpen] = useState(false);
  const [targetDraft, setTargetDraft] = useState<TargetDraft>({
    host: '',
    port: 80,
    weight: 1,
  });
  const [targetError, setTargetError] = useState<string | null>(null);
  const [savingTarget, setSavingTarget] = useState(false);

  const refresh = useCallback(async () => {
    try {
      const fresh = await api.getTargetGroup(tgId);
      setTg(fresh);
      setLoadError(null);
      try {
        const hosts = await api.listHosts();
        setInUseCount(hosts.filter((h) => h.target_group_id === tgId).length);
      } catch {
        setInUseCount(0);
      }
    } catch (err) {
      setLoadError(err instanceof ApiError ? err.message : 'load failed');
    }
  }, [tgId]);

  useEffect(() => {
    if (!Number.isFinite(tgId) || tgId <= 0) return;
    refresh();
  }, [tgId, refresh]);

  function openEdit() {
    if (!tg) return;
    setEditForm({
      name: tg.name,
      protocol: tg.protocol,
      verify_tls: tg.verify_tls,
      algorithm: tg.algorithm,
      health_check_enabled: tg.health_check_enabled,
      health_check_path: tg.health_check_path,
      health_check_method: tg.health_check_method,
      health_check_expect_status: tg.health_check_expect_status,
      health_check_interval_seconds: tg.health_check_interval_seconds,
      health_check_timeout_seconds: tg.health_check_timeout_seconds,
      health_check_fails_to_unhealthy: tg.health_check_fails_to_unhealthy,
      health_check_passes_to_healthy: tg.health_check_passes_to_healthy,
    });
    setEditError(null);
    setEditOpen(true);
  }

  async function onEditSubmit(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    if (!editForm) return;
    setSavingEdit(true);
    setEditError(null);
    const payload: TargetGroupInput = { ...editForm };
    delete payload.targets;
    try {
      await api.updateTargetGroup(tgId, payload);
      toasts.push(`updated ${payload.name}`, 'success');
      setEditOpen(false);
      await refresh();
    } catch (err) {
      setEditError(err instanceof ApiError ? err.message : 'save failed');
    } finally {
      setSavingEdit(false);
    }
  }

  async function onDeleteTG() {
    if (!tg) return;
    if (!window.confirm(`Delete target group "${tg.name}"? This cannot be undone.`)) return;
    try {
      await api.deleteTargetGroup(tgId);
      toasts.push(`deleted ${tg.name}`, 'success');
      navigate('/target-groups');
    } catch (err) {
      toasts.push(err instanceof ApiError ? err.message : 'delete failed', 'error');
    }
  }

  function openAddTarget() {
    setTargetDraft({ host: '', port: tg?.protocol === 'https' ? 443 : 80, weight: 1 });
    setTargetError(null);
    setTargetOpen(true);
  }

  async function onAddTargetSubmit(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    setSavingTarget(true);
    setTargetError(null);
    try {
      await api.addTarget(tgId, {
        host: targetDraft.host,
        port: targetDraft.port,
        weight: targetDraft.weight,
      });
      toasts.push(`added ${targetDraft.host}:${targetDraft.port}`, 'success');
      setTargetOpen(false);
      await refresh();
    } catch (err) {
      setTargetError(err instanceof ApiError ? err.message : 'add failed');
    } finally {
      setSavingTarget(false);
    }
  }

  async function onToggleTarget(t: Target) {
    try {
      await api.toggleTarget(tgId, t.id);
      toasts.push(`${t.host}:${t.port} ${t.enabled ? 'disabled' : 'enabled'}`, 'success');
      await refresh();
    } catch (err) {
      toasts.push(err instanceof ApiError ? err.message : 'toggle failed', 'error');
    }
  }

  async function onDeleteTarget(t: Target) {
    if (!window.confirm(`Remove ${t.host}:${t.port} from this group?`)) return;
    try {
      await api.deleteTarget(tgId, t.id);
      toasts.push(`removed ${t.host}:${t.port}`, 'success');
      await refresh();
    } catch (err) {
      toasts.push(err instanceof ApiError ? err.message : 'delete failed', 'error');
    }
  }

  if (!Number.isFinite(tgId) || tgId <= 0) {
    return <div className="p-6 text-red-400">invalid target group id</div>;
  }

  return (
    <div className="p-6 max-w-5xl mx-auto">
      <Link
        to="/target-groups"
        className="inline-flex items-center gap-1 text-slate-400 hover:text-slate-200 text-sm mb-3"
      >
        <ArrowLeft className="w-4 h-4" />
        Target groups
      </Link>

      {loadError && (
        <div className="mb-4 px-3 py-2 rounded bg-red-950/40 border border-red-900 text-sm text-red-300">
          {loadError}
        </div>
      )}

      {tg && (
        <>
          <div className="flex items-center justify-between mb-3">
            <h1 className="text-2xl font-semibold font-mono">{tg.name}</h1>
            <div className="flex items-center gap-2">
              <button
                type="button"
                onClick={openEdit}
                className="flex items-center gap-1 px-3 py-1.5 rounded border border-slate-700 hover:bg-slate-800 text-sm"
              >
                <Pencil className="w-4 h-4" /> Edit
              </button>
              <button
                type="button"
                onClick={onDeleteTG}
                disabled={inUseCount > 0}
                title={inUseCount > 0 ? `In use by ${inUseCount} hosts` : 'Delete'}
                className="flex items-center gap-1 px-3 py-1.5 rounded border border-red-800 text-red-300 hover:bg-red-950 disabled:opacity-40 disabled:cursor-not-allowed text-sm"
              >
                <Trash2 className="w-4 h-4" /> Delete
              </button>
            </div>
          </div>

          <div className="bg-slate-900 border border-slate-800 rounded-lg p-4 mb-6 text-sm">
            <dl className="grid grid-cols-2 md:grid-cols-3 gap-3">
              <Info label="Protocol">
                {tg.protocol}
                {tg.protocol === 'https' && !tg.verify_tls && (
                  <span className="ml-2 text-xs px-2 py-0.5 rounded bg-amber-950 text-amber-300 border border-amber-800">
                    TLS not verified
                  </span>
                )}
              </Info>
              <Info label="Algorithm">{tg.algorithm}</Info>
              <Info label="Health check">
                {tg.health_check_enabled
                  ? `${tg.health_check_method} ${tg.health_check_path} every ${tg.health_check_interval_seconds}s (expect ${tg.health_check_expect_status})`
                  : 'passive only'}
              </Info>
              <Info label="Targets">
                {tg.targets_enabled_count} enabled / {tg.targets_count} total
              </Info>
              <Info label="Used by hosts">
                {inUseCount}
              </Info>
              <Info label="Updated">
                {new Date(tg.updated_at).toLocaleString()}
              </Info>
            </dl>
          </div>

          <div className="flex items-center justify-between mb-2">
            <h2 className="text-lg font-semibold">Targets</h2>
            <button
              type="button"
              onClick={openAddTarget}
              className="flex items-center gap-2 px-3 py-1.5 rounded bg-sky-600 hover:bg-sky-500 text-sm font-medium"
            >
              <Plus className="w-4 h-4" />
              Add target
            </button>
          </div>

          <div className="bg-slate-900 border border-slate-800 rounded-lg overflow-hidden">
            <table className="w-full text-sm">
              <thead className="bg-slate-950/60 text-slate-400 uppercase text-xs tracking-wide">
                <tr>
                  <th className="text-left px-4 py-2">Host</th>
                  <th className="text-left px-4 py-2">Port</th>
                  <th className="text-left px-4 py-2">Weight</th>
                  <th className="text-left px-4 py-2">Enabled</th>
                  <th className="text-right px-4 py-2">Actions</th>
                </tr>
              </thead>
              <tbody>
                {(tg.targets ?? []).length === 0 && (
                  <tr>
                    <td colSpan={5} className="px-4 py-4 text-slate-500">
                      no targets yet.
                    </td>
                  </tr>
                )}
                {tg.targets?.map((t) => (
                  <tr key={t.id} className="border-t border-slate-800">
                    <td className="px-4 py-2 font-mono">{t.host}</td>
                    <td className="px-4 py-2 font-mono">{t.port}</td>
                    <td className="px-4 py-2 font-mono">{t.weight}</td>
                    <td className="px-4 py-2">
                      <span
                        className={`text-xs px-2 py-0.5 rounded ${
                          t.enabled
                            ? 'bg-emerald-900 text-emerald-200'
                            : 'bg-slate-800 text-slate-400'
                        }`}
                      >
                        {t.enabled ? 'on' : 'off'}
                      </span>
                    </td>
                    <td className="px-4 py-2 text-right">
                      <div className="inline-flex items-center gap-1">
                        <IconButton label="toggle" onClick={() => onToggleTarget(t)}>
                          <Power className="w-4 h-4" />
                        </IconButton>
                        <IconButton label="delete" onClick={() => onDeleteTarget(t)} danger>
                          <Trash2 className="w-4 h-4" />
                        </IconButton>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </>
      )}

      <Modal open={editOpen} title="Edit target group" onClose={() => setEditOpen(false)}>
        {editForm && (
          <form onSubmit={onEditSubmit}>
            <TargetGroupForm value={editForm} onChange={setEditForm} />
            {editError && (
              <div className="mt-3 px-3 py-2 rounded bg-red-950/40 border border-red-900 text-red-300 text-sm">
                {editError}
              </div>
            )}
            <div className="flex justify-end gap-2 pt-3">
              <button
                type="button"
                onClick={() => setEditOpen(false)}
                className="px-3 py-1.5 rounded border border-slate-700 hover:bg-slate-800 text-sm"
              >
                Cancel
              </button>
              <button
                type="submit"
                disabled={savingEdit}
                className="px-3 py-1.5 rounded bg-sky-600 hover:bg-sky-500 disabled:bg-slate-700 text-sm font-medium"
              >
                {savingEdit ? 'saving...' : 'Save'}
              </button>
            </div>
          </form>
        )}
      </Modal>

      <Modal open={targetOpen} title="Add target" onClose={() => setTargetOpen(false)}>
        <form onSubmit={onAddTargetSubmit} className="space-y-3 text-sm">
          <div>
            <label className="block text-slate-300 mb-1">Host</label>
            <input
              type="text"
              required
              value={targetDraft.host}
              onChange={(e) => setTargetDraft({ ...targetDraft, host: e.target.value })}
              placeholder="192.168.1.10 or backend.internal"
              className="w-full px-3 py-2 rounded bg-slate-800 border border-slate-700 focus:outline-none focus:border-sky-500 font-mono"
            />
          </div>
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="block text-slate-300 mb-1">Port</label>
              <input
                type="number"
                required
                min={1}
                max={65535}
                value={targetDraft.port}
                onChange={(e) =>
                  setTargetDraft({ ...targetDraft, port: parseInt(e.target.value, 10) || 0 })
                }
                className="w-full px-3 py-2 rounded bg-slate-800 border border-slate-700 focus:outline-none focus:border-sky-500 font-mono"
              />
            </div>
            <div>
              <label className="block text-slate-300 mb-1">Weight</label>
              <input
                type="number"
                min={1}
                max={256}
                value={targetDraft.weight}
                onChange={(e) =>
                  setTargetDraft({ ...targetDraft, weight: parseInt(e.target.value, 10) || 1 })
                }
                className="w-full px-3 py-2 rounded bg-slate-800 border border-slate-700 focus:outline-none focus:border-sky-500 font-mono"
              />
            </div>
          </div>
          {targetError && (
            <div className="px-3 py-2 rounded bg-red-950/40 border border-red-900 text-red-300">
              {targetError}
            </div>
          )}
          <div className="flex justify-end gap-2 pt-2">
            <button
              type="button"
              onClick={() => setTargetOpen(false)}
              className="px-3 py-1.5 rounded border border-slate-700 hover:bg-slate-800"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={savingTarget}
              className="px-3 py-1.5 rounded bg-sky-600 hover:bg-sky-500 disabled:bg-slate-700 font-medium"
            >
              {savingTarget ? 'saving...' : 'Add'}
            </button>
          </div>
        </form>
      </Modal>
    </div>
  );
}

function Info({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div>
      <div className="text-xs uppercase text-slate-500 tracking-wide mb-0.5">{label}</div>
      <div className="text-slate-200">{children}</div>
    </div>
  );
}

function IconButton({
  children,
  onClick,
  label,
  danger,
}: {
  children: React.ReactNode;
  onClick: () => void;
  label: string;
  danger?: boolean;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      aria-label={label}
      title={label}
      className={`p-1.5 rounded border border-slate-700 hover:bg-slate-800 ${
        danger ? 'text-red-400 hover:text-red-300' : 'text-slate-300'
      }`}
    >
      {children}
    </button>
  );
}
