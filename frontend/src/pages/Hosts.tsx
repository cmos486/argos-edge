import { FormEvent, useEffect, useMemo, useState } from 'react';
import { Link } from 'react-router-dom';
import { FileText, ListOrdered, Pencil, Plus, Power, ShieldAlert, Trash2 } from 'lucide-react';
import {
  ApiError,
  Host,
  HostInput,
  TLSMode,
  TargetGroup,
  api,
} from '../api/client';
import Modal from '../components/Modal';
import TargetGroupForm from '../components/TargetGroupForm';
import {
  TargetGroupFormValue,
  emptyTargetGroupForm,
} from '../components/targetGroupFormValue';
import { useToasts } from '../components/toastsContext';

type HostFormState = {
  id?: number;
  domain: string;
  tls_mode: TLSMode;
  tls_email: string;
  // target group selection: either "existing:{id}" or "inline"
  tgChoice: string;
  tgInline: TargetGroupFormValue;
};

const INLINE_CHOICE = 'inline';

function emptyHostForm(): HostFormState {
  return {
    domain: '',
    tls_mode: 'auto',
    tls_email: '',
    tgChoice: '',
    tgInline: emptyTargetGroupForm(),
  };
}

export default function Hosts() {
  const toasts = useToasts();
  const [hosts, setHosts] = useState<Host[] | null>(null);
  const [tgs, setTgs] = useState<TargetGroup[]>([]);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [modalOpen, setModalOpen] = useState(false);
  const [form, setForm] = useState<HostFormState>(emptyHostForm());
  const [submitting, setSubmitting] = useState(false);
  const [formError, setFormError] = useState<string | null>(null);

  async function refresh() {
    try {
      const [hostList, tgList] = await Promise.all([api.listHosts(), api.listTargetGroups()]);
      setHosts(hostList);
      setTgs(tgList);
      setLoadError(null);
    } catch (err) {
      setLoadError(err instanceof ApiError ? err.message : 'load failed');
    }
  }

  useEffect(() => {
    refresh();
  }, []);

  function openCreate() {
    const next = emptyHostForm();
    if (tgs.length > 0) {
      next.tgChoice = String(tgs[0]!.id);
    } else {
      next.tgChoice = INLINE_CHOICE;
    }
    setForm(next);
    setFormError(null);
    setModalOpen(true);
  }

  function openEdit(h: Host) {
    setForm({
      id: h.id,
      domain: h.domain,
      tls_mode: h.tls_mode,
      tls_email: h.tls_email,
      tgChoice: String(h.target_group_id),
      tgInline: emptyTargetGroupForm(),
    });
    setFormError(null);
    setModalOpen(true);
  }

  async function onSubmit(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    setSubmitting(true);
    setFormError(null);

    try {
      const base: HostInput = {
        domain: form.domain,
        tls_mode: form.tls_mode,
        tls_email: form.tls_email,
      };

      if (form.tgChoice === INLINE_CHOICE) {
        if (form.id) {
          setFormError('inline target_group is not supported on update; pick an existing one');
          setSubmitting(false);
          return;
        }
        base.target_group = { ...form.tgInline };
      } else {
        const idNum = Number(form.tgChoice);
        if (!Number.isFinite(idNum) || idNum <= 0) {
          setFormError('pick a target group');
          setSubmitting(false);
          return;
        }
        base.target_group_id = idNum;
      }

      if (form.id) {
        const existing = hosts?.find((h) => h.id === form.id);
        await api.updateHost(form.id, {
          ...base,
          enabled: existing?.enabled ?? true,
        } as HostInput & { enabled: boolean });
        toasts.push(`updated ${form.domain}`, 'success');
      } else {
        await api.createHost(base);
        toasts.push(`created ${form.domain}`, 'success');
      }
      setModalOpen(false);
      await refresh();
    } catch (err) {
      setFormError(err instanceof ApiError ? err.message : 'save failed');
    } finally {
      setSubmitting(false);
    }
  }

  async function onToggle(h: Host) {
    try {
      await api.toggleHost(h.id);
      toasts.push(`${h.domain} ${h.enabled ? 'disabled' : 'enabled'}`, 'success');
      await refresh();
    } catch (err) {
      toasts.push(err instanceof ApiError ? err.message : 'toggle failed', 'error');
    }
  }

  async function onDelete(h: Host) {
    if (!window.confirm(`Delete host ${h.domain}? Caddy is reconciled on save.`)) return;
    try {
      await api.deleteHost(h.id);
      toasts.push(`deleted ${h.domain}`, 'success');
      await refresh();
    } catch (err) {
      toasts.push(err instanceof ApiError ? err.message : 'delete failed', 'error');
    }
  }

  const tgMap = useMemo(() => {
    const m = new Map<number, TargetGroup>();
    for (const t of tgs) m.set(t.id, t);
    return m;
  }, [tgs]);

  return (
    <div className="p-6 max-w-6xl mx-auto">
      <div className="flex items-center justify-between mb-4">
        <h1 className="text-2xl font-semibold">Hosts</h1>
        <button
          type="button"
          onClick={openCreate}
          className="flex items-center gap-2 px-3 py-1.5 rounded bg-sky-600 hover:bg-sky-500 text-sm font-medium"
        >
          <Plus className="w-4 h-4" />
          Add host
        </button>
      </div>

      {loadError && (
        <div className="mb-4 px-3 py-2 rounded bg-red-950/40 border border-red-900 text-sm text-red-300">
          {loadError}
        </div>
      )}

      <div className="bg-slate-900 border border-slate-800 rounded-lg overflow-hidden">
        <table className="w-full text-sm">
          <thead className="bg-slate-950/60 text-slate-400 uppercase text-xs tracking-wide">
            <tr>
              <th className="text-left px-4 py-2">Domain</th>
              <th className="text-left px-4 py-2">Upstream</th>
              <th className="text-left px-4 py-2">TLS</th>
              <th className="text-left px-4 py-2">Rules</th>
              <th className="text-left px-4 py-2">Enabled</th>
              <th className="text-right px-4 py-2">Actions</th>
            </tr>
          </thead>
          <tbody>
            {hosts === null && (
              <tr>
                <td colSpan={6} className="px-4 py-4 text-slate-500">
                  loading...
                </td>
              </tr>
            )}
            {hosts !== null && hosts.length === 0 && (
              <tr>
                <td colSpan={6} className="px-4 py-4 text-slate-500">
                  no hosts yet. Click Add host to create one.
                </td>
              </tr>
            )}
            {hosts?.map((h) => {
              const tg = h.target_group ?? tgMap.get(h.target_group_id);
              const https = tg?.protocol === 'https';
              const tgFull = tgMap.get(h.target_group_id);
              const notVerified = https && tgFull && !tgFull.verify_tls;
              return (
                <tr key={h.id} className="border-t border-slate-800">
                  <td className="px-4 py-2 font-mono">{h.domain}</td>
                  <td className="px-4 py-2">
                    {tg ? (
                      <div className="flex items-center gap-2 flex-wrap">
                        <Link
                          to={`/target-groups/${h.target_group_id}`}
                          className="font-mono text-sky-400 hover:underline"
                        >
                          {tg.name}
                        </Link>
                        <span className="text-xs px-2 py-0.5 rounded bg-slate-800 text-slate-300">
                          {tg.protocol}
                        </span>
                        <span className="text-xs px-2 py-0.5 rounded bg-slate-800 text-slate-300">
                          {tg.algorithm}
                        </span>
                        <span className="text-xs text-slate-400">
                          {tg.targets_enabled_count}/{tg.targets_count} targets
                        </span>
                        {notVerified && (
                          <span className="inline-flex items-center gap-1 text-[11px] px-1.5 py-0.5 rounded bg-amber-950 text-amber-300 border border-amber-800">
                            <ShieldAlert className="w-3 h-3" />
                            TLS not verified
                          </span>
                        )}
                      </div>
                    ) : (
                      <span className="text-slate-500">tg {h.target_group_id}</span>
                    )}
                  </td>
                  <td className="px-4 py-2">
                    <span
                      className={`text-xs px-2 py-0.5 rounded ${
                        h.tls_mode === 'auto'
                          ? 'bg-sky-900 text-sky-200'
                          : 'bg-slate-800 text-slate-400'
                      }`}
                    >
                      {h.tls_mode}
                    </span>
                  </td>
                  <td className="px-4 py-2">
                    <Link
                      to={`/hosts/${h.id}/rules`}
                      className="inline-flex items-center gap-1 text-xs px-2 py-0.5 rounded border border-slate-700 hover:bg-slate-800 text-slate-300"
                      title="edit rules"
                    >
                      <ListOrdered className="w-3 h-3" />
                      {h.rules_count > 0 ? `${h.rules_count} rules` : 'add'}
                    </Link>
                  </td>
                  <td className="px-4 py-2">
                    <span
                      className={`text-xs px-2 py-0.5 rounded ${
                        h.enabled
                          ? 'bg-emerald-900 text-emerald-200'
                          : 'bg-slate-800 text-slate-400'
                      }`}
                    >
                      {h.enabled ? 'on' : 'off'}
                    </span>
                  </td>
                  <td className="px-4 py-2 text-right">
                    <div className="inline-flex items-center gap-1">
                      <Link
                        to={`/logs?host_id=${h.id}`}
                        aria-label="view logs"
                        title="view logs"
                        className="p-1.5 rounded border border-slate-700 hover:bg-slate-800 text-slate-300"
                      >
                        <FileText className="w-4 h-4" />
                      </Link>
                      <IconButton label="toggle" onClick={() => onToggle(h)}>
                        <Power className="w-4 h-4" />
                      </IconButton>
                      <IconButton label="edit" onClick={() => openEdit(h)}>
                        <Pencil className="w-4 h-4" />
                      </IconButton>
                      <IconButton label="delete" onClick={() => onDelete(h)} danger>
                        <Trash2 className="w-4 h-4" />
                      </IconButton>
                    </div>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>

      <Modal
        open={modalOpen}
        title={form.id ? `Edit ${form.domain}` : 'Add host'}
        onClose={() => setModalOpen(false)}
      >
        <form onSubmit={onSubmit} className="space-y-3 text-sm">
          <div>
            <label className="block text-slate-300 mb-1">Domain</label>
            <input
              type="text"
              required
              value={form.domain}
              onChange={(e) => setForm({ ...form, domain: e.target.value })}
              placeholder="foo.example.com"
              className="w-full px-3 py-2 rounded bg-slate-800 border border-slate-700 focus:outline-none focus:border-sky-500 font-mono"
            />
          </div>

          <div>
            <label className="block text-slate-300 mb-1">Target group</label>
            <select
              value={form.tgChoice}
              onChange={(e) => setForm({ ...form, tgChoice: e.target.value })}
              className="w-full px-3 py-2 rounded bg-slate-800 border border-slate-700 focus:outline-none focus:border-sky-500"
            >
              {tgs.map((tg) => (
                <option key={tg.id} value={tg.id}>
                  {tg.name} — {tg.protocol} / {tg.algorithm} ({tg.targets_enabled_count}/
                  {tg.targets_count} targets)
                </option>
              ))}
              {!form.id && <option value={INLINE_CHOICE}>+ Create new target group</option>}
            </select>
          </div>

          {form.tgChoice === INLINE_CHOICE && (
            <div className="p-3 rounded border border-slate-800 bg-slate-950/60">
              <div className="text-xs uppercase text-slate-500 tracking-wide mb-2">
                New target group
              </div>
              <TargetGroupForm
                value={form.tgInline}
                onChange={(v) => setForm({ ...form, tgInline: v })}
                requireTargets
              />
            </div>
          )}

          <div>
            <label className="block text-slate-300 mb-1">TLS mode</label>
            <select
              value={form.tls_mode}
              onChange={(e) => setForm({ ...form, tls_mode: e.target.value as TLSMode })}
              className="w-full px-3 py-2 rounded bg-slate-800 border border-slate-700 focus:outline-none focus:border-sky-500"
            >
              <option value="auto">auto (Let's Encrypt via Cloudflare DNS-01)</option>
              <option value="none">none (plain HTTP)</option>
            </select>
          </div>
          <div>
            <label className="block text-slate-300 mb-1">TLS email</label>
            <input
              type="text"
              value={form.tls_email}
              onChange={(e) => setForm({ ...form, tls_email: e.target.value })}
              placeholder="ops@example.com"
              required={form.tls_mode === 'auto'}
              className="w-full px-3 py-2 rounded bg-slate-800 border border-slate-700 focus:outline-none focus:border-sky-500 font-mono"
            />
          </div>

          {formError && (
            <div className="px-3 py-2 rounded bg-red-950/40 border border-red-900 text-red-300">
              {formError}
            </div>
          )}
          <div className="flex justify-end gap-2 pt-2">
            <button
              type="button"
              onClick={() => setModalOpen(false)}
              className="px-3 py-1.5 rounded border border-slate-700 hover:bg-slate-800"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={submitting}
              className="px-3 py-1.5 rounded bg-sky-600 hover:bg-sky-500 disabled:bg-slate-700 font-medium"
            >
              {submitting ? 'saving...' : form.id ? 'Save' : 'Create'}
            </button>
          </div>
        </form>
      </Modal>
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
