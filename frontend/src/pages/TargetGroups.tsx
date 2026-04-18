import { FormEvent, useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { HeartPulse, Plus } from 'lucide-react';
import { ApiError, TargetGroup, api } from '../api/client';
import Modal from '../components/Modal';
import TargetGroupForm from '../components/TargetGroupForm';
import {
  TargetGroupFormValue,
  emptyTargetGroupForm,
} from '../components/targetGroupFormValue';
import { useToasts } from '../components/toastsContext';

export default function TargetGroups() {
  const toasts = useToasts();
  const [tgs, setTgs] = useState<TargetGroup[] | null>(null);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [modalOpen, setModalOpen] = useState(false);
  const [form, setForm] = useState<TargetGroupFormValue>(emptyTargetGroupForm());
  const [submitting, setSubmitting] = useState(false);
  const [formError, setFormError] = useState<string | null>(null);

  async function refresh() {
    try {
      setTgs(await api.listTargetGroups());
      setLoadError(null);
    } catch (err) {
      setLoadError(err instanceof ApiError ? err.message : 'load failed');
    }
  }
  useEffect(() => {
    refresh();
  }, []);

  function openCreate() {
    setForm(emptyTargetGroupForm());
    setFormError(null);
    setModalOpen(true);
  }

  async function onSubmit(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    setSubmitting(true);
    setFormError(null);
    try {
      const created = await api.createTargetGroup(form);
      toasts.push(`created ${created.name}`, 'success');
      setModalOpen(false);
      await refresh();
    } catch (err) {
      setFormError(err instanceof ApiError ? err.message : 'save failed');
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <div className="p-6 max-w-5xl mx-auto">
      <div className="flex items-center justify-between mb-4">
        <h1 className="text-2xl font-semibold">Target Groups</h1>
        <button
          type="button"
          onClick={openCreate}
          className="flex items-center gap-2 px-3 py-1.5 rounded bg-sky-600 hover:bg-sky-500 text-sm font-medium"
        >
          <Plus className="w-4 h-4" />
          Add target group
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
              <th className="text-left px-4 py-2">Name</th>
              <th className="text-left px-4 py-2">Protocol</th>
              <th className="text-left px-4 py-2">Algorithm</th>
              <th className="text-left px-4 py-2">Targets</th>
              <th className="text-left px-4 py-2">Health check</th>
            </tr>
          </thead>
          <tbody>
            {tgs === null && (
              <tr>
                <td colSpan={5} className="px-4 py-4 text-slate-500">
                  loading...
                </td>
              </tr>
            )}
            {tgs !== null && tgs.length === 0 && (
              <tr>
                <td colSpan={5} className="px-4 py-4 text-slate-500">
                  no target groups yet.
                </td>
              </tr>
            )}
            {tgs?.map((tg) => (
              <tr key={tg.id} className="border-t border-slate-800 hover:bg-slate-800/30">
                <td className="px-4 py-2 font-mono">
                  <Link to={`/target-groups/${tg.id}`} className="text-sky-400 hover:underline">
                    {tg.name}
                  </Link>
                </td>
                <td className="px-4 py-2">
                  <ProtocolBadge protocol={tg.protocol} verifyTLS={tg.verify_tls} />
                </td>
                <td className="px-4 py-2 font-mono text-slate-300">{tg.algorithm}</td>
                <td className="px-4 py-2 text-slate-300">
                  {tg.targets_enabled_count} / {tg.targets_count}
                </td>
                <td className="px-4 py-2">
                  {tg.health_check_enabled ? (
                    <span className="inline-flex items-center gap-1 text-xs px-2 py-0.5 rounded bg-emerald-900 text-emerald-200">
                      <HeartPulse className="w-3 h-3" />
                      active
                    </span>
                  ) : (
                    <span className="text-xs px-2 py-0.5 rounded bg-slate-800 text-slate-400">
                      passive only
                    </span>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <Modal open={modalOpen} title="Add target group" onClose={() => setModalOpen(false)}>
        <form onSubmit={onSubmit}>
          <TargetGroupForm value={form} onChange={setForm} requireTargets />
          {formError && (
            <div className="mt-3 px-3 py-2 rounded bg-red-950/40 border border-red-900 text-red-300 text-sm">
              {formError}
            </div>
          )}
          <div className="flex justify-end gap-2 pt-3">
            <button
              type="button"
              onClick={() => setModalOpen(false)}
              className="px-3 py-1.5 rounded border border-slate-700 hover:bg-slate-800 text-sm"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={submitting}
              className="px-3 py-1.5 rounded bg-sky-600 hover:bg-sky-500 disabled:bg-slate-700 text-sm font-medium"
            >
              {submitting ? 'saving...' : 'Create'}
            </button>
          </div>
        </form>
      </Modal>
    </div>
  );
}

function ProtocolBadge({ protocol, verifyTLS }: { protocol: string; verifyTLS: boolean }) {
  if (protocol === 'https') {
    return (
      <span className="inline-flex items-center gap-1">
        <span className="text-xs px-2 py-0.5 rounded bg-sky-900 text-sky-200">https</span>
        {!verifyTLS && (
          <span className="text-xs px-2 py-0.5 rounded bg-amber-950 text-amber-300 border border-amber-800">
            no-verify
          </span>
        )}
      </span>
    );
  }
  return <span className="text-xs px-2 py-0.5 rounded bg-slate-800 text-slate-300">http</span>;
}
