import { FormEvent, useEffect, useState } from 'react';
import { Pencil, Plus, Power, Trash2 } from 'lucide-react';
import { ApiError, Host, HostInput, TLSMode, api } from '../api/client';
import Modal from '../components/Modal';
import { useToasts } from '../components/toastsContext';

type FormState = HostInput & { id?: number };

const emptyForm: FormState = {
  domain: '',
  upstream_url: '',
  upstream_verify_tls: true,
  tls_mode: 'auto',
  tls_email: '',
};

function isHttpsUrl(raw: string): boolean {
  return /^https:\/\//i.test(raw.trim());
}

export default function Hosts() {
  const toasts = useToasts();
  const [hosts, setHosts] = useState<Host[] | null>(null);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [modalOpen, setModalOpen] = useState(false);
  const [form, setForm] = useState<FormState>(emptyForm);
  const [submitting, setSubmitting] = useState(false);
  const [formError, setFormError] = useState<string | null>(null);

  async function refresh() {
    try {
      const list = await api.listHosts();
      setHosts(list);
      setLoadError(null);
    } catch (err) {
      setLoadError(err instanceof ApiError ? err.message : 'load failed');
    }
  }

  useEffect(() => {
    refresh();
  }, []);

  function openCreate() {
    setForm(emptyForm);
    setFormError(null);
    setModalOpen(true);
  }

  function openEdit(h: Host) {
    setForm({
      id: h.id,
      domain: h.domain,
      upstream_url: h.upstream_url,
      upstream_verify_tls: h.upstream_verify_tls,
      tls_mode: h.tls_mode,
      tls_email: h.tls_email,
    });
    setFormError(null);
    setModalOpen(true);
  }

  async function onSubmit(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    setSubmitting(true);
    setFormError(null);
    try {
      const verify = isHttpsUrl(form.upstream_url)
        ? form.upstream_verify_tls ?? true
        : true;

      if (form.id) {
        const existing = hosts?.find((h) => h.id === form.id);
        await api.updateHost(form.id, {
          domain: form.domain,
          upstream_url: form.upstream_url,
          upstream_verify_tls: verify,
          tls_mode: form.tls_mode,
          tls_email: form.tls_email,
          enabled: existing?.enabled ?? true,
        });
        toasts.push(`updated ${form.domain}`, 'success');
      } else {
        await api.createHost({
          domain: form.domain,
          upstream_url: form.upstream_url,
          upstream_verify_tls: verify,
          tls_mode: form.tls_mode,
          tls_email: form.tls_email,
        });
        toasts.push(`created ${form.domain}`, 'success');
      }
      setModalOpen(false);
      await refresh();
    } catch (err) {
      const msg = err instanceof ApiError ? err.message : 'save failed';
      setFormError(msg);
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
    if (!window.confirm(`Delete host ${h.domain}? This removes it from Caddy on reconcile.`)) {
      return;
    }
    try {
      await api.deleteHost(h.id);
      toasts.push(`deleted ${h.domain}`, 'success');
      await refresh();
    } catch (err) {
      toasts.push(err instanceof ApiError ? err.message : 'delete failed', 'error');
    }
  }

  return (
    <div className="p-6 max-w-5xl mx-auto">
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
              <th className="text-left px-4 py-2">Enabled</th>
              <th className="text-right px-4 py-2">Actions</th>
            </tr>
          </thead>
          <tbody>
            {hosts === null && (
              <tr>
                <td colSpan={5} className="px-4 py-4 text-slate-500">
                  loading...
                </td>
              </tr>
            )}
            {hosts !== null && hosts.length === 0 && (
              <tr>
                <td colSpan={5} className="px-4 py-4 text-slate-500">
                  no hosts yet. Click Add host to create one.
                </td>
              </tr>
            )}
            {hosts?.map((h) => (
              <tr key={h.id} className="border-t border-slate-800">
                <td className="px-4 py-2 font-mono">{h.domain}</td>
                <td className="px-4 py-2 font-mono text-slate-300">{h.upstream_url}</td>
                <td className="px-4 py-2">
                  <TLSBadge mode={h.tls_mode} />
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
            ))}
          </tbody>
        </table>
      </div>

      <Modal
        open={modalOpen}
        title={form.id ? `Edit ${form.domain}` : 'Add host'}
        onClose={() => setModalOpen(false)}
      >
        <form onSubmit={onSubmit} className="space-y-3 text-sm">
          <Field
            label="Domain"
            value={form.domain}
            onChange={(v) => setForm({ ...form, domain: v })}
            placeholder="foo.example.com"
            required
          />
          <Field
            label="Upstream URL"
            value={form.upstream_url}
            onChange={(v) => setForm({ ...form, upstream_url: v })}
            placeholder="http://192.168.1.10:8080"
            required
          />
          {isHttpsUrl(form.upstream_url) && (
            <div>
              <label className="flex items-center gap-2 text-slate-200">
                <input
                  type="checkbox"
                  checked={form.upstream_verify_tls ?? true}
                  onChange={(e) =>
                    setForm({ ...form, upstream_verify_tls: e.target.checked })
                  }
                  className="w-4 h-4 accent-sky-600"
                />
                <span>Verify upstream TLS certificate</span>
              </label>
              <p className="mt-1 text-xs text-slate-500">
                Unmark when the backend uses a self-signed certificate or an
                SNI that does not match the hostname.
              </p>
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
          <Field
            label="TLS email"
            value={form.tls_email}
            onChange={(v) => setForm({ ...form, tls_email: v })}
            placeholder="ops@example.com"
            required={form.tls_mode === 'auto'}
          />
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

function Field({
  label,
  value,
  onChange,
  placeholder,
  required,
}: {
  label: string;
  value: string;
  onChange: (v: string) => void;
  placeholder?: string;
  required?: boolean;
}) {
  return (
    <div>
      <label className="block text-slate-300 mb-1">{label}</label>
      <input
        type="text"
        value={value}
        onChange={(e) => onChange(e.target.value)}
        placeholder={placeholder}
        required={required}
        className="w-full px-3 py-2 rounded bg-slate-800 border border-slate-700 focus:outline-none focus:border-sky-500 font-mono"
      />
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

function TLSBadge({ mode }: { mode: TLSMode }) {
  if (mode === 'auto') {
    return (
      <span className="text-xs px-2 py-0.5 rounded bg-sky-900 text-sky-200">auto</span>
    );
  }
  return (
    <span className="text-xs px-2 py-0.5 rounded bg-slate-800 text-slate-400">none</span>
  );
}
