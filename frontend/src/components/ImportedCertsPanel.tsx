import { useCallback, useEffect, useState } from 'react';
import { Download, Plus, Trash2 } from 'lucide-react';
import { ApiError, ManualCert, api } from '../api/client';
import ImportCertModal from './ImportCertModal';
import RelativeTime from './RelativeTime';
import { useToasts } from './toastsContext';
import { CertStatusBadge } from './CertStatusBadge';

export default function ImportedCertsPanel() {
  const toasts = useToasts();
  const [items, setItems] = useState<ManualCert[] | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [importOpen, setImportOpen] = useState(false);

  const load = useCallback(async () => {
    try {
      const list = await api.listManualCerts();
      setItems(list);
      setErr(null);
    } catch (e) {
      setErr(e instanceof ApiError ? e.message : 'load failed');
    }
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  async function onDelete(c: ManualCert) {
    const ok = window.confirm(
      `Remove the manual cert for ${c.domain}?\n\n` +
        `The files are deleted from the shared volume and the host reverts to tls_mode=auto. ` +
        `Caddy will try to re-issue a Let's Encrypt cert on the next request.`,
    );
    if (!ok) return;
    try {
      await api.deleteManualCert(c.host_id, 'auto');
      toasts.push(`removed manual cert for ${c.domain}`, 'success');
      await load();
    } catch (e) {
      toasts.push(e instanceof ApiError ? e.message : 'delete failed', 'error');
    }
  }

  return (
    <>
      <div className="flex items-start justify-between gap-4 mb-3">
        <p className="text-xs text-slate-500 flex-1">
          Operator-uploaded certificates (cert + key + optional chain). Hosts in this list use{' '}
          <code className="font-mono">tls_mode=manual</code>: Caddy serves the file directly and{' '}
          <strong>does NOT auto-renew</strong>. The notification event{' '}
          <code className="font-mono">manual_cert_expiring_soon</code> fires at 30 / 14 / 7 / 1 days
          before expiry so you have time to upload a replacement.
        </p>
        <button
          type="button"
          onClick={() => setImportOpen(true)}
          className="inline-flex items-center gap-1 px-3 py-1.5 rounded bg-sky-600 hover:bg-sky-500 text-sm font-medium whitespace-nowrap"
        >
          <Plus className="w-3.5 h-3.5" /> Import certificate
        </button>
      </div>

      {err && (
        <div className="mb-4 px-3 py-2 rounded bg-red-950/40 border border-red-900 text-sm text-red-300">
          {err}
        </div>
      )}

      <div className="bg-slate-900 border border-slate-800 rounded-lg overflow-hidden">
        <table className="w-full text-sm">
          <thead className="bg-slate-950/60 text-slate-400 uppercase text-xs tracking-wide">
            <tr>
              <th className="text-left px-4 py-2">Domain</th>
              <th className="text-left px-4 py-2">SANs</th>
              <th className="text-left px-4 py-2">Chain</th>
              <th className="text-left px-4 py-2">Status</th>
              <th className="text-left px-4 py-2">Days left</th>
              <th className="text-left px-4 py-2">Uploaded</th>
              <th className="text-left px-4 py-2">Fingerprint</th>
              <th className="text-right px-4 py-2">Actions</th>
            </tr>
          </thead>
          <tbody>
            {items === null && (
              <tr>
                <td colSpan={8} className="px-4 py-4 text-slate-500">
                  loading...
                </td>
              </tr>
            )}
            {items !== null && items.length === 0 && (
              <tr>
                <td colSpan={8} className="px-4 py-4 text-slate-500">
                  no imported certificates. Hosts with <code className="font-mono">tls_mode=manual</code>{' '}
                  will appear here after upload.
                </td>
              </tr>
            )}
            {items?.map((c) => (
              <tr key={c.host_id} className="border-t border-slate-800">
                <td className="px-4 py-2 font-mono">{c.domain}</td>
                <td className="px-4 py-2 text-slate-300 max-w-[240px] truncate" title={c.sans.join(', ')}>
                  {c.sans.join(', ') || '—'}
                </td>
                <td className="px-4 py-2">
                  <span
                    className={`text-xs px-2 py-0.5 rounded ${
                      c.has_chain ? 'bg-emerald-900 text-emerald-200' : 'bg-slate-800 text-slate-400'
                    }`}
                  >
                    {c.has_chain ? 'yes' : 'none'}
                  </span>
                </td>
                <td className="px-4 py-2">
                  <CertStatusBadge status={c.status} />
                </td>
                <td
                  className="px-4 py-2 font-mono text-slate-300"
                  title={new Date(c.not_after).toLocaleString()}
                >
                  {c.days_left >= 0 ? `${c.days_left}d` : `${Math.abs(c.days_left)}d ago`}
                </td>
                <td className="px-4 py-2 text-slate-400">
                  <RelativeTime iso={c.uploaded_at} />
                </td>
                <td className="px-4 py-2 font-mono text-xs text-slate-500 truncate max-w-[120px]" title={c.fingerprint_sha256}>
                  {c.fingerprint_sha256.slice(0, 12)}...
                </td>
                <td className="px-4 py-2 text-right whitespace-nowrap">
                  <a
                    href={api.manualCertDownloadURL(c.host_id)}
                    className="inline-flex items-center gap-1 px-2 py-1 rounded border border-slate-700 hover:bg-slate-800 text-xs text-slate-300"
                    title="Download cert + chain PEM (no key)"
                  >
                    <Download className="w-3 h-3" /> Download
                  </a>
                  <button
                    type="button"
                    onClick={() => void onDelete(c)}
                    className="ml-1 inline-flex items-center gap-1 px-2 py-1 rounded border border-red-900 text-red-300 hover:bg-red-950/50 text-xs"
                    title="Remove manual cert and revert host to tls_mode=auto"
                  >
                    <Trash2 className="w-3 h-3" /> Remove
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <ImportCertModal
        open={importOpen}
        onClose={() => setImportOpen(false)}
        onImported={() => {
          setImportOpen(false);
          void load();
        }}
      />
    </>
  );
}
