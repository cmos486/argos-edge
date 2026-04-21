import { FormEvent, useCallback, useEffect, useState } from 'react';
import { AlertTriangle, Upload } from 'lucide-react';
import { ApiError, Host, ManualCert, api } from '../api/client';
import Modal from './Modal';
import { useToasts } from './toastsContext';

interface Props {
  open: boolean;
  onClose: () => void;
  onImported: (cert: ManualCert) => void;
}

// ImportCertModal is the single entry point for uploading an operator-
// owned cert. It lives on the Certificates page (Imported tab). Host
// selection happens here, NOT on the host edit form -- the host edit
// form only renders a read-only info card when a cert is already in
// place, because putting an upload form inside the host edit form
// was invalid HTML (nested forms) and caused the v1.1.0 bug where
// "Upload & activate" submitted the outer host form instead.
export default function ImportCertModal({ open, onClose, onImported }: Props) {
  const toasts = useToasts();
  const [hosts, setHosts] = useState<Host[]>([]);
  const [existing, setExisting] = useState<Set<number>>(new Set());
  const [hostID, setHostID] = useState<string>('');
  const [certFile, setCertFile] = useState<File | null>(null);
  const [keyFile, setKeyFile] = useState<File | null>(null);
  const [chainFile, setChainFile] = useState<File | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [warnings, setWarnings] = useState<string[]>([]);

  const load = useCallback(async () => {
    try {
      const [hs, ms] = await Promise.all([api.listHosts(), api.listManualCerts()]);
      setHosts(hs);
      setExisting(new Set(ms.map((m) => m.host_id)));
    } catch (e) {
      setErr(e instanceof ApiError ? e.message : 'failed to load hosts');
    }
  }, []);

  useEffect(() => {
    if (!open) return;
    // Reset every time the modal reopens so stale state from a previous
    // session does not leak into a new upload.
    setHostID('');
    setCertFile(null);
    setKeyFile(null);
    setChainFile(null);
    setErr(null);
    setWarnings([]);
    void load();
  }, [open, load]);

  const selectedHost = hosts.find((h) => String(h.id) === hostID);
  const hostCurrentlyAuto = selectedHost?.tls_mode === 'auto';
  const hostHasExistingCert = selectedHost ? existing.has(selectedHost.id) : false;

  async function onSubmit(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    if (!selectedHost) {
      setErr('pick a host');
      return;
    }
    if (!certFile || !keyFile) {
      setErr('cert and key files are required');
      return;
    }
    if (hostHasExistingCert) {
      if (!window.confirm(`Replace the existing manual cert for ${selectedHost.domain}?`)) {
        return;
      }
    }
    setSubmitting(true);
    setErr(null);
    setWarnings([]);
    try {
      const r = await api.uploadManualCert(selectedHost.id, {
        cert: certFile,
        key: keyFile,
        chain: chainFile ?? undefined,
      });
      toasts.push(`imported cert for ${r.cert.domain}`, 'success');
      onImported(r.cert);
      // If the server returned soft warnings, show them briefly before
      // the caller closes the modal. The parent decides via
      // onImported() when to actually close.
      if (r.warnings && r.warnings.length > 0) {
        setWarnings(r.warnings);
      } else {
        onClose();
      }
    } catch (e) {
      setErr(e instanceof ApiError ? e.message : 'import failed');
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <Modal open={open} title="Import certificate" onClose={onClose}>
      <form onSubmit={onSubmit} className="space-y-3 text-sm">
        <div>
          <label className="block text-slate-300 mb-1">Host</label>
          <select
            value={hostID}
            onChange={(e) => setHostID(e.target.value)}
            required
            className="w-full px-3 py-2 rounded bg-slate-800 border border-slate-700 focus:outline-none focus:border-sky-500"
          >
            <option value="">Pick a host...</option>
            {hosts.map((h) => (
              <option key={h.id} value={h.id}>
                {h.domain}  ({h.tls_mode}{existing.has(h.id) ? ', has manual cert' : ''})
              </option>
            ))}
          </select>
          <p className="mt-1 text-xs text-slate-500">
            Uploading flips the host to <code className="font-mono">tls_mode=manual</code>. A
            host with an existing manual cert is offered for replacement (you confirm first).
          </p>
        </div>

        {hostCurrentlyAuto && !hostHasExistingCert && (
          <div className="flex items-start gap-2 bg-amber-950/40 border border-amber-900 rounded px-3 py-2 text-xs text-amber-200">
            <AlertTriangle className="w-4 h-4 mt-0.5 flex-shrink-0" />
            <span>
              <strong>{selectedHost?.domain}</strong> currently uses{' '}
              <code className="font-mono">tls_mode=auto</code> (Let's Encrypt auto-renewal). This
              upload switches it to manual and disables auto-renewal. Caddy drops the ACME
              policy on the next reconcile.
            </span>
          </div>
        )}

        <FileField
          label="Certificate (cert.pem)"
          file={certFile}
          onChange={setCertFile}
          required
        />
        <FileField label="Private key (key.pem)" file={keyFile} onChange={setKeyFile} required />
        <FileField
          label="Chain / intermediates (optional)"
          file={chainFile}
          onChange={setChainFile}
        />

        {warnings.length > 0 && (
          <div className="bg-amber-950/40 border border-amber-900 rounded px-3 py-2 text-xs text-amber-200 space-y-1">
            <div className="font-semibold mb-1">Upload succeeded with warnings:</div>
            {warnings.map((w, i) => (
              <div key={i}>· {w}</div>
            ))}
            <button
              type="button"
              onClick={onClose}
              className="mt-2 px-2 py-0.5 rounded border border-amber-700 text-amber-100 hover:bg-amber-900/40"
            >
              Close
            </button>
          </div>
        )}

        {err && (
          <div className="bg-red-950/40 border border-red-900 rounded px-3 py-2 text-xs text-red-300">
            {err}
          </div>
        )}

        <div className="flex items-center justify-end gap-2 pt-2 border-t border-slate-800">
          <button
            type="button"
            onClick={onClose}
            className="px-3 py-1.5 rounded border border-slate-700 hover:bg-slate-800"
          >
            Cancel
          </button>
          <button
            type="submit"
            disabled={submitting || !hostID || !certFile || !keyFile}
            className="inline-flex items-center gap-1 px-3 py-1.5 rounded bg-sky-600 hover:bg-sky-500 disabled:bg-slate-700 disabled:cursor-not-allowed font-medium"
          >
            <Upload className="w-3.5 h-3.5" />
            {submitting ? 'importing...' : hostHasExistingCert ? 'Replace & activate' : 'Import & activate'}
          </button>
        </div>
      </form>
    </Modal>
  );
}

function FileField({
  label,
  file,
  onChange,
  required,
}: {
  label: string;
  file: File | null;
  onChange: (f: File | null) => void;
  required?: boolean;
}) {
  return (
    <div>
      <label className="block text-xs text-slate-400 mb-1">
        {label}
        {required && <span className="text-red-400"> *</span>}
      </label>
      <input
        type="file"
        accept=".pem,.crt,.key,.cer,text/plain,application/x-pem-file"
        required={required}
        onChange={(e) => onChange(e.target.files?.[0] ?? null)}
        className="text-xs text-slate-300 file:mr-2 file:py-1 file:px-2 file:rounded file:border file:border-slate-700 file:bg-slate-800 file:text-slate-300 file:text-xs"
      />
      {file && (
        <div className="text-[10px] text-slate-500 mt-1">
          {file.name} ({(file.size / 1024).toFixed(1)} KiB)
        </div>
      )}
    </div>
  );
}
