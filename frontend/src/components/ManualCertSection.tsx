import { FormEvent, useCallback, useEffect, useState } from 'react';
import { AlertTriangle, Download, Trash2, Upload } from 'lucide-react';
import { ApiError, ManualCert, api } from '../api/client';
import RelativeTime from './RelativeTime';
import { CertStatusBadge } from './CertStatusBadge';
import { useToasts } from './toastsContext';

interface Props {
  hostID: number;
  domain: string;
  onChanged: () => void;
}

// ManualCertSection renders inside the host edit modal when
// tls_mode=manual. It shows the currently-uploaded cert (if any) and
// a three-file upload form (cert / key / optional chain). The warn
// about "no auto-renewal" is always visible -- this is the single
// piece of UX that separates manual from auto modes operationally.
export default function ManualCertSection({ hostID, domain, onChanged }: Props) {
  const toasts = useToasts();
  const [current, setCurrent] = useState<ManualCert | null>(null);
  const [loading, setLoading] = useState(true);
  const [err, setErr] = useState<string | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const c = await api.getManualCert(hostID);
      setCurrent(c);
      setErr(null);
    } catch (e) {
      if (e instanceof ApiError && e.status === 404) {
        setCurrent(null);
        setErr(null);
      } else {
        setErr(e instanceof ApiError ? e.message : 'load failed');
      }
    } finally {
      setLoading(false);
    }
  }, [hostID]);

  useEffect(() => {
    load();
  }, [load]);

  async function onRemove() {
    const ok = window.confirm(
      `Remove the manual cert for ${domain}?\n\n` +
        `Files deleted from the shared volume. The host reverts to tls_mode=auto.`,
    );
    if (!ok) return;
    try {
      await api.deleteManualCert(hostID, 'auto');
      toasts.push('manual cert removed', 'success');
      await load();
      onChanged();
    } catch (e) {
      toasts.push(e instanceof ApiError ? e.message : 'remove failed', 'error');
    }
  }

  return (
    <div className="border border-slate-800 rounded p-3 space-y-3 bg-slate-950/40">
      <div className="flex items-start gap-2 bg-amber-950/40 border border-amber-900 rounded px-3 py-2 text-xs text-amber-200">
        <AlertTriangle className="w-4 h-4 mt-0.5 flex-shrink-0" />
        <span>
          Manual certs do <strong>NOT</strong> auto-renew. Argos fires a
          {' '}<code className="font-mono">manual_cert_expiring_soon</code> notification at 30 / 14
          / 7 / 1 days before expiry; upload a replacement before then.
        </span>
      </div>

      {loading ? (
        <div className="text-xs text-slate-500">loading...</div>
      ) : err ? (
        <div className="text-xs text-red-300 bg-red-950/40 border border-red-900 rounded px-2 py-1.5">
          {err}
        </div>
      ) : current ? (
        <CurrentCertSummary cert={current} onRemove={onRemove} />
      ) : null}

      <UploadForm
        hostID={hostID}
        domain={domain}
        hasExisting={!!current}
        onUploaded={() => {
          void load();
          onChanged();
        }}
      />
    </div>
  );
}

function CurrentCertSummary({
  cert,
  onRemove,
}: {
  cert: ManualCert;
  onRemove: () => void;
}) {
  return (
    <div className="border border-slate-800 rounded p-3 bg-slate-900/60">
      <div className="flex items-center justify-between mb-2">
        <div className="text-sm font-medium text-slate-200">Currently loaded</div>
        <CertStatusBadge status={cert.status} />
      </div>
      <dl className="text-xs text-slate-400 space-y-1 font-mono">
        <div className="flex gap-4">
          <dt className="w-28 text-slate-500">SANs</dt>
          <dd className="flex-1 truncate" title={cert.sans.join(', ')}>
            {cert.sans.join(', ') || '—'}
          </dd>
        </div>
        <div className="flex gap-4">
          <dt className="w-28 text-slate-500">Expires</dt>
          <dd>
            {cert.days_left}d (<RelativeTime iso={cert.not_after} />)
          </dd>
        </div>
        <div className="flex gap-4">
          <dt className="w-28 text-slate-500">Chain</dt>
          <dd>{cert.has_chain ? 'present' : 'none (self-signed or missing)'}</dd>
        </div>
        <div className="flex gap-4">
          <dt className="w-28 text-slate-500">Fingerprint</dt>
          <dd className="truncate" title={cert.fingerprint_sha256}>
            {cert.fingerprint_sha256.slice(0, 24)}...
          </dd>
        </div>
        <div className="flex gap-4">
          <dt className="w-28 text-slate-500">Uploaded</dt>
          <dd>
            <RelativeTime iso={cert.uploaded_at} />
          </dd>
        </div>
      </dl>
      <div className="flex gap-2 pt-2 mt-2 border-t border-slate-800">
        <a
          href={api.manualCertDownloadURL(cert.host_id)}
          className="inline-flex items-center gap-1 px-2 py-1 rounded border border-slate-700 hover:bg-slate-800 text-xs text-slate-300"
        >
          <Download className="w-3 h-3" /> Download PEM
        </a>
        <button
          type="button"
          onClick={onRemove}
          className="inline-flex items-center gap-1 px-2 py-1 rounded border border-red-900 text-red-300 hover:bg-red-950/50 text-xs"
        >
          <Trash2 className="w-3 h-3" /> Remove
        </button>
      </div>
    </div>
  );
}

function UploadForm({
  hostID,
  domain,
  hasExisting,
  onUploaded,
}: {
  hostID: number;
  domain: string;
  hasExisting: boolean;
  onUploaded: () => void;
}) {
  const toasts = useToasts();
  const [certFile, setCertFile] = useState<File | null>(null);
  const [keyFile, setKeyFile] = useState<File | null>(null);
  const [chainFile, setChainFile] = useState<File | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const [warn, setWarn] = useState<string[]>([]);

  async function onSubmit(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    if (!certFile || !keyFile) {
      toasts.push('cert and key files are required', 'error');
      return;
    }
    if (hasExisting) {
      if (!window.confirm(`Replace the existing manual cert for ${domain}?`)) return;
    }
    setSubmitting(true);
    setWarn([]);
    try {
      const r = await api.uploadManualCert(hostID, {
        cert: certFile,
        key: keyFile,
        chain: chainFile ?? undefined,
      });
      toasts.push(`uploaded cert for ${r.cert.domain}`, 'success');
      setWarn(r.warnings ?? []);
      // Clear inputs to avoid accidental re-upload.
      setCertFile(null);
      setKeyFile(null);
      setChainFile(null);
      onUploaded();
    } catch (e) {
      toasts.push(e instanceof ApiError ? e.message : 'upload failed', 'error');
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <form onSubmit={onSubmit} className="space-y-3">
      <div className="text-sm font-medium text-slate-200">
        {hasExisting ? 'Replace certificate' : 'Upload certificate'}
      </div>
      <FileField label="Certificate (cert.pem)" file={certFile} onChange={setCertFile} required />
      <FileField label="Private key (key.pem)" file={keyFile} onChange={setKeyFile} required />
      <FileField
        label="Chain / intermediates (optional)"
        file={chainFile}
        onChange={setChainFile}
      />

      {warn.length > 0 && (
        <div className="bg-amber-950/40 border border-amber-900 rounded px-3 py-2 text-xs text-amber-200 space-y-1">
          {warn.map((w, i) => (
            <div key={i}>{w}</div>
          ))}
        </div>
      )}

      <button
        type="submit"
        disabled={submitting || !certFile || !keyFile}
        className="inline-flex items-center gap-1 px-3 py-1.5 text-sm rounded bg-sky-600 hover:bg-sky-500 disabled:bg-slate-700 disabled:cursor-not-allowed font-medium"
      >
        <Upload className="w-3.5 h-3.5" />
        {submitting ? 'uploading...' : hasExisting ? 'Replace & activate' : 'Upload & activate'}
      </button>
    </form>
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
