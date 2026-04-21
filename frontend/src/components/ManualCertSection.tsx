import { useCallback, useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { ExternalLink, FileLock2 } from 'lucide-react';
import { ApiError, ManualCert, api } from '../api/client';
import RelativeTime from './RelativeTime';
import { CertStatusBadge } from './CertStatusBadge';

interface Props {
  hostID: number;
  domain: string;
}

// ManualCertSection is a READ-ONLY info card rendered inside the host
// edit modal when tls_mode=manual. All cert management -- import,
// replace, remove -- happens on the Certificates page (Imported tab).
//
// Prior to the v1.1.0 UX fix this component embedded an upload form
// inside the host edit form. Nested <form> elements are invalid HTML
// and the browser flattened them, causing the submit button to fire
// the OUTER host form (calling updateHost) instead of the inner
// upload. Splitting import into its own modal on the Certificates
// page eliminates the nesting entirely.
export default function ManualCertSection({ hostID, domain }: Props) {
  const [cert, setCert] = useState<ManualCert | null>(null);
  const [loading, setLoading] = useState(true);
  const [err, setErr] = useState<string | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const c = await api.getManualCert(hostID);
      setCert(c);
      setErr(null);
    } catch (e) {
      if (e instanceof ApiError && e.status === 404) {
        setCert(null);
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

  return (
    <div className="border border-slate-800 rounded p-3 bg-slate-950/40 space-y-3">
      <div className="flex items-center gap-2 text-slate-300">
        <FileLock2 className="w-4 h-4" />
        <span className="font-medium text-sm">Manual certificate</span>
      </div>

      {loading ? (
        <div className="text-xs text-slate-500">loading...</div>
      ) : err ? (
        <div className="text-xs text-red-300 bg-red-950/40 border border-red-900 rounded px-2 py-1.5">
          {err}
        </div>
      ) : cert ? (
        <LoadedInfo cert={cert} />
      ) : (
        <div className="text-xs text-slate-400 bg-slate-900/60 border border-slate-800 rounded px-3 py-2">
          <strong>No manual cert loaded yet.</strong> Upload one from the Certificates page to
          activate this host with your own cert.
        </div>
      )}

      <Link
        to="/certificates"
        className="inline-flex items-center gap-1 text-xs text-sky-400 hover:text-sky-300"
        title={`Manage manual certs for ${domain} on the Certificates page`}
      >
        <ExternalLink className="w-3 h-3" /> Manage in Certificates → Imported
      </Link>
    </div>
  );
}

function LoadedInfo({ cert }: { cert: ManualCert }) {
  return (
    <div className="border border-slate-800 rounded p-3 bg-slate-900/60">
      <div className="flex items-center justify-between mb-2">
        <div className="text-xs text-slate-400">Currently loaded</div>
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
    </div>
  );
}
