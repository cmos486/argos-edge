import { useCallback, useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { FileText, RefreshCw } from 'lucide-react';
import { ApiError, Cert, TLSChallenge, api } from '../api/client';
import RelativeTime from './RelativeTime';
import { useToasts } from './toastsContext';
import { CertStatusBadge } from './CertStatusBadge';

export default function ActiveCertsPanel() {
  const toasts = useToasts();
  const [certs, setCerts] = useState<Cert[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [renewing, setRenewing] = useState<number | null>(null);

  const load = useCallback(async () => {
    try {
      const list = await api.listCerts();
      setCerts(list);
      setError(null);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'load failed');
    }
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  async function onRenew(c: Cert) {
    if (!window.confirm(`Force renewal check for ${c.domain}?\n\nCaddy renews only certs inside the ~30-day window; this is a no-op for fresh certs.`)) {
      return;
    }
    setRenewing(c.host_id);
    try {
      const r = await api.renewCert(c.host_id);
      toasts.push(r.message || `renewal queued for ${r.domain}`, 'success');
      setTimeout(() => {
        void load();
      }, 5000);
    } catch (err) {
      toasts.push(err instanceof ApiError ? err.message : 'renew failed', 'error');
    } finally {
      setRenewing(null);
    }
  }

  return (
    <>
      <p className="text-xs text-slate-500 mb-3">
        Hosts with <code className="font-mono">tls_mode=auto</code>. Caddy renews these certs
        automatically inside the ~30-day window; the Renew now button re-pushes the config so
        that check runs on demand.
      </p>

      {error && (
        <div className="mb-4 px-3 py-2 rounded bg-red-950/40 border border-red-900 text-sm text-red-300">
          {error}
        </div>
      )}

      <div className="bg-slate-900 border border-slate-800 rounded-lg overflow-hidden">
        <table className="w-full text-sm">
          <thead className="bg-slate-950/60 text-slate-400 uppercase text-xs tracking-wide">
            <tr>
              <th className="text-left px-4 py-2">Domain</th>
              <th className="text-left px-4 py-2">Issuer</th>
              <th className="text-left px-4 py-2">Challenge</th>
              <th className="text-left px-4 py-2">Status</th>
              <th className="text-left px-4 py-2">Days left</th>
              <th className="text-left px-4 py-2">Last event</th>
              <th className="text-left px-4 py-2">Next renewal</th>
              <th className="text-right px-4 py-2">Actions</th>
            </tr>
          </thead>
          <tbody>
            {certs === null && (
              <tr>
                <td colSpan={8} className="px-4 py-4 text-slate-500">
                  loading...
                </td>
              </tr>
            )}
            {certs !== null && certs.length === 0 && (
              <tr>
                <td colSpan={8} className="px-4 py-4 text-slate-500">
                  no certificates issued yet. Add a host with tls_mode=auto to get one.
                </td>
              </tr>
            )}
            {certs?.map((c) => (
              <tr key={c.domain} className="border-t border-slate-800">
                <td className="px-4 py-2 font-mono">{c.domain}</td>
                <td className="px-4 py-2 text-slate-300">{c.issuer || '—'}</td>
                <td className="px-4 py-2">
                  <ChallengeBadge challenge={c.challenge} />
                </td>
                <td className="px-4 py-2">
                  <CertStatusBadge status={c.status} />
                </td>
                <td
                  className="px-4 py-2 font-mono text-slate-300"
                  title={c.not_after ? new Date(c.not_after).toLocaleString() : undefined}
                >
                  {formatDays(c.status, c.days_left)}
                </td>
                <td className="px-4 py-2 text-slate-400">
                  {c.last_renewal_event ? (
                    <Link
                      to={`/logs?source=caddy_error&q=${encodeURIComponent(c.domain)}`}
                      className="flex items-center gap-1 hover:text-slate-200"
                      title={c.last_renewal_event.message}
                    >
                      <EventDot success={c.last_renewal_event.success} />
                      <RelativeTime iso={c.last_renewal_event.timestamp} thresholdHours={24 * 30} />
                    </Link>
                  ) : (
                    <span className="text-slate-600">—</span>
                  )}
                </td>
                <td className="px-4 py-2 text-slate-400">
                  {c.status === 'unknown' || !c.next_renewal_estimate ? (
                    <span className="text-slate-600">—</span>
                  ) : (
                    <RelativeTime iso={c.next_renewal_estimate} thresholdHours={24 * 60} />
                  )}
                </td>
                <td className="px-4 py-2 text-right">
                  <button
                    type="button"
                    onClick={() => void onRenew(c)}
                    disabled={renewing === c.host_id || c.status === 'unknown'}
                    className="inline-flex items-center gap-1 px-2 py-1 rounded border border-slate-700 hover:bg-slate-800 text-xs text-slate-300 disabled:opacity-40 disabled:cursor-not-allowed"
                    title="Ask Caddy to re-check this cert; renewal only fires inside the ~30-day window"
                  >
                    <RefreshCw className={`w-3 h-3 ${renewing === c.host_id ? 'animate-spin' : ''}`} />
                    {renewing === c.host_id ? 'renewing' : 'Renew now'}
                  </button>
                  <Link
                    to={`/logs?source=caddy_error&q=${encodeURIComponent(c.domain)}`}
                    className="ml-1 inline-flex items-center gap-1 px-2 py-1 rounded border border-slate-700 hover:bg-slate-800 text-xs text-slate-300"
                    title="open caddy error log filtered by this domain"
                  >
                    <FileText className="w-3 h-3" /> Logs
                  </Link>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </>
  );
}

function formatDays(status: Cert['status'], days: number): string {
  if (status === 'unknown') return 'pending';
  if (status === 'expired') return `${Math.abs(days)}d ago`;
  if (days === 0) return 'today';
  return `${days}d`;
}

function ChallengeBadge({ challenge }: { challenge?: TLSChallenge }) {
  if (!challenge) {
    return <span className="text-xs text-slate-500">—</span>;
  }
  const label = challenge === 'tls-alpn' ? 'TLS-ALPN-01' : challenge === 'http' ? 'HTTP-01' : 'DNS-01';
  return (
    <span className="text-xs px-2 py-0.5 rounded bg-slate-800 text-slate-300 font-mono">
      {label}
    </span>
  );
}

function EventDot({ success }: { success: boolean }) {
  return (
    <span
      className={`inline-block w-1.5 h-1.5 rounded-full ${success ? 'bg-emerald-500' : 'bg-red-500'}`}
      aria-label={success ? 'success' : 'failure'}
    />
  );
}
