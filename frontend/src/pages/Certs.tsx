import { useEffect, useState } from 'react';
import { ApiError, Cert, api } from '../api/client';

export default function Certs() {
  const [certs, setCerts] = useState<Cert[] | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    api
      .listCerts()
      .then((list) => {
        if (!cancelled) setCerts(list);
      })
      .catch((err) => {
        if (!cancelled) {
          setError(err instanceof ApiError ? err.message : 'load failed');
        }
      });
    return () => {
      cancelled = true;
    };
  }, []);

  return (
    <div className="p-6 max-w-5xl mx-auto">
      <h1 className="text-2xl font-semibold mb-4">Certificates</h1>

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
              <th className="text-left px-4 py-2">Expires in</th>
              <th className="text-left px-4 py-2">Status</th>
            </tr>
          </thead>
          <tbody>
            {certs === null && (
              <tr>
                <td colSpan={4} className="px-4 py-4 text-slate-500">
                  loading...
                </td>
              </tr>
            )}
            {certs !== null && certs.length === 0 && (
              <tr>
                <td colSpan={4} className="px-4 py-4 text-slate-500">
                  no certificates issued yet. Add a host with tls_mode=auto to get one.
                </td>
              </tr>
            )}
            {certs?.map((c) => {
              const days = daysUntil(c.not_after);
              return (
                <tr key={c.domain} className="border-t border-slate-800">
                  <td className="px-4 py-2 font-mono">{c.domain}</td>
                  <td className="px-4 py-2 text-slate-300">{c.issuer || '—'}</td>
                  <td
                    className="px-4 py-2"
                    title={c.not_after ? new Date(c.not_after).toLocaleString() : undefined}
                  >
                    {formatExpires(days)}
                  </td>
                  <td className="px-4 py-2">
                    <StatusBadge days={days} />
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
}

function daysUntil(iso: string): number {
  const t = new Date(iso).getTime();
  if (!Number.isFinite(t)) return Number.NaN;
  return Math.floor((t - Date.now()) / (24 * 3600 * 1000));
}

function formatExpires(days: number): string {
  if (!Number.isFinite(days)) return 'unknown';
  if (days < 0) return `expired ${Math.abs(days)}d ago`;
  if (days === 0) return 'today';
  return `${days}d`;
}

function StatusBadge({ days }: { days: number }) {
  if (!Number.isFinite(days)) {
    return <Pill cls="bg-slate-800 text-slate-400">unknown</Pill>;
  }
  if (days < 0) return <Pill cls="bg-red-900 text-red-200">expired</Pill>;
  if (days <= 14) return <Pill cls="bg-amber-900 text-amber-200">expiring</Pill>;
  return <Pill cls="bg-emerald-900 text-emerald-200">valid</Pill>;
}

function Pill({ children, cls }: { children: React.ReactNode; cls: string }) {
  return <span className={`text-xs px-2 py-0.5 rounded ${cls}`}>{children}</span>;
}
