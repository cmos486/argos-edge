import { useCallback, useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { FileText, Shield } from 'lucide-react';
import { ApiError, SecurityOverview, api } from '../api/client';
import { useToasts } from '../components/toastsContext';

export default function SecurityOverviewPage() {
  const toasts = useToasts();
  const [ov, setOV] = useState<SecurityOverview | null>(null);

  const refresh = useCallback(async () => {
    try {
      const v = await api.securityOverview();
      setOV(v);
    } catch (e) {
      toasts.push(e instanceof ApiError ? e.message : 'load failed', 'error');
    }
  }, [toasts]);

  useEffect(() => {
    refresh();
    const t = setInterval(refresh, 30_000);
    return () => clearInterval(t);
  }, [refresh]);

  return (
    <div className="p-6 max-w-6xl mx-auto">
      <h1 className="text-2xl font-semibold mb-4">Security overview</h1>

      {ov && (
        <div className="grid grid-cols-4 gap-3 mb-4">
          <Card label="WAF enabled" value={`${ov.waf_block_count + ov.waf_detect_count} hosts`}
                sub={`${ov.waf_block_count} block · ${ov.waf_detect_count} detect · ${ov.waf_off_count} off`} />
          <Card label="Rate limited" value={`${ov.rate_limit_on_count} hosts`} />
          <Card label="Blocked 24h" value={String(ov.blocked_24h_total)} cls="text-red-300" />
          <Card label="Critical alerts 24h" value={String(ov.alerts_critical_24h)} cls="text-red-300" />
        </div>
      )}

      <div className="bg-slate-900 border border-slate-800 rounded-lg overflow-hidden">
        <table className="w-full text-sm">
          <thead className="bg-slate-950/60 text-slate-400 uppercase text-xs tracking-wide">
            <tr>
              <th className="text-left px-4 py-2">Domain</th>
              <th className="text-left px-4 py-2">WAF</th>
              <th className="text-left px-4 py-2">Paranoia</th>
              <th className="text-left px-4 py-2">Rate limit</th>
              <th className="text-left px-4 py-2">Blocked 24h</th>
              <th className="text-left px-4 py-2">Last triggered</th>
              <th className="text-right px-4 py-2">Actions</th>
            </tr>
          </thead>
          <tbody>
            {(ov?.hosts ?? []).map((h) => (
              <tr key={h.host_id} className="border-t border-slate-800">
                <td className="px-4 py-2 font-mono">{h.domain}</td>
                <td className="px-4 py-2">{wafBadge(h)}</td>
                <td className="px-4 py-2 font-mono">{h.waf_enabled ? h.waf_paranoia : '—'}</td>
                <td className="px-4 py-2">
                  <span className={`text-xs px-2 py-0.5 rounded ${
                    h.rate_limit_enabled ? 'bg-sky-900 text-sky-200' : 'bg-slate-800 text-slate-400'
                  }`}>
                    {h.rate_limit_enabled ? 'on' : 'off'}
                  </span>
                </td>
                <td className="px-4 py-2 font-mono text-slate-300">{h.blocked_24h}</td>
                <td className="px-4 py-2 text-slate-400">
                  {h.last_triggered_at ? new Date(h.last_triggered_at).toLocaleString() : '—'}
                </td>
                <td className="px-4 py-2 text-right">
                  <Link
                    to={`/hosts/${h.host_id}/security`}
                    className="inline-flex items-center gap-1 px-2 py-1 rounded border border-slate-700 hover:bg-slate-800 text-xs text-slate-300"
                  >
                    <Shield className="w-3 h-3" /> Configure
                  </Link>
                  <Link
                    to={`/logs?source=waf_audit&host_id=${h.host_id}`}
                    className="ml-1 inline-flex items-center gap-1 px-2 py-1 rounded border border-slate-700 hover:bg-slate-800 text-xs text-slate-300"
                  >
                    <FileText className="w-3 h-3" /> Logs
                  </Link>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

function wafBadge(h: SecurityOverview['hosts'][number]) {
  if (!h.waf_enabled) {
    return <span className="text-xs px-2 py-0.5 rounded bg-slate-800 text-slate-400">off</span>;
  }
  if (h.waf_mode === 'block') {
    return <span className="text-xs px-2 py-0.5 rounded bg-red-900 text-red-200">block</span>;
  }
  return <span className="text-xs px-2 py-0.5 rounded bg-amber-900 text-amber-200">detect</span>;
}

function Card({ label, value, sub, cls }: { label: string; value: string; sub?: string; cls?: string }) {
  return (
    <div className="bg-slate-900 border border-slate-800 rounded p-3">
      <div className="text-xs uppercase text-slate-500 tracking-wide">{label}</div>
      <div className={`text-xl font-semibold ${cls ?? 'text-slate-200'}`}>{value}</div>
      {sub && <div className="text-xs text-slate-500 mt-1">{sub}</div>}
    </div>
  );
}
