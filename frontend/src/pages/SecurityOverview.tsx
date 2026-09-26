import { useCallback, useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { FileText, Shield } from 'lucide-react';
import { ApiError, SecurityOverview, api } from '../api/client';
import RelativeTime from '../components/RelativeTime';
import { SkeletonCards, SkeletonTable } from '../components/Skeleton';
import { useToasts } from '../components/toastsContext';
import { getLastKnown, setLastKnown } from '../api/lastKnown';

const KEY = 'security:overview';

export default function SecurityOverviewPage() {
  const toasts = useToasts();
  // v1.3.38.5: last-known value first, skeleton only on a cold session.
  const [ov, setOV] = useState<SecurityOverview | null>(() => getLastKnown(KEY));

  const refresh = useCallback(async () => {
    try {
      const v = await api.securityOverview();
      setLastKnown(KEY, v);
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
    <div className="p-6 max-w-[1400px] mx-auto">
      <h1 className="text-2xl font-semibold mb-4">Security overview</h1>

      {!ov && (
        <div className="space-y-4">
          <SkeletonCards count={4} cols="grid-cols-4" />
          <div className="bg-slate-900 border border-slate-800 rounded-lg p-4">
            <SkeletonTable rows={6} cols={7} />
          </div>
        </div>
      )}

      {ov && (
        <div className="grid grid-cols-4 gap-3 mb-4">
          {/* v1.3.39: two engines, named. Coraza off on every host is a
              state, not an alarm, while AppSec is in block mode. */}
          <Card
            label="WAF engines"
            value={`AppSec: ${ov.appsec_mode}`}
            sub={`Coraza per host: ${ov.waf_off_count === ov.hosts.length ? `off on ${ov.waf_off_count} hosts` : `${ov.waf_block_count} block · ${ov.waf_detect_count} detect · ${ov.waf_off_count} off`}`}
            cls={ov.appsec_mode === 'block' ? 'text-emerald-300' : ov.appsec_mode === 'detect' ? 'text-amber-300' : 'text-slate-400'}
          />
          <Card label="Rate limited" value={`${ov.rate_limit_on_count} hosts`} />
          <Card
            label="Blocked 24h"
            value={ov.blocked_24h_total.toLocaleString()}
            cls="text-red-300"
            sub={ov.appsec_error
              ? `AppSec unavailable: ${ov.appsec_error}`
              : `AppSec ${(ov.appsec_hits_24h + ov.appsec_bans_24h).toLocaleString()} (${ov.appsec_hits_24h.toLocaleString()} hits · ${ov.appsec_bans_24h.toLocaleString()} bans) · Coraza ${ov.blocked_24h_by_engine.coraza.toLocaleString()}`}
            title="AppSec: hits are alerts (one per request), bans are bucket overflows that produced a decision; whether a hit was blocked or only detected is attributed by the mode active at the time. Coraza: audit rows at ERROR/CRITICAL."
          />
          <Card label="Critical alerts 24h (Coraza)" value={String(ov.alerts_critical_24h)} cls="text-red-300" />
        </div>
      )}

      {ov && (
      <div className="bg-slate-900 border border-slate-800 rounded-lg overflow-hidden">
        <table className="w-full text-sm">
          <thead className="bg-slate-950/60 text-slate-400 uppercase text-xs tracking-wide">
            <tr>
              <th className="text-left px-4 py-2">Domain</th>
              <th className="text-left px-4 py-2">Engine</th>
              <th className="text-left px-4 py-2">Coraza</th>
              <th className="text-left px-4 py-2">Paranoia</th>
              <th className="text-left px-4 py-2">Rate limit</th>
              <th className="text-left px-4 py-2">Blocked 24h</th>
              <th className="text-left px-4 py-2">Last triggered</th>
              <th className="text-right px-4 py-2">Actions</th>
            </tr>
          </thead>
          <tbody>
            {ov.hosts.map((h) => (
              <tr key={h.host_id} className="border-t border-slate-800">
                <td className="px-4 py-2 font-mono">{h.domain}</td>
                <td className="px-4 py-2">{engineBadge(h.engine)}</td>
                <td className="px-4 py-2">{wafBadge(h)}</td>
                <td className="px-4 py-2 font-mono">{h.waf_enabled ? h.waf_paranoia : '—'}</td>
                <td className="px-4 py-2">
                  <span className={`text-xs px-2 py-0.5 rounded ${
                    h.rate_limit_enabled ? 'bg-sky-900 text-sky-200' : 'bg-slate-800 text-slate-400'
                  }`}>
                    {h.rate_limit_enabled ? 'on' : 'off'}
                  </span>
                </td>
                <td className="px-4 py-2 font-mono text-slate-300" title={`AppSec hits ${h.appsec_hits_24h} · Coraza ${h.coraza_24h}`}>
                  {h.blocked_24h}
                  {h.blocked_24h > 0 && (
                    <span className="ml-1 text-[10px] text-slate-500">
                      {h.appsec_hits_24h > 0 && h.coraza_24h > 0 ? `${h.appsec_hits_24h}a/${h.coraza_24h}c` : h.coraza_24h > 0 ? 'coraza' : 'appsec'}
                    </span>
                  )}
                </td>
                <td className="px-4 py-2 text-slate-400">
                  {/* A zero time (no event ever) serialises as year 0001. */}
                  {h.last_triggered_at && !h.last_triggered_at.startsWith('0001-') ? <RelativeTime iso={h.last_triggered_at} /> : 'never'}
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
      )}
    </div>
  );
}

function engineBadge(engine: SecurityOverview['hosts'][number]['engine']) {
  const cls: Record<string, string> = {
    'appsec': 'bg-sky-900 text-sky-200',
    'coraza': 'bg-violet-900 text-violet-200',
    'coraza+appsec': 'bg-violet-900 text-violet-200',
    'none': 'bg-slate-800 text-slate-400',
  };
  return <span className={`text-xs px-2 py-0.5 rounded ${cls[engine] ?? cls.none}`}>{engine}</span>;
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

function Card({ label, value, sub, cls, title }: { label: string; value: string; sub?: string; cls?: string; title?: string }) {
  return (
    <div className="bg-slate-900 border border-slate-800 rounded p-3" title={title}>
      <div className="text-xs uppercase text-slate-500 tracking-wide">{label}</div>
      <div className={`text-xl font-semibold ${cls ?? 'text-slate-200'}`}>{value}</div>
      {sub && <div className="text-xs text-slate-500 mt-1">{sub}</div>}
    </div>
  );
}
