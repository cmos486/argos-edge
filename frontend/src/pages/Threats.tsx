import { FormEvent, useCallback, useEffect, useMemo, useState } from 'react';
import {
  AlertTriangle,
  Ban,
  CheckCircle2,
  Clock,
  FileWarning,
  Radio,
  RefreshCw,
  Shield,
  Trash2,
  XCircle,
} from 'lucide-react';
import {
  ApiError,
  ThreatCollection,
  ThreatDecision,
  ThreatsStats,
  ThreatsStatus,
  api,
} from '../api/client';
import GeoFlag from '../components/GeoFlag';
import RelativeTime from '../components/RelativeTime';
import { useToasts } from '../components/toastsContext';

const REFRESH_MS = 15_000;

export default function Threats() {
  const [status, setStatus] = useState<ThreatsStatus | null>(null);
  const [decisions, setDecisions] = useState<ThreatDecision[] | null>(null);
  const [stats, setStats] = useState<ThreatsStats | null>(null);
  const [scenarios, setScenarios] = useState<ThreatCollection[] | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [filterOrigin, setFilterOrigin] = useState('');
  const [filterType, setFilterType] = useState('');
  const [search, setSearch] = useState('');

  const refresh = useCallback(async () => {
    try {
      const [s, sc, ss, st] = await Promise.all([
        api.threatsStatus(),
        api.threatsScenarios(),
        api.threatsStats(),
        api.threatsDecisions({
          origin: filterOrigin,
          type: filterType,
          search: search,
        }),
      ]);
      setStatus(s);
      setScenarios(sc);
      setStats(ss);
      setDecisions(st);
      setErr(null);
    } catch (e) {
      setErr(e instanceof ApiError ? e.message : 'load failed');
    }
  }, [filterOrigin, filterType, search]);

  useEffect(() => {
    refresh();
    const id = setInterval(refresh, REFRESH_MS);
    return () => clearInterval(id);
  }, [refresh]);

  return (
    <div className="p-6 max-w-6xl mx-auto space-y-4">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-semibold flex items-center gap-2">
          <Shield className="w-6 h-6 text-sky-400" />
          Threats
        </h1>
        <button
          type="button"
          onClick={refresh}
          className="flex items-center gap-1 px-2 py-1 rounded border border-slate-700 hover:bg-slate-800 text-xs"
        >
          <RefreshCw className="w-3 h-3" />
          refresh
        </button>
      </div>

      {err && (
        <div className="px-3 py-2 rounded bg-red-950/40 border border-red-900 text-sm text-red-300">
          {err}
        </div>
      )}

      {status?.state === 'not_configured' && <SetupBanner />}

      {/* status cards */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        <StatusCard status={status} />
        <StatCard
          icon={<Ban className="w-5 h-5" />}
          label="Active decisions"
          value={stats ? String(stats.active_decisions) : '—'}
        />
        <StatCard
          icon={<Radio className="w-5 h-5" />}
          label="Top origin"
          value={topKey(stats?.by_origin) ?? '—'}
          sub={topValue(stats?.by_origin) ?? ''}
        />
        <StatCard
          icon={<FileWarning className="w-5 h-5" />}
          label="Top scenario"
          value={topKey(stats?.by_scenario) ?? '—'}
          sub={topValue(stats?.by_scenario) ?? ''}
          truncate
        />
      </div>

      {/* decisions */}
      <section className="bg-slate-900 border border-slate-800 rounded-lg p-4">
        <div className="flex items-center justify-between mb-3">
          <h2 className="text-lg font-semibold">Active decisions</h2>
          <div className="flex gap-2 text-xs">
            <select
              value={filterOrigin}
              onChange={(e) => setFilterOrigin(e.target.value)}
              className="px-2 py-1 rounded bg-slate-800 border border-slate-700"
            >
              <option value="">all origins</option>
              <option value="CAPI">CAPI (community)</option>
              <option value="crowdsec">crowdsec (local)</option>
              <option value="cscli">cscli</option>
              <option value="argos-panel">argos-panel (manual)</option>
              <option value="manual">manual</option>
            </select>
            <select
              value={filterType}
              onChange={(e) => setFilterType(e.target.value)}
              className="px-2 py-1 rounded bg-slate-800 border border-slate-700"
            >
              <option value="">all types</option>
              <option value="ban">ban</option>
              <option value="captcha">captcha</option>
            </select>
            <input
              type="text"
              placeholder="search IP or scenario"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="px-2 py-1 rounded bg-slate-800 border border-slate-700 font-mono w-48"
            />
          </div>
        </div>

        {!decisions ? (
          <Loading />
        ) : decisions.length === 0 ? (
          <Empty msg="No active decisions" />
        ) : (
          <DecisionsTable rows={decisions} onRemoved={refresh} />
        )}
      </section>

      {/* Add manual ban */}
      <AddDecisionForm onAdded={refresh} disabled={!status?.machine_ok} />

      {/* Collections & scenarios */}
      <section className="bg-slate-900 border border-slate-800 rounded-lg p-4">
        <h2 className="text-lg font-semibold mb-3">Collections</h2>
        {!scenarios ? (
          <Loading />
        ) : (
          <div className="space-y-3">
            {scenarios.map((c) => (
              <div key={c.name} className="border border-slate-800 rounded p-3">
                <div className="flex items-center justify-between">
                  <a
                    href={`https://docs.crowdsec.net/docs/collections/${c.name.replace('crowdsecurity/', '')}`}
                    target="_blank"
                    rel="noreferrer"
                    className="font-mono text-sm text-sky-400 hover:underline"
                  >
                    {c.name}
                  </a>
                  <span className="text-xs text-slate-500">{c.version}</span>
                </div>
                {c.scenarios && c.scenarios.length > 0 && (
                  <div className="mt-2 flex flex-wrap gap-1">
                    {c.scenarios.map((s) => (
                      <code
                        key={s}
                        className="text-[10px] px-1.5 py-0.5 rounded bg-slate-800 text-slate-400"
                      >
                        {s}
                      </code>
                    ))}
                  </div>
                )}
              </div>
            ))}
            <div className="px-3 py-2 rounded bg-slate-950/60 border border-slate-800 text-xs text-slate-400">
              To install more collections:{' '}
              <code className="font-mono">docker compose exec argos-crowdsec cscli collections install &lt;name&gt;</code>
            </div>
          </div>
        )}
      </section>
    </div>
  );
}

function SetupBanner() {
  return (
    <div className="px-4 py-3 rounded bg-amber-950/40 border border-amber-900 text-amber-200 text-sm space-y-2">
      <div className="font-semibold flex items-center gap-2">
        <AlertTriangle className="w-4 h-4" /> CrowdSec one-time setup required
      </div>
      <p>
        CrowdSec LAPI is running but the panel cannot read decisions yet. Run the following on
        the host (Docker Compose LXC) to provision the bouncer + panel credentials:
      </p>
      <pre className="text-xs bg-slate-950/60 border border-slate-800 rounded p-2 overflow-x-auto text-slate-300">{`docker compose exec argos-crowdsec cscli bouncers add argos-caddy-bouncer
# copy the API key printed -> .env as CROWDSEC_BOUNCER_API_KEY=<key>

docker compose exec argos-crowdsec cscli machines add argos-panel -a -f /tmp/argos-panel.yaml
docker compose exec argos-crowdsec cat /tmp/argos-panel.yaml
# copy login / password -> .env:
#   CROWDSEC_PANEL_MACHINE_USER=argos-panel
#   CROWDSEC_PANEL_MACHINE_PASSWORD=<password>

docker compose up -d  # restart stack`}</pre>
    </div>
  );
}

function StatusCard({ status }: { status: ThreatsStatus | null }) {
  const state = status?.state ?? 'loading';
  const cls: Record<string, string> = {
    connected: 'bg-emerald-900 text-emerald-200',
    not_configured: 'bg-amber-900 text-amber-200',
    disconnected: 'bg-red-900 text-red-200',
    degraded: 'bg-amber-900 text-amber-200',
    loading: 'bg-slate-800 text-slate-400',
  };
  return (
    <div className="bg-slate-900 border border-slate-800 rounded-lg p-3">
      <div className="flex items-center gap-2 text-slate-400 text-xs mb-1">
        <Shield className="w-5 h-5" />
        <span>CrowdSec</span>
      </div>
      <div className="flex items-center gap-2">
        <span className={`text-xs px-2 py-0.5 rounded ${cls[state]}`}>{state}</span>
        {status?.lapi_version && (
          <span className="text-xs text-slate-500">v{status.lapi_version}</span>
        )}
      </div>
      {status?.last_heartbeat && (
        <div className="text-[10px] text-slate-500 mt-1">
          hb <RelativeTime iso={status.last_heartbeat} />
        </div>
      )}
    </div>
  );
}

function StatCard({
  icon,
  label,
  value,
  sub,
  truncate,
}: {
  icon: React.ReactNode;
  label: string;
  value: string;
  sub?: string;
  truncate?: boolean;
}) {
  return (
    <div className="bg-slate-900 border border-slate-800 rounded-lg p-3">
      <div className="flex items-center gap-2 text-slate-400 text-xs mb-1">
        {icon}
        <span>{label}</span>
      </div>
      <div className={`text-xl font-semibold ${truncate ? 'truncate' : ''}`} title={value}>
        {value}
      </div>
      {sub && <div className="text-xs text-slate-500 truncate">{sub}</div>}
    </div>
  );
}

function DecisionsTable({
  rows,
  onRemoved,
}: {
  rows: ThreatDecision[];
  onRemoved: () => void;
}) {
  const toasts = useToasts();
  async function onWhitelist(d: ThreatDecision) {
    if (!window.confirm(`Remove ban for ${d.value}?`)) return;
    try {
      const r = await api.deleteThreatDecision(d.value);
      toasts.push(`removed ${r.removed} decision(s) for ${d.value}`, 'success');
      onRemoved();
    } catch (e) {
      toasts.push(e instanceof ApiError ? e.message : 'whitelist failed', 'error');
    }
  }
  return (
    <table className="w-full text-sm">
      <thead className="text-slate-400 uppercase text-xs tracking-wide">
        <tr>
          <th className="text-left px-2 py-1">Value</th>
          <th className="text-left px-2 py-1">Location</th>
          <th className="text-left px-2 py-1">ASN</th>
          <th className="text-left px-2 py-1">Scope</th>
          <th className="text-left px-2 py-1">Type</th>
          <th className="text-left px-2 py-1">Origin</th>
          <th className="text-left px-2 py-1">Scenario</th>
          <th className="text-left px-2 py-1">Until</th>
          <th className="text-right px-2 py-1">Actions</th>
        </tr>
      </thead>
      <tbody>
        {rows.map((d) => (
          <tr key={d.id} className="border-t border-slate-800">
            <td className="px-2 py-1.5 font-mono">{d.value}</td>
            <td className="px-2 py-1.5 text-xs">
              {d.geo?.is_private ? (
                <span className="flex items-center gap-1"><GeoFlag isPrivate /><span className="text-slate-500">LAN</span></span>
              ) : d.geo?.country_code ? (
                <span className="flex items-center gap-1"><GeoFlag countryCode={d.geo.country_code} /><span>{d.geo.country_code}</span></span>
              ) : d.scope === 'Ip' ? (
                <span className="flex items-center gap-1"><GeoFlag /><span className="text-slate-500">—</span></span>
              ) : (
                <span className="text-slate-500">n/a</span>
              )}
            </td>
            <td className="px-2 py-1.5 text-xs font-mono text-slate-400 truncate max-w-[180px]" title={d.geo?.asn_org || ''}>
              {d.geo?.asn_org ? (d.geo.asn_org.length > 20 ? d.geo.asn_org.slice(0, 20) + '…' : d.geo.asn_org) : '—'}
            </td>
            <td className="px-2 py-1.5 text-xs text-slate-400">{d.scope}</td>
            <td className="px-2 py-1.5">
              <span
                className={`text-xs px-2 py-0.5 rounded ${
                  d.type === 'ban'
                    ? 'bg-red-900 text-red-200'
                    : 'bg-amber-900 text-amber-200'
                }`}
              >
                {d.type}
              </span>
            </td>
            <td className="px-2 py-1.5 text-xs text-slate-400">{d.origin}</td>
            <td className="px-2 py-1.5 text-xs font-mono text-slate-400 truncate max-w-[280px]">
              {d.scenario}
            </td>
            <td className="px-2 py-1.5 text-xs text-slate-400 font-mono">
              {d.until ? (
                <span title={new Date(d.until).toLocaleString()}>
                  {remainingFor(d.until)}
                </span>
              ) : (
                '—'
              )}
            </td>
            <td className="px-2 py-1.5 text-right">
              <button
                type="button"
                onClick={() => onWhitelist(d)}
                aria-label="whitelist"
                title="whitelist"
                className="p-1.5 rounded border border-slate-700 hover:bg-slate-800 text-emerald-400"
              >
                <Trash2 className="w-3.5 h-3.5" />
              </button>
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

function AddDecisionForm({
  onAdded,
  disabled,
}: {
  onAdded: () => void;
  disabled: boolean;
}) {
  const toasts = useToasts();
  const [ip, setIp] = useState('');
  const [hours, setHours] = useState('1');
  const [reason, setReason] = useState('');
  const [submitting, setSubmitting] = useState(false);

  async function onSubmit(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    if (!ip) return;
    setSubmitting(true);
    try {
      await api.addThreatDecision({
        ip,
        duration_hours: Number(hours),
        reason: reason || 'manual ban via argos panel',
      });
      toasts.push(`banned ${ip} for ${hours}h`, 'success');
      setIp('');
      setReason('');
      onAdded();
    } catch (e) {
      toasts.push(e instanceof ApiError ? e.message : 'ban failed', 'error');
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <section className="bg-slate-900 border border-slate-800 rounded-lg p-4">
      <h2 className="text-lg font-semibold mb-3">Add manual ban</h2>
      {disabled && (
        <div className="mb-3 px-3 py-2 rounded bg-amber-950/40 border border-amber-900 text-amber-200 text-xs">
          Manual bans require CrowdSec <em>machine</em> credentials. See the setup banner above.
        </div>
      )}
      <form onSubmit={onSubmit} className="flex flex-wrap gap-2 items-end text-sm">
        <div>
          <label className="block text-slate-300 mb-1 text-xs">IP</label>
          <input
            type="text"
            required
            value={ip}
            onChange={(e) => setIp(e.target.value)}
            placeholder="203.0.113.99"
            className="px-3 py-2 rounded bg-slate-800 border border-slate-700 font-mono w-48"
          />
        </div>
        <div>
          <label className="block text-slate-300 mb-1 text-xs">Duration (hours)</label>
          <input
            type="number"
            min={1}
            max={8760}
            value={hours}
            onChange={(e) => setHours(e.target.value)}
            className="px-3 py-2 rounded bg-slate-800 border border-slate-700 font-mono w-24"
          />
        </div>
        <div className="flex-1 min-w-[200px]">
          <label className="block text-slate-300 mb-1 text-xs">Reason</label>
          <input
            type="text"
            value={reason}
            onChange={(e) => setReason(e.target.value)}
            placeholder="abuse / scanner / etc."
            className="w-full px-3 py-2 rounded bg-slate-800 border border-slate-700"
          />
        </div>
        <button
          type="submit"
          disabled={submitting || disabled || !ip}
          className="flex items-center gap-1 px-3 py-2 rounded bg-red-700 hover:bg-red-600 disabled:bg-slate-700 text-sm font-medium"
        >
          <Ban className="w-4 h-4" /> {submitting ? 'banning...' : 'Ban IP'}
        </button>
      </form>
    </section>
  );
}

function Loading() {
  return (
    <div className="flex items-center gap-2 text-slate-400 text-sm">
      <Clock className="w-4 h-4 animate-pulse" /> loading...
    </div>
  );
}

function Empty({ msg }: { msg: string }) {
  return (
    <div className="flex items-center gap-2 text-slate-500 text-sm">
      <CheckCircle2 className="w-4 h-4" /> {msg}
    </div>
  );
}

function topKey(m?: Record<string, number>): string | null {
  if (!m) return null;
  let k: string | null = null;
  let n = -1;
  for (const [key, val] of Object.entries(m)) {
    if (val > n) {
      n = val;
      k = key;
    }
  }
  return k;
}
function topValue(m?: Record<string, number>): string | null {
  if (!m) return null;
  const k = topKey(m);
  if (!k) return null;
  return `${m[k]} decisions`;
}
function remainingFor(iso: string): string {
  const d = new Date(iso).getTime();
  const s = Math.floor((d - Date.now()) / 1000);
  if (s <= 0) return 'expired';
  if (s < 3600) return `${Math.floor(s / 60)}m`;
  if (s < 86400) return `${Math.floor(s / 3600)}h`;
  return `${Math.floor(s / 86400)}d`;
}

// Silence unused imports in case lucide-react shakes
void XCircle;
void useMemo;
