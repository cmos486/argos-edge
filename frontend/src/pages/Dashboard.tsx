import { Component, ReactNode, Suspense, lazy, useCallback, useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import {
  Activity,
  AlertCircle,
  AlertTriangle,
  Archive,
  CheckCircle2,
  Globe,
  Loader2,
  Pause,
  Play,
  Server,
  Shield,
  ShieldAlert,
  XCircle,
  Zap,
} from 'lucide-react';
import {
  Area,
  AreaChart,
  CartesianGrid,
  Line,
  LineChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts';
import {
  ApiError,
  DashHealth,
  DashOverview,
  DashRange,
  DashSecurity,
  DashTraffic,
  DashWafEngines,
  GeoEnrichment,
  Host,
  SecurityDashboardStats,
  api,
} from '../api/client';
import { getLastKnown, setLastKnown } from '../api/lastKnown';
import GeoFlag from '../components/GeoFlag';
import RelativeTime from '../components/RelativeTime';
import { SkeletonCards, SkeletonCharts } from '../components/Skeleton';

// WorldMap drags in the world-atlas topology JSON (~108 KiB) plus
// react-simple-maps + d3-geo (~85 KiB min). Lazy so a user who lands
// on the dashboard but never scrolls to the security card STILL
// loads the map chunk (the component mounts when this page renders).
// A user who navigates directly to /hosts skips the chunk entirely.
const WorldMap = lazy(() => import('../components/WorldMap'));

const REFRESH_INTERVAL_MS = 30_000;

export default function Dashboard() {
  const [paused, setPaused] = useState(false);
  const [lastUpdated, setLastUpdated] = useState<number>(Date.now());
  const [tick, setTick] = useState(0);

  useEffect(() => {
    if (paused) return;
    const id = setInterval(() => setTick((t) => t + 1), REFRESH_INTERVAL_MS);
    return () => clearInterval(id);
  }, [paused]);

  // Stable identity: OverviewSection's effect depends on this callback.
  // An inline arrow here changes on every render, and every completed
  // fetch triggers a render (setLastUpdated), so the effect re-ran and
  // re-fetched /api/dashboard/overview in a tight loop (v1.3.38.0 fix).
  // v1.3.38.2: the age shown is the server's generated_at, not the time
  // the response arrived: the API may serve a cached value up to 30 s
  // old (stale-while-revalidate), and a 25 s old number must not read
  // as "updated 0s ago".
  const onOverviewLoaded = useCallback((generatedAt: string) => {
    const t = Date.parse(generatedAt);
    setLastUpdated(Number.isFinite(t) ? t : Date.now());
  }, []);

  return (
    <div className="p-6 max-w-[1400px] mx-auto space-y-8">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-semibold">Dashboard</h1>
        <RefreshControl
          paused={paused}
          onToggle={() => setPaused((p) => !p)}
          lastUpdated={lastUpdated}
        />
      </div>

      <ErrorBoundary name="Overview">
        <OverviewSection tick={tick} onLoaded={onOverviewLoaded} />
      </ErrorBoundary>

      <ErrorBoundary name="Traffic">
        <TrafficSection tick={tick} />
      </ErrorBoundary>

      <ErrorBoundary name="Security">
        <SecuritySection tick={tick} />
      </ErrorBoundary>

      <ErrorBoundary name="Bans & whitelist">
        <BansAndWhitelistSection tick={tick} />
      </ErrorBoundary>

      <ErrorBoundary name="Health">
        <HealthSection tick={tick} />
      </ErrorBoundary>
    </div>
  );
}

function RefreshControl({
  paused,
  onToggle,
  lastUpdated,
}: {
  paused: boolean;
  onToggle: () => void;
  lastUpdated: number;
}) {
  const [ago, setAgo] = useState(0);
  useEffect(() => {
    const id = setInterval(() => setAgo(Math.floor((Date.now() - lastUpdated) / 1000)), 1000);
    return () => clearInterval(id);
  }, [lastUpdated]);
  return (
    <div className="flex items-center gap-2 text-xs text-slate-400">
      <span>updated {ago}s ago</span>
      <button
        type="button"
        onClick={onToggle}
        className="flex items-center gap-1 px-2 py-1 rounded border border-slate-700 hover:bg-slate-800"
        title={paused ? 'resume auto-refresh' : 'pause auto-refresh'}
      >
        {paused ? <Play className="w-3 h-3" /> : <Pause className="w-3 h-3" />}
        <span>{paused ? 'paused' : 'auto 30s'}</span>
      </button>
    </div>
  );
}

// ================ Overview ================

// Every section keeps its last-known response in memory (api/lastKnown)
// keyed by its query, so a revisit or a range already seen paints at
// once and refreshes behind; a skeleton only shows for a view this
// session has never had (v1.3.38.5).
const KEY_OVERVIEW = 'dash:overview';
const KEY_BANS = 'dash:bans';
const KEY_HEALTH = 'dash:health';
const keyTraffic = (range: DashRange, hostID: number) => `dash:traffic:${range}:${hostID}`;
const keySecurity = (range: DashRange) => `dash:security:${range}`;

function OverviewSection({ tick, onLoaded }: { tick: number; onLoaded: (generatedAt: string) => void }) {
  const [data, setData] = useState<DashOverview | null>(() => getLastKnown(KEY_OVERVIEW));
  const [err, setErr] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    api
      .dashboardOverview()
      .then((d) => {
        if (cancelled) return;
        setLastKnown(KEY_OVERVIEW, d);
        setData(d);
        setErr(null);
        onLoaded(d.generated_at);
      })
      .catch((e) => {
        if (cancelled) return;
        setErr(e instanceof ApiError ? e.message : 'load failed');
      });
    return () => {
      cancelled = true;
    };
  }, [tick, onLoaded]);

  if (err) return <SectionError msg={err} />;
  if (!data) {
    return (
      <section>
        <h2 className="text-lg font-semibold mb-3 text-slate-300">Overview (last 24h)</h2>
        <SkeletonCards count={6} cols="grid-cols-2 md:grid-cols-3 lg:grid-cols-6" />
      </section>
    );
  }

  const blockedSuspicious = data.blocked_requests_24h > 0;
  const errorsSuspicious = data.error_requests_24h > 0;
  const unhealthySuspicious = data.unhealthy_targets > 0;
  const certBadge =
    data.certs_expiring_soon > 0 ? 'bg-amber-900 text-amber-200' : 'bg-slate-800 text-slate-300';
  const backupBadge =
    data.last_backup_status === 'ok'
      ? 'bg-emerald-900 text-emerald-200'
      : data.last_backup_status === 'stale'
        ? 'bg-red-900 text-red-200'
        : 'bg-slate-800 text-slate-400';

  return (
    <section>
      <h2 className="text-lg font-semibold mb-3 text-slate-300">Overview (last 24h)</h2>
      <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-3">
        <OverviewCard
          icon={<Activity className="w-5 h-5" />}
          label="Requests"
          value={fmtNumber(data.total_requests_24h)}
          to="/logs?source=caddy_access"
        />
        <OverviewCard
          icon={<ShieldAlert className="w-5 h-5" />}
          label="Blocked"
          value={fmtNumber(data.blocked_requests_24h)}
          tone={blockedSuspicious ? 'warn' : 'neutral'}
          to="/logs?source=caddy_access&status=403,429"
        />
        <OverviewCard
          icon={<AlertCircle className="w-5 h-5" />}
          label="Errors 5xx"
          value={fmtNumber(data.error_requests_24h)}
          tone={errorsSuspicious ? 'bad' : 'neutral'}
          to="/logs?source=caddy_access&status=5xx"
        />
        <OverviewCard
          icon={<Globe className="w-5 h-5" />}
          label="Active hosts"
          value={String(data.active_hosts)}
          to="/hosts"
        />
        <OverviewCard
          icon={<Server className="w-5 h-5" />}
          label="Unhealthy targets"
          value={String(data.unhealthy_targets)}
          tone={unhealthySuspicious ? 'warn' : 'neutral'}
          to="/target-groups"
        />
        <OverviewCard
          icon={<Shield className="w-5 h-5" />}
          label="Certs ≤14d"
          value={String(data.certs_expiring_soon)}
          badgeClass={certBadge}
          to="/certificates"
        />
        <OverviewCard
          icon={<Archive className="w-5 h-5" />}
          label="Last backup"
          value={
            data.last_backup_at
              ? <RelativeTime iso={data.last_backup_at} />
              : '—'
          }
          badgeClass={backupBadge}
          badgeLabel={data.last_backup_status}
          to="/backup"
        />
      </div>
    </section>
  );
}

function OverviewCard({
  icon,
  label,
  value,
  tone,
  to,
  badgeClass,
  badgeLabel,
}: {
  icon: ReactNode;
  label: string;
  // ReactNode so a card can render a live component (RelativeTime)
  // in place of a precomputed string -- the "last backup" card uses
  // this to get the rolling "2 hours ago" label.
  value: ReactNode;
  tone?: 'bad' | 'warn' | 'neutral';
  to: string;
  badgeClass?: string;
  badgeLabel?: string;
}) {
  const border =
    tone === 'bad'
      ? 'border-red-900/60 hover:border-red-800'
      : tone === 'warn'
        ? 'border-amber-900/60 hover:border-amber-800'
        : 'border-slate-800 hover:border-slate-700';
  return (
    <Link
      to={to}
      className={`bg-slate-900 border rounded-lg p-3 block ${border}`}
    >
      <div className="flex items-center gap-2 text-slate-400 text-xs mb-1">
        {icon}
        <span>{label}</span>
      </div>
      <div className="flex items-center justify-between">
        <div className="text-xl font-semibold truncate">{value}</div>
        {badgeLabel && badgeClass && (
          <span className={`text-[10px] px-1.5 py-0.5 rounded ${badgeClass}`}>{badgeLabel}</span>
        )}
      </div>
    </Link>
  );
}

// ================ Traffic ================

function TrafficSection({ tick }: { tick: number }) {
  const [range, setRange] = useState<DashRange>('24h');
  const [hostID, setHostID] = useState<number>(0);
  const [hosts, setHosts] = useState<Host[]>([]);
  const [data, setData] = useState<DashTraffic | null>(() => getLastKnown(keyTraffic('24h', 0)));
  const [err, setErr] = useState<string | null>(null);

  useEffect(() => {
    api.listHosts().then(setHosts).catch(() => {});
  }, []);

  useEffect(() => {
    let cancelled = false;
    const key = keyTraffic(range, hostID);
    setData(getLastKnown(key));
    api
      .dashboardTraffic(range, hostID || undefined)
      .then((d) => {
        if (cancelled) return;
        setLastKnown(key, d);
        setData(d);
        setErr(null);
      })
      .catch((e) => {
        if (cancelled) return;
        setErr(e instanceof ApiError ? e.message : 'load failed');
      });
    return () => {
      cancelled = true;
    };
  }, [range, hostID, tick]);

  return (
    <section>
      <div className="flex items-center justify-between mb-3">
        <h2 className="text-lg font-semibold text-slate-300 flex items-center gap-2">
          <Zap className="w-5 h-5 text-sky-400" /> Traffic
        </h2>
        <div className="flex items-center gap-2 text-xs">
          <select
            value={hostID}
            onChange={(e) => setHostID(Number(e.target.value))}
            className="px-2 py-1 rounded bg-slate-800 border border-slate-700"
          >
            <option value={0}>all hosts</option>
            {hosts.map((h) => (
              <option key={h.id} value={h.id}>
                {h.domain}
              </option>
            ))}
          </select>
          <RangeSelect value={range} onChange={setRange} />
        </div>
      </div>

      {err ? (
        <SectionError msg={err} />
      ) : !data ? (
        <SkeletonCharts count={2} />
      ) : (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
          <ChartCard title={data.series_covers_range === false ? `Requests by status class (last ${windowLabel(data.detail_window)} of range)` : 'Requests by status class'}>
            <ResponsiveContainer width="100%" height={200}>
              <AreaChart data={data.timeseries.map((b) => ({ ...b, t: fmtTick(b.time, range) }))}>
                <CartesianGrid stroke="#1e293b" strokeDasharray="3 3" />
                <XAxis dataKey="t" fontSize={10} stroke="#64748b" />
                <YAxis fontSize={10} stroke="#64748b" />
                <Tooltip contentStyle={tooltipStyle} />
                <Area
                  type="monotone"
                  dataKey="c2xx"
                  stackId="1"
                  stroke="#10b981"
                  fill="#10b981"
                  fillOpacity={0.6}
                />
                <Area
                  type="monotone"
                  dataKey="c3xx"
                  stackId="1"
                  stroke="#eab308"
                  fill="#eab308"
                  fillOpacity={0.6}
                />
                <Area
                  type="monotone"
                  dataKey="c4xx"
                  stackId="1"
                  stroke="#f97316"
                  fill="#f97316"
                  fillOpacity={0.6}
                />
                <Area
                  type="monotone"
                  dataKey="c5xx"
                  stackId="1"
                  stroke="#ef4444"
                  fill="#ef4444"
                  fillOpacity={0.7}
                />
              </AreaChart>
            </ResponsiveContainer>
            <LegendRow
              items={[
                ['2xx', '#10b981'],
                ['3xx', '#eab308'],
                ['4xx', '#f97316'],
                ['5xx', '#ef4444'],
              ]}
            />
          </ChartCard>

          <ChartCard title={data.detail_window ? `Response time percentiles (ms, last ${windowLabel(data.detail_window)} of range)` : 'Response time percentiles (ms)'}>
            <ResponsiveContainer width="100%" height={200}>
              <LineChart data={data.response_times.map((b) => ({ ...b, t: fmtTick(b.time, range) }))}>
                <CartesianGrid stroke="#1e293b" strokeDasharray="3 3" />
                <XAxis dataKey="t" fontSize={10} stroke="#64748b" />
                <YAxis fontSize={10} stroke="#64748b" />
                <Tooltip contentStyle={tooltipStyle} />
                <Line type="monotone" dataKey="p50_ms" stroke="#38bdf8" dot={false} />
                <Line type="monotone" dataKey="p95_ms" stroke="#a78bfa" dot={false} />
                <Line type="monotone" dataKey="p99_ms" stroke="#f472b6" dot={false} />
              </LineChart>
            </ResponsiveContainer>
            <LegendRow
              items={[
                ['p50', '#38bdf8'],
                ['p95', '#a78bfa'],
                ['p99', '#f472b6'],
              ]}
            />
          </ChartCard>

          <TableCard title={data.series_covers_range === false ? `Top hosts by volume (last ${windowLabel(data.detail_window)})` : 'Top hosts by volume'}>
            <SimpleTable
              cols={['Host', 'Requests']}
              rows={(data.top_hosts ?? []).map((h) => [h.host_domain, fmtNumber(h.count)])}
              emptyMsg="No traffic in range"
            />
          </TableCard>

          <TableCard title={data.detail_window ? `Top paths (last ${windowLabel(data.detail_window)})` : 'Top paths'}>
            <SimpleTable
              cols={['Host', 'Path', 'Count']}
              rows={(data.top_paths ?? [])
                .slice(0, 10)
                .map((p) => [p.host_domain, p.path, fmtNumber(p.count)])}
              emptyMsg="No traffic in range"
            />
          </TableCard>
        </div>
      )}
    </section>
  );
}

// ================ Security ================

function SecuritySection({ tick }: { tick: number }) {
  const [range, setRange] = useState<DashRange>('24h');
  const [data, setData] = useState<DashSecurity | null>(() => getLastKnown(keySecurity('24h')));
  const [err, setErr] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    const key = keySecurity(range);
    setData(getLastKnown(key));
    api
      .dashboardSecurity(range)
      .then((d) => {
        if (cancelled) return;
        setLastKnown(key, d);
        setData(d);
        setErr(null);
      })
      .catch((e) => {
        if (cancelled) return;
        setErr(e instanceof ApiError ? e.message : 'load failed');
      });
    return () => {
      cancelled = true;
    };
  }, [range, tick]);

  return (
    <section>
      <div className="flex items-center justify-between mb-3">
        <h2 className="text-lg font-semibold text-slate-300 flex items-center gap-2">
          <Shield className="w-5 h-5 text-sky-400" /> Security
        </h2>
        <div className="flex items-center gap-2 text-xs">
          <span className="text-slate-500">rate-limit hits: {data ? fmtNumber(data.rate_limit_hits) : '—'}</span>
          <RangeSelect value={range} onChange={setRange} />
        </div>
      </div>

      {err ? (
        <SectionError msg={err} />
      ) : !data ? (
        <SkeletonCharts count={2} />
      ) : (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
          {data.waf_engines && (
            <div className="lg:col-span-2">
              <WafEnginesLine engines={data.waf_engines} />
            </div>
          )}
          <ChartCard title={wafChartTitle(data.waf_engines)}>
            <ResponsiveContainer width="100%" height={200}>
              <AreaChart data={data.waf_timeseries.map((b) => ({ ...b, t: fmtTick(b.time, range) }))}>
                <CartesianGrid stroke="#1e293b" strokeDasharray="3 3" />
                <XAxis dataKey="t" fontSize={10} stroke="#64748b" />
                <YAxis fontSize={10} stroke="#64748b" />
                <Tooltip contentStyle={tooltipStyle} />
                <Area type="monotone" dataKey="appsec" name="AppSec alerts" stroke="#38bdf8" fill="#38bdf8" fillOpacity={0.5} />
                <Area type="monotone" dataKey="detected" name="Coraza detections" stroke="#eab308" fill="#eab308" fillOpacity={0.5} />
                <Area type="monotone" dataKey="blocked" name="403 at the edge" stroke="#ef4444" fill="#ef4444" fillOpacity={0.4} />
              </AreaChart>
            </ResponsiveContainer>
            <LegendRow items={[['AppSec alerts', '#38bdf8'], ['Coraza detections', '#eab308'], ['403 at the edge (bans + WAF)', '#ef4444']]} />
          </ChartCard>

          <TableCard title="Top attack types">
            <SimpleTable
              cols={['Rule', 'Engine', 'Message', 'Count']}
              rows={(data.top_attack_types ?? []).map((a) => [
                <span key={`${a.engine}-${a.rule ?? a.rule_id}`} className="font-mono text-xs">{a.rule ?? String(a.rule_id)}</span>,
                a.engine ?? 'coraza',
                truncate(a.message, 60),
                fmtNumber(a.count),
              ])}
              emptyMsg={data.waf_engines && data.waf_engines.events_total > 0 ? 'No rule breakdown in range' : 'No WAF events in range'}
            />
          </TableCard>

          {/* World map spans both grid columns on lg+: a wide map
              reads much better than one squashed into a single column.
              Lives right above the Top attacking IPs table so the
              viewer sees the geographic distribution first, then the
              per-IP details below. */}
          <div className="lg:col-span-2">
            <ChartCard title="Attacking IPs by country">
              <Suspense fallback={<MapSkeleton height={320} />}>
                <WorldMap
                  data={byCountryMap(data.by_country)}
                  height={320}
                />
              </Suspense>
              {data.private_hits > 0 && (
                <div className="mt-2 text-xs text-slate-500">
                  Plus <span className="font-mono text-slate-300">{fmtNumber(data.private_hits)}</span>
                  {' '}
                  {data.private_hits === 1 ? 'hit' : 'hits'} from the local network
                  {' '}
                  (not shown on the map).
                </div>
              )}
            </ChartCard>
          </div>

          <TableCard title="Top attacking IPs">
            <SimpleTable
              cols={['Remote IP', 'Location', 'ASN', 'Count', 'Hosts', 'Last seen']}
              rows={(data.top_attack_ips ?? []).map((ip) => [
                <Link key={ip.remote_ip} to={`/logs?q=${encodeURIComponent(ip.remote_ip)}`} className="font-mono text-sky-400 hover:underline">
                  {ip.remote_ip}
                </Link>,
                <GeoCell key={`g-${ip.remote_ip}`} geo={ip.geo} />,
                <ASNCell key={`a-${ip.remote_ip}`} geo={ip.geo} />,
                fmtNumber(ip.count),
                String(ip.distinct_hosts),
                <RelativeTime key={`t-${ip.remote_ip}`} iso={ip.last_seen} />,
              ])}
              emptyMsg="No attacking IPs"
            />
          </TableCard>

          <TableCard title="Top attacked paths">
            <SimpleTable
              cols={['Host', 'Path', 'Count']}
              rows={(data.top_attacked_paths ?? []).map((p) => [
                p.host_domain,
                p.path,
                fmtNumber(p.count),
              ])}
              emptyMsg="No attacked paths"
            />
          </TableCard>
        </div>
      )}
    </section>
  );
}

// WafEnginesLine names the engine behind the numbers (v1.3.39): the
// per-host Coraza WAF and the global CrowdSec AppSec. The section
// never says "no WAF events" while AppSec is producing them.
function WafEnginesLine({ engines }: { engines: DashWafEngines }) {
  const a = engines.appsec;
  const c = engines.coraza;
  const corazaState = c.enabled_hosts === 0
    ? `off on ${c.total_hosts}/${c.total_hosts} hosts`
    : `on ${c.enabled_hosts}/${c.total_hosts} hosts`;
  return (
    <div className="flex flex-wrap items-center gap-x-4 gap-y-1 text-xs text-slate-400">
      <span>
        <span className="text-slate-300">AppSec</span> ({a.mode}): {fmtNumber(a.hits)} hits, {fmtNumber(a.bans)} bans
        <span
          className="ml-1 text-slate-500 cursor-help"
          title="Blocked vs detected is attributed by the AppSec mode active when each alert fired; the alert itself does not say whether the request was blocked."
        >
          ({fmtNumber(a.blocked)} blocked / {fmtNumber(a.logged)} detected)
        </span>
      </span>
      <span>
        <span className="text-slate-300">Coraza</span> per host: {corazaState}, {fmtNumber(c.events)} events
      </span>
    </div>
  );
}

function wafChartTitle(e?: DashWafEngines): string {
  if (!e) return 'WAF detections vs blocks';
  const parts: string[] = [];
  if (e.appsec.events > 0 || e.appsec.mode !== 'disabled') parts.push('AppSec');
  if (e.coraza.events > 0 || e.coraza.enabled_hosts > 0) parts.push('Coraza');
  return parts.length ? `WAF events (${parts.join(' + ')})` : 'WAF events (no engine active)';
}

// ================ Bans & whitelist ================
//
// v1.3.24 widget that surfaces the v1.3.23 /api/security/dashboard-stats
// rollup: total active bans + scope breakdown, top countries from
// the panel-side country expansion table, whitelist size, and
// last-24h audit count. Complements the existing SecuritySection
// (WAF activity / per-IP attacks) -- this one is the "global
// security state at a glance" view.

function BansAndWhitelistSection({ tick }: { tick: number }) {
  const [data, setData] = useState<SecurityDashboardStats | null>(() => getLastKnown(KEY_BANS));
  const [err, setErr] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    api
      .securityDashboardStats()
      .then((d) => {
        if (cancelled) return;
        setLastKnown(KEY_BANS, d);
        setData(d);
        setErr(null);
      })
      .catch((e) => {
        if (cancelled) return;
        setErr(e instanceof ApiError ? e.message : 'load failed');
      });
    return () => {
      cancelled = true;
    };
  }, [tick]);

  return (
    <section>
      <div className="flex items-center justify-between mb-3">
        <h2 className="text-lg font-semibold text-slate-300 flex items-center gap-2">
          <Shield className="w-5 h-5 text-emerald-400" /> Bans &amp; whitelist
        </h2>
        <Link
          to="/security"
          className="text-xs text-sky-400 hover:underline"
        >
          manage →
        </Link>
      </div>

      {err ? (
        <SectionError msg={err} />
      ) : !data ? (
        <SkeletonCards count={4} />
      ) : (
        <div className="grid grid-cols-2 md:grid-cols-4 gap-3 mb-3">
          <BansStatCard
            label="Active bans"
            value={fmtNumber(data.bans_total)}
            sub={banScopeSummary(data.bans_by_scope)}
          />
          <BansStatCard
            label="Whitelist entries"
            value={fmtNumber(data.whitelist_entries)}
            sub="operator-managed"
          />
          <BansStatCard
            label="Audit events 24h"
            value={fmtNumber(data.audit_last_24h)}
            sub="admin actions"
          />
          <BansStatCard
            label="Country expansions"
            value={fmtNumber(data.top_countries.length)}
            sub={topCountrySummary(data.top_countries)}
          />
        </div>
      )}

      {data && data.top_countries.length > 0 && (
        <TableCard title="Country expansions (active)">
          <SimpleTable
            cols={['Country', 'CIDRs (rolled-up)', 'Active in LAPI']}
            rows={data.top_countries.slice(0, 10).map((c) => [
              c.country_code,
              fmtNumber(c.cidr_count),
              fmtNumber(c.decisions_active),
            ])}
            emptyMsg="no expansions"
          />
        </TableCard>
      )}
    </section>
  );
}

function BansStatCard({
  label,
  value,
  sub,
}: {
  label: string;
  value: string;
  sub?: string;
}) {
  return (
    <div className="bg-slate-900 border border-slate-800 rounded-lg p-3">
      <div className="text-xs text-slate-400 uppercase tracking-wide">
        {label}
      </div>
      <div className="text-2xl font-semibold text-slate-100 mt-1">{value}</div>
      {sub && (
        <div className="text-xs text-slate-500 mt-1 truncate" title={sub}>
          {sub}
        </div>
      )}
    </div>
  );
}

function banScopeSummary(byScope: Record<string, number>): string {
  const order = ['Ip', 'Range', 'Country', 'AS'];
  const parts: string[] = [];
  for (const s of order) {
    if (byScope[s]) parts.push(`${byScope[s]} ${s.toLowerCase()}`);
  }
  return parts.join(' · ') || '—';
}

function topCountrySummary(
  rows: SecurityDashboardStats['top_countries'],
): string {
  if (rows.length === 0) return '—';
  return rows
    .slice(0, 3)
    .map((r) => r.country_code)
    .join(' · ');
}

// ================ Health ================

function HealthSection({ tick }: { tick: number }) {
  const [data, setData] = useState<DashHealth | null>(() => getLastKnown(KEY_HEALTH));
  const [err, setErr] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    api
      .dashboardHealth()
      .then((d) => {
        if (cancelled) return;
        setLastKnown(KEY_HEALTH, d);
        setData(d);
        setErr(null);
      })
      .catch((e) => {
        if (cancelled) return;
        setErr(e instanceof ApiError ? e.message : 'load failed');
      });
    return () => {
      cancelled = true;
    };
  }, [tick]);

  return (
    <section>
      <h2 className="text-lg font-semibold text-slate-300 mb-3 flex items-center gap-2">
        <Activity className="w-5 h-5 text-sky-400" /> Health
      </h2>

      {err ? (
        <SectionError msg={err} />
      ) : !data ? (
        <SkeletonCharts count={2} />
      ) : (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
          <ChartCard title="Target groups">
            {data.target_groups.length === 0 ? (
              <Empty msg="No target groups" />
            ) : (
              <ul className="text-sm space-y-1">
                {data.target_groups.map((tg) => (
                  <li key={tg.name} className="flex items-center justify-between py-1">
                    <Link to="/target-groups" className="font-mono text-slate-200 hover:underline">
                      {tg.name}
                    </Link>
                    <div className="flex items-center gap-2">
                      <span className="text-xs text-slate-400">
                        {tg.enabled}/{tg.total}
                      </span>
                      <StatusPill status={tg.status} />
                    </div>
                  </li>
                ))}
              </ul>
            )}
          </ChartCard>

          <ChartCard title="Certificates">
            {data.certs.length === 0 ? (
              <Empty msg="No TLS certs" />
            ) : (
              <ul className="text-sm space-y-1">
                {data.certs.map((c) => (
                  <li key={c.domain} className="flex items-center justify-between py-1">
                    <span className="font-mono text-slate-200 truncate">{c.domain}</span>
                    <div className="flex items-center gap-2">
                      <span className="text-xs text-slate-400">
                        {c.status === 'unknown' ? '?' : `${c.days_left}d`}
                      </span>
                      <StatusPill status={c.status} />
                    </div>
                  </li>
                ))}
              </ul>
            )}
          </ChartCard>

          <ChartCard title="Last backup">
            {data.last_backup ? (
              <div className="text-sm space-y-1">
                <div className="font-mono text-xs truncate">{data.last_backup.filename}</div>
                <div className="text-slate-400 text-xs">
                  {humanSize(data.last_backup.size_bytes)} · {data.last_backup.kind} ·{' '}
                  <RelativeTime iso={data.last_backup.created_at} />
                </div>
                <Link to="/backup" className="text-xs text-sky-400 hover:underline">
                  manage backups →
                </Link>
              </div>
            ) : (
              <Empty msg="No backups yet" />
            )}
          </ChartCard>

          <ChartCard title="System">
            <dl className="text-sm space-y-1">
              <div className="flex items-center justify-between py-1">
                <dt className="text-slate-400">Panel uptime</dt>
                <dd className="font-mono">{data.panel_uptime || '—'}</dd>
              </div>
              <div className="flex items-center justify-between py-1">
                <dt className="text-slate-400">Caddy</dt>
                <dd>
                  <StatusPill status={data.caddy_status} />
                </dd>
              </div>
            </dl>
          </ChartCard>

          <div className="lg:col-span-2">
            <ChartCard title="Recent errors">
              {data.recent_errors.length === 0 ? (
                <Empty msg="No recent errors" />
              ) : (
                <ul className="divide-y divide-slate-800 text-sm">
                  {data.recent_errors.map((e, i) => (
                    <li key={i} className="py-1.5 flex items-start gap-2">
                      <AlertTriangle className="w-4 h-4 mt-0.5 text-amber-400 flex-shrink-0" />
                      <div className="flex-1 min-w-0">
                        <div className="text-xs text-slate-500 font-mono">
                          {new Date(e.timestamp).toLocaleString()} · {e.source} {e.level ? `· ${e.level}` : ''}
                        </div>
                        <div className="text-slate-300 truncate">{e.message}</div>
                      </div>
                      <Link
                        to="/logs?source=caddy_error"
                        className="text-xs text-sky-400 hover:underline flex-shrink-0"
                      >
                        logs →
                      </Link>
                    </li>
                  ))}
                </ul>
              )}
            </ChartCard>
          </div>
        </div>
      )}
    </section>
  );
}

// ================ Shared bits ================

function RangeSelect({
  value,
  onChange,
}: {
  value: DashRange;
  onChange: (r: DashRange) => void;
}) {
  return (
    <select
      value={value}
      onChange={(e) => onChange(e.target.value as DashRange)}
      className="px-2 py-1 rounded bg-slate-800 border border-slate-700"
    >
      <option value="1h">1h</option>
      <option value="6h">6h</option>
      <option value="24h">24h</option>
      <option value="7d">7d</option>
    </select>
  );
}

function ChartCard({ title, children }: { title: string; children: ReactNode }) {
  return (
    <div className="bg-slate-900 border border-slate-800 rounded-lg p-4">
      <div className="text-xs uppercase text-slate-500 tracking-wide mb-2">{title}</div>
      {children}
    </div>
  );
}

function TableCard({ title, children }: { title: string; children: ReactNode }) {
  return (
    <div className="bg-slate-900 border border-slate-800 rounded-lg p-4">
      <div className="text-xs uppercase text-slate-500 tracking-wide mb-2">{title}</div>
      {/* overflow-x-auto on the container instead of the <table> so
          a row wider than the card (pathological Last-Seen strings,
          long IPv6 literals) shows a scrollbar instead of bleeding
          past the card border. Matches the pattern used on the
          Top attacking IPs card, which was the Dashboard overflow
          complaint's origin. */}
      <div className="overflow-x-auto">{children}</div>
    </div>
  );
}

function SimpleTable({
  cols,
  rows,
  emptyMsg,
}: {
  cols: string[];
  rows: ReactNode[][];
  emptyMsg: string;
}) {
  if (rows.length === 0) return <Empty msg={emptyMsg} />;
  return (
    <table className="w-full text-sm">
      <thead className="text-slate-400 uppercase text-[10px] tracking-wide">
        <tr>
          {cols.map((c) => (
            <th key={c} className="text-left px-2 py-1 whitespace-nowrap">
              {c}
            </th>
          ))}
        </tr>
      </thead>
      <tbody>
        {rows.map((r, i) => (
          <tr key={i} className="border-t border-slate-800">
            {r.map((cell, j) => (
              <td
                key={j}
                // Last column gets whitespace-nowrap so a timestamp
                // like "2 hours ago" stays on one line; other columns
                // keep the truncate cap so pathological IDs /
                // user-agents do not stretch the row.
                className={`px-2 py-1.5 ${
                  j === r.length - 1
                    ? 'text-right font-mono text-xs whitespace-nowrap'
                    : 'truncate max-w-[200px]'
                }`}
              >
                {cell}
              </td>
            ))}
          </tr>
        ))}
      </tbody>
    </table>
  );
}

function StatusPill({ status }: { status: string }) {
  const cls: Record<string, string> = {
    ok: 'bg-emerald-900 text-emerald-200',
    degraded: 'bg-amber-900 text-amber-200',
    warning: 'bg-amber-900 text-amber-200',
    down: 'bg-red-900 text-red-200',
    critical: 'bg-red-900 text-red-200',
    unreachable: 'bg-red-900 text-red-200',
    unknown: 'bg-slate-800 text-slate-400',
  };
  return (
    <span className={`text-[10px] px-1.5 py-0.5 rounded ${cls[status] ?? 'bg-slate-800 text-slate-300'}`}>
      {status}
    </span>
  );
}

function LegendRow({ items }: { items: [string, string][] }) {
  return (
    <div className="flex gap-3 text-[10px] text-slate-400 mt-1">
      {items.map(([l, c]) => (
        <span key={l} className="flex items-center gap-1">
          <span className="w-2 h-2 rounded-sm" style={{ backgroundColor: c }} />
          {l}
        </span>
      ))}
    </div>
  );
}

function SectionError({ msg }: { msg: string }) {
  return (
    <div className="px-3 py-2 rounded bg-red-950/40 border border-red-900 text-sm text-red-300 flex items-center gap-2">
      <XCircle className="w-4 h-4" /> {msg}
    </div>
  );
}

function Empty({ msg }: { msg: string }) {
  return (
    <div className="text-slate-500 text-sm flex items-center gap-2">
      <CheckCircle2 className="w-4 h-4" /> {msg}
    </div>
  );
}

// Error boundary per section so a failing sub-query does not crash
// the whole page.
class ErrorBoundary extends Component<
  { name: string; children: ReactNode },
  { hasError: boolean; message: string }
> {
  constructor(props: { name: string; children: ReactNode }) {
    super(props);
    this.state = { hasError: false, message: '' };
  }
  static getDerivedStateFromError(err: Error) {
    return { hasError: true, message: err.message };
  }
  override render() {
    if (this.state.hasError) {
      return (
        <section>
          <SectionError msg={`${this.props.name}: ${this.state.message}`} />
        </section>
      );
    }
    return this.props.children;
  }
}

// ----- formatting helpers -----

function fmtNumber(n: number): string {
  if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(1)}M`;
  if (n >= 1_000) return `${(n / 1_000).toFixed(1)}k`;
  return String(n);
}

function humanSize(n: number): string {
  if (n < 1024) return `${n} B`;
  const u = ['KiB', 'MiB', 'GiB'];
  let v = n / 1024;
  let i = 0;
  while (v >= 1024 && i < u.length - 1) {
    v /= 1024;
    i++;
  }
  return `${v.toFixed(1)} ${u[i]}`;
}

// windowLabel turns the API's Go duration ("24h0m0s") into the label
// the honesty notes use ("24 h"). v1.3.38.4: long ranges compute some
// sections over the newest window only and each card says so.
function windowLabel(d?: string): string {
  if (!d) return '';
  const m = /^(\d+)h/.exec(d);
  return m ? `${m[1]} h` : d;
}

function fmtTick(iso: string, range: DashRange): string {
  const d = new Date(iso);
  if (range === '1h' || range === '6h') {
    return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
  }
  if (range === '24h') {
    return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
  }
  return `${d.getMonth() + 1}/${d.getDate()}`;
}

function truncate(s: string, n: number): string {
  if (s.length <= n) return s;
  return s.slice(0, n) + '...';
}

// MapSkeleton keeps the card at the right height while the map chunk
// downloads. Avoiding layout jump is the point -- a user who scrolls
// during load should not see the cards below jump up and then down
// when the map materialises.
function MapSkeleton({ height }: { height: number }) {
  return (
    <div
      className="w-full flex items-center justify-center text-slate-500 bg-slate-950/40 border border-slate-800 rounded"
      style={{ height }}
    >
      <Loader2 className="w-5 h-5 animate-spin" />
    </div>
  );
}

// byCountryMap flattens the backend's by_country array to the
// {ISO2: count} shape <WorldMap> consumes. Keys normalised uppercase
// so backend drift (lowercase codes, stray whitespace) never
// silently drops hits from the choropleth.
function byCountryMap(
  list: { country_code: string; count: number }[] | undefined,
): Record<string, number> {
  const out: Record<string, number> = {};
  if (!list) return out;
  for (const c of list) {
    const k = c.country_code?.toUpperCase?.().trim();
    if (!k) continue;
    out[k] = (out[k] ?? 0) + c.count;
  }
  return out;
}

const tooltipStyle = {
  backgroundColor: '#0f172a',
  border: '1px solid #1e293b',
  fontSize: '11px',
} as const;

// GeoCell renders the flag + country name. Falls back to an LAN
// marker for private IPs or a neutral globe when no data is known.
function GeoCell({ geo }: { geo?: GeoEnrichment }) {
  if (geo?.is_private) {
    return (
      <span className="flex items-center gap-1">
        <GeoFlag isPrivate /> <span className="text-slate-500 text-xs">LAN</span>
      </span>
    );
  }
  const name = geo?.country_name || 'Unknown';
  return (
    <span className="flex items-center gap-1">
      <GeoFlag countryCode={geo?.country_code} /> <span className="text-xs">{name}</span>
    </span>
  );
}

function ASNCell({ geo }: { geo?: GeoEnrichment }) {
  if (!geo || !geo.asn_org) {
    return <span className="text-xs text-slate-500">—</span>;
  }
  const org = geo.asn_org.length > 20 ? geo.asn_org.slice(0, 20) + '…' : geo.asn_org;
  return <span className="text-xs font-mono" title={geo.asn_org}>{org}</span>;
}
