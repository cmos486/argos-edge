// AppSec is a top-level route (/appsec) rather than a tab in /threats
// or a subroute under /security. Justification: /threats is IP-
// centric (decisions/bans), /security is per-host, /appsec is
// URL+rule-centric -- different mental model, cleaner independence.
// Flat routing matches every other feature page (/backup, /system,
// /certs, /notifications).

import { useCallback, useEffect, useMemo, useState } from 'react';
import {
  AlertTriangle,
  RefreshCw,
  Shield,
  ShieldAlert,
  ShieldCheck,
  ShieldOff,
} from 'lucide-react';
import {
  Area,
  AreaChart,
  Bar,
  BarChart,
  CartesianGrid,
  Legend,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts';
import {
  ApiError,
  AppSecDegradedReason,
  AppSecMetrics,
  AppSecMode,
  AppSecStatus,
  AppSecWindow,
  api,
} from '../api/client';
import Modal from '../components/Modal';
import AppSecModeToggle from '../components/AppSecModeToggle';
import GeoFlag from '../components/GeoFlag';
import { useToasts } from '../components/toastsContext';

const REFRESH_MS = 30_000;

interface Props {
  username: string;
}

export default function AppSec({ username }: Props) {
  const [status, setStatus] = useState<AppSecStatus | null>(null);
  const [metrics, setMetrics] = useState<AppSecMetrics | null>(null);
  const [window, setWindow] = useState<AppSecWindow>('24h');
  const [err, setErr] = useState<string | null>(null);
  const [showToggle, setShowToggle] = useState(false);

  const load = useCallback(async () => {
    try {
      const [s, m] = await Promise.all([
        api.appsecStatus(),
        api.appsecMetrics(window),
      ]);
      setStatus(s);
      setMetrics(m);
      setErr(null);
    } catch (e) {
      setErr(e instanceof ApiError ? e.message : 'load failed');
    }
  }, [window]);

  useEffect(() => {
    void load();
    const id = setInterval(load, REFRESH_MS);
    return () => clearInterval(id);
  }, [load]);

  const onModeChanged = useCallback(
    (_next: AppSecMode) => {
      setShowToggle(false);
      void load();
    },
    [load],
  );

  return (
    <div className="p-6 max-w-[1400px] mx-auto space-y-4">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-semibold flex items-center gap-2">
          <Shield className="w-6 h-6 text-sky-400" /> AppSec (WAF)
        </h1>
        <button
          type="button"
          onClick={load}
          className="flex items-center gap-1 px-2 py-1 rounded border border-slate-700 hover:bg-slate-800 text-xs"
        >
          <RefreshCw className="w-3 h-3" /> refresh
        </button>
      </div>

      {err && (
        <div className="flex items-start gap-2 px-3 py-2 rounded bg-red-950/40 border border-red-900 text-sm text-red-300">
          <AlertTriangle className="w-4 h-4 mt-0.5 flex-shrink-0" />
          <span>
            Could not load AppSec state: {err}. Check that the crowdsec
            container is healthy.
          </span>
        </div>
      )}

      {status && (
        <AppSecStatusCard
          status={status}
          onToggle={() => setShowToggle(true)}
        />
      )}

      {status && status.mode !== 'disabled' && <AppSecFailOpenCard />}

      {/* "disabled" mode short-circuits the metrics block -- there are
          no hits to chart, and the empty state is more honest than
          showing a flat line. */}
      {status?.mode === 'disabled' ? (
        <section className="bg-slate-900 border border-slate-800 rounded-lg p-8 text-center text-slate-400">
          <ShieldOff className="w-10 h-10 mx-auto mb-3 text-slate-600" />
          <div className="text-lg font-medium text-slate-200 mb-1">
            AppSec is disabled
          </div>
          <div className="text-sm mb-4">
            No WAF round-trip on the request path. Enable detect mode to start
            observing attacks without blocking them.
          </div>
          <button
            type="button"
            onClick={() => setShowToggle(true)}
            className="inline-flex items-center gap-1 px-3 py-1.5 text-sm rounded bg-sky-600 hover:bg-sky-500 font-medium"
          >
            <ShieldCheck className="w-3.5 h-3.5" /> Enable
          </button>
        </section>
      ) : (
        metrics &&
        (metrics.degraded ? (
          <AppSecMetricsDegradedBanner degraded={metrics.degraded} />
        ) : (
          <AppSecMetricsView
            metrics={metrics}
            window={window}
            onWindowChange={setWindow}
          />
        ))
      )}

      <Modal
        open={showToggle}
        title="Change AppSec mode"
        onClose={() => setShowToggle(false)}
      >
        <AppSecModeToggle
          current={status?.mode ?? 'detect'}
          username={username}
          onDone={onModeChanged}
          onCancel={() => setShowToggle(false)}
        />
      </Modal>
    </div>
  );
}

// ---- status card ----

function AppSecStatusCard({
  status,
  onToggle,
}: {
  status: AppSecStatus;
  onToggle: () => void;
}) {
  const badgeCls: Record<AppSecMode, string> = {
    detect: 'bg-emerald-900 text-emerald-200 border-emerald-800',
    block: 'bg-red-900 text-red-200 border-red-800',
    disabled: 'bg-slate-800 text-slate-400 border-slate-700',
  };
  const Icon = {
    detect: Shield,
    block: ShieldAlert,
    disabled: ShieldOff,
  }[status.mode];

  const last =
    status.last_mode_change_at
      ? new Date(status.last_mode_change_at).toLocaleString()
      : 'never';
  const by = status.last_mode_change_by || '—';

  return (
    <section className="bg-slate-900 border border-slate-800 rounded-lg p-4">
      <div className="flex items-start justify-between gap-4 flex-wrap">
        <div className="flex items-start gap-3">
          <div
            className={`px-3 py-2 rounded border inline-flex items-center gap-2 ${badgeCls[status.mode]}`}
          >
            <Icon className="w-4 h-4" />
            <span className="font-semibold tracking-wide uppercase">
              {status.mode}
            </span>
          </div>
          <div className="text-sm text-slate-300 space-y-0.5">
            <div>
              <span className="text-slate-400">Collections:</span>{' '}
              {(status.collections_installed ?? []).length > 0
                ? status.collections_installed!.length
                : '—'}
              {status.total_rules ? (
                <>
                  {' · '}
                  <span className="text-slate-400">Rules:</span>{' '}
                  <span className="font-mono">{status.total_rules}</span>
                </>
              ) : null}
            </div>
            <div className="text-xs text-slate-400">
              Last change: {last} by <span className="font-mono">{by}</span>
            </div>
          </div>
        </div>
        <button
          type="button"
          onClick={onToggle}
          className="px-3 py-1.5 text-sm rounded bg-sky-600 hover:bg-sky-500 font-medium"
        >
          Change mode
        </button>
      </div>

      {(status.collections_installed ?? []).length > 0 && (
        <div className="mt-3 flex flex-wrap gap-1.5">
          {status.collections_installed!.map((c) => (
            <span
              key={c}
              className="text-xs font-mono px-2 py-0.5 rounded bg-slate-800 border border-slate-700 text-slate-300"
            >
              {c.replace(/^crowdsecurity\//, '')}
            </span>
          ))}
        </div>
      )}
    </section>
  );
}

// ---- metrics view ----

function AppSecMetricsView({
  metrics,
  window,
  onWindowChange,
}: {
  metrics: AppSecMetrics;
  window: AppSecWindow;
  onWindowChange: (w: AppSecWindow) => void;
}) {
  const windows: AppSecWindow[] = ['1h', '6h', '12h', '24h'];

  const ts = useMemo(
    () =>
      metrics.hits_over_time.map((b) => ({
        t: fmtTick(b.time, window),
        hits: b.hits,
        blocked: b.blocked,
        // logged = hits - blocked; we stack blocked on top so both
        // stripes sum to total hits on the chart.
        logged: Math.max(0, b.hits - b.blocked),
      })),
    [metrics.hits_over_time, window],
  );

  return (
    <>
      <div className="flex items-center justify-between">
        <div className="flex gap-1 text-xs">
          {windows.map((w) => (
            <button
              key={w}
              type="button"
              onClick={() => onWindowChange(w)}
              className={`px-2 py-1 rounded border ${
                w === window
                  ? 'bg-slate-800 border-slate-600 text-slate-100'
                  : 'border-slate-800 text-slate-400 hover:bg-slate-900'
              }`}
            >
              {w}
            </button>
          ))}
        </div>
        <span className="text-xs text-slate-500">
          showing attribution under current mode (
          <span className="font-mono">{metrics.mode}</span>)
        </span>
      </div>

      {/* stat cards */}
      <div className="grid grid-cols-3 gap-3">
        <Stat label="Total hits" value={metrics.total_hits} />
        <Stat label="Blocked" value={metrics.blocked} accent="red" />
        <Stat label="Detected (logged)" value={metrics.logged} accent="emerald" />
      </div>

      {/* hits_over_time */}
      <section className="bg-slate-900 border border-slate-800 rounded-lg p-4">
        <div className="text-sm text-slate-300 mb-2">Hits over time</div>
        <ResponsiveContainer width="100%" height={220}>
          <AreaChart data={ts}>
            <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
            <XAxis dataKey="t" stroke="#64748b" fontSize={11} />
            <YAxis stroke="#64748b" fontSize={11} allowDecimals={false} />
            <Tooltip contentStyle={chartTooltipStyle} />
            <Legend wrapperStyle={{ fontSize: 12 }} />
            <Area
              type="monotone"
              dataKey="blocked"
              stackId="1"
              stroke="#f87171"
              fill="#ef4444"
              fillOpacity={0.4}
              name="blocked"
            />
            <Area
              type="monotone"
              dataKey="logged"
              stackId="1"
              stroke="#34d399"
              fill="#10b981"
              fillOpacity={0.4}
              name="logged"
            />
          </AreaChart>
        </ResponsiveContainer>
      </section>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
        {/* by_category */}
        <section className="bg-slate-900 border border-slate-800 rounded-lg p-4">
          <div className="text-sm text-slate-300 mb-2">By category</div>
          {metrics.by_category.length === 0 ? (
            <div className="text-sm text-slate-500">no hits in window</div>
          ) : (
            <ResponsiveContainer width="100%" height={200}>
              <BarChart data={metrics.by_category} layout="vertical">
                <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
                <XAxis type="number" stroke="#64748b" fontSize={11} allowDecimals={false} />
                <YAxis type="category" dataKey="category" stroke="#64748b" fontSize={11} width={110} />
                <Tooltip contentStyle={chartTooltipStyle} />
                <Bar dataKey="count" fill="#38bdf8" />
              </BarChart>
            </ResponsiveContainer>
          )}
        </section>

        {/* top rules */}
        <section className="bg-slate-900 border border-slate-800 rounded-lg p-4">
          <div className="text-sm text-slate-300 mb-2">Top rules</div>
          {metrics.top_rules.length === 0 ? (
            <div className="text-sm text-slate-500">no hits in window</div>
          ) : (
            <table className="w-full text-sm">
              <thead className="text-xs text-slate-500 uppercase">
                <tr>
                  <th className="text-left font-normal py-1">rule</th>
                  <th className="text-right font-normal py-1">hits</th>
                </tr>
              </thead>
              <tbody>
                {metrics.top_rules.map((r) => (
                  <tr key={r.rule} className="border-t border-slate-800/60">
                    <td className="py-1.5 pr-2">
                      <div className="font-mono text-xs text-slate-200">
                        {r.rule.replace(/^crowdsecurity\//, '')}
                      </div>
                      {r.message && (
                        <div className="text-xs text-slate-500 truncate max-w-[280px]">
                          {r.message}
                        </div>
                      )}
                    </td>
                    <td className="py-1.5 text-right font-mono">{r.count}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </section>

        {/* top ips */}
        <section className="bg-slate-900 border border-slate-800 rounded-lg p-4">
          <div className="text-sm text-slate-300 mb-2">Top source IPs</div>
          {metrics.top_ips.length === 0 ? (
            <div className="text-sm text-slate-500">no hits in window</div>
          ) : (
            <table className="w-full text-sm">
              <thead className="text-xs text-slate-500 uppercase">
                <tr>
                  <th className="text-left font-normal py-1">ip</th>
                  <th className="text-left font-normal py-1">geo</th>
                  <th className="text-right font-normal py-1">hits</th>
                </tr>
              </thead>
              <tbody>
                {metrics.top_ips.map((i) => (
                  <tr key={i.ip} className="border-t border-slate-800/60">
                    <td className="py-1.5 font-mono text-xs">{i.ip}</td>
                    <td className="py-1.5 text-xs text-slate-300">
                      <GeoFlag
                        countryCode={i.geo?.country_code}
                        isPrivate={i.geo?.is_private}
                      />{' '}
                      {i.geo?.country_name ?? '—'}
                      {i.geo?.asn_org ? (
                        <span className="text-slate-500"> · {i.geo.asn_org}</span>
                      ) : null}
                    </td>
                    <td className="py-1.5 text-right font-mono">{i.count}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </section>

        {/* top paths */}
        <section className="bg-slate-900 border border-slate-800 rounded-lg p-4">
          <div className="text-sm text-slate-300 mb-2">Top attacked paths</div>
          {metrics.top_paths.length === 0 ? (
            <div className="text-sm text-slate-500">no hits in window</div>
          ) : (
            <table className="w-full text-sm">
              <thead className="text-xs text-slate-500 uppercase">
                <tr>
                  <th className="text-left font-normal py-1">path</th>
                  <th className="text-right font-normal py-1">hits</th>
                </tr>
              </thead>
              <tbody>
                {metrics.top_paths.map((p, idx) => (
                  <tr key={`${p.host}${p.path}${idx}`} className="border-t border-slate-800/60">
                    <td className="py-1.5">
                      <div className="font-mono text-xs text-slate-200 truncate max-w-[260px]">
                        {p.path}
                      </div>
                      {p.host && (
                        <div className="text-xs text-slate-500">{p.host}</div>
                      )}
                    </td>
                    <td className="py-1.5 text-right font-mono">{p.count}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </section>
      </div>
    </>
  );
}

function Stat({
  label,
  value,
  accent,
}: {
  label: string;
  value: number;
  accent?: 'red' | 'emerald';
}) {
  const valueCls =
    accent === 'red'
      ? 'text-red-300'
      : accent === 'emerald'
        ? 'text-emerald-300'
        : 'text-slate-100';
  return (
    <div className="bg-slate-900 border border-slate-800 rounded-lg p-4">
      <div className="text-xs uppercase tracking-wide text-slate-500">
        {label}
      </div>
      <div className={`text-2xl font-semibold mt-1 font-mono ${valueCls}`}>
        {value}
      </div>
    </div>
  );
}

// fmtTick shortens a UTC ISO string to a tick label appropriate for
// the current window. 24h/12h -> "HH:00", 6h/1h -> "HH:MM".
function fmtTick(iso: string, w: AppSecWindow): string {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  const hh = String(d.getHours()).padStart(2, '0');
  const mm = String(d.getMinutes()).padStart(2, '0');
  if (w === '24h' || w === '12h') return `${hh}:00`;
  return `${hh}:${mm}`;
}

const chartTooltipStyle = {
  backgroundColor: '#0f172a',
  border: '1px solid #1e293b',
  borderRadius: 4,
  fontSize: 12,
} as const;

// AppSecFailOpenCard lets the operator flip the appsec.fail_open
// setting. v1.3.2 introduces the knob and defaults it to "true" so
// a dead AppSec sidecar does not 500 every request. Operators who
// actively run AppSec and want strict enforcement can opt out here.
function AppSecFailOpenCard() {
  const toasts = useToasts();
  const [failOpen, setFailOpen] = useState<boolean | null>(null);
  const [saving, setSaving] = useState(false);

  const load = useCallback(async () => {
    try {
      const items = await api.listSettings('appsec.');
      const row = items.find((s) => s.key === 'appsec.fail_open');
      // Default is "true" when the setting has never been saved.
      setFailOpen(row?.value !== 'false');
    } catch (e) {
      toasts.push(e instanceof ApiError ? e.message : 'load failed', 'error');
    }
  }, [toasts]);

  useEffect(() => {
    load();
  }, [load]);

  async function toggle(next: boolean) {
    setSaving(true);
    try {
      await api.updateSetting('appsec.fail_open', next ? 'true' : 'false');
      setFailOpen(next);
      toasts.push(
        next ? 'AppSec: fail-open (requests pass on sidecar error)'
             : 'AppSec: fail-closed (requests 500 on sidecar error)',
        'success',
      );
    } catch (e) {
      toasts.push(e instanceof ApiError ? e.message : 'save failed', 'error');
    } finally {
      setSaving(false);
    }
  }

  if (failOpen === null) {
    return (
      <section className="bg-slate-900 border border-slate-800 rounded-lg p-4 text-sm text-slate-400">
        loading AppSec fail policy...
      </section>
    );
  }

  return (
    <section className="bg-slate-900 border border-slate-800 rounded-lg p-4">
      <h2 className="text-base font-semibold mb-1">Fail policy</h2>
      <p className="text-xs text-slate-500 mb-3">
        Behaviour when the CrowdSec AppSec sidecar is unreachable or
        returns an error. Applies only while AppSec is enabled (mode
        is not <code className="font-mono">disabled</code>).
      </p>
      <label className="flex items-start gap-2 cursor-pointer mb-2">
        <input
          type="radio"
          name="appsec-fail"
          checked={failOpen}
          disabled={saving}
          onChange={() => toggle(true)}
          className="mt-1 accent-sky-600"
        />
        <span>
          <span className="text-slate-200">Fail-open (default, recommended)</span>
          <span className="block text-xs text-slate-500">
            On AppSec error, let the request continue to the backend.
            WAF-inline protection is skipped for that request; a
            warning event is raised to alert the operator.
          </span>
        </span>
      </label>
      <label className="flex items-start gap-2 cursor-pointer">
        <input
          type="radio"
          name="appsec-fail"
          checked={!failOpen}
          disabled={saving}
          onChange={() => toggle(false)}
          className="mt-1 accent-sky-600"
        />
        <span>
          <span className="text-slate-200">Fail-closed (strict)</span>
          <span className="block text-xs text-slate-500">
            On AppSec error, return 500 and drop the request. Use only
            when you are certain AppSec is reliably configured on the
            CrowdSec container -- a single sidecar failure will take
            every host offline.
          </span>
        </span>
      </label>
    </section>
  );
}

// AppSecMetricsDegradedBanner replaces the metrics charts when the
// panel can't fetch LAPI alerts -- most commonly because machine
// credentials are not set (v1.3.4). Pre-v1.3.4 the whole page
// failed with "Could not load AppSec state: metrics from lapi:
// crowdsec not configured", which incorrectly suggested the whole
// CrowdSec stack was broken. This banner is scoped to the metrics
// block; the status card above (which uses a different code path
// not requiring machine creds) renders normally alongside.
function AppSecMetricsDegradedBanner({
  degraded,
}: {
  degraded: AppSecDegradedReason;
}) {
  const cta =
    degraded.code === 'machine_credentials_missing' ? (
      <div className="mt-2 text-xs text-amber-200/80">
        Add machine credentials inside the CrowdSec container with{' '}
        <code className="font-mono">
          cscli machines add argos-panel --password
        </code>
        , then paste user + password into{' '}
        <strong>Settings → CrowdSec → Machine credentials</strong>. See{' '}
        <a
          href="/docs/features/appsec/#panel-metrics-vs-endpoint-reachability"
          className="underline hover:text-amber-100"
        >
          AppSec → Panel metrics
        </a>{' '}
        for the why.
      </div>
    ) : null;

  return (
    <section className="bg-slate-900 border border-amber-900/60 rounded-lg p-4">
      <div className="flex items-start gap-2 text-sm">
        <AlertTriangle className="w-4 h-4 text-amber-400 mt-0.5 flex-shrink-0" />
        <div>
          <div className="font-medium text-amber-200 mb-1">
            AppSec metrics unavailable
          </div>
          <p className="text-slate-300 text-xs">{degraded.message}</p>
          {cta}
          <p className="mt-2 text-xs text-slate-500">
            The AppSec endpoint itself may still be reachable — the status
            card above is authoritative on that. Only this metrics view
            needs machine credentials to aggregate the alert history.
          </p>
        </div>
      </div>
    </section>
  );
}
