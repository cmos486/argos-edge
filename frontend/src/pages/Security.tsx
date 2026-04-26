import { ReactNode, useCallback, useEffect, useMemo, useState } from 'react';
import { Link } from 'react-router-dom';
import {
  ApiError,
  SecurityAppSecTuning,
  SecurityAuditLogEntry,
  SecurityAuditLogResponse,
  SecurityDecision,
  SecurityDecisionsListResponse,
  SecurityScenarioItem,
  SecurityScenariosResponse,
  SecurityWhitelistEntry,
  api,
} from '../api/client';
import { useToasts } from '../components/toastsContext';

// v1.3.24 /security global panel.
//
// Three tabs consuming the v1.3.23 endpoints:
//   Banned IPs  -> /api/security/decisions (+ DELETE /:id)
//   Whitelist   -> /api/security/whitelist (+ DELETE /:id)
//   Activity    -> /api/security/audit-log
//
// Per-host security config used to live at /security; v1.3.24
// moved it to /security/hosts so this URL belongs to global
// state. The tab strip carries a visually-distinct "Hosts ->"
// link to the moved page so operators discover the new URL on
// first visit; a session-dismissable banner explicitly mentions
// the move for bookmark rescue.

const TABS = [
  { id: 'banned', label: 'Banned IPs' },
  { id: 'whitelist', label: 'Whitelist' },
  { id: 'activity', label: 'Activity' },
  { id: 'scenarios', label: 'Scenarios' },
  { id: 'appsec', label: 'AppSec' },
] as const;

type TabID = (typeof TABS)[number]['id'];

const MOVE_BANNER_KEY = 'argos.security.hostsMoveBannerDismissed.v1.3.24';

export default function Security() {
  const [tab, setTab] = useState<TabID>('banned');

  const [bannerDismissed, setBannerDismissed] = useState<boolean>(() => {
    try {
      return sessionStorage.getItem(MOVE_BANNER_KEY) === '1';
    } catch {
      return false;
    }
  });

  function dismissBanner() {
    try {
      sessionStorage.setItem(MOVE_BANNER_KEY, '1');
    } catch {
      /* private mode etc. */
    }
    setBannerDismissed(true);
  }

  return (
    <div className="p-6 max-w-[1400px] mx-auto">
      <h1 className="text-2xl font-semibold mb-4">Security</h1>

      {!bannerDismissed && (
        <div className="mb-4 flex items-start gap-3 bg-slate-900 border border-slate-800 rounded-lg px-4 py-3 text-sm">
          <span className="text-slate-400">
            Looking for the host-WAF overview? It moved to{' '}
            <Link
              to="/security/hosts"
              className="text-sky-400 hover:underline"
            >
              /security/hosts
            </Link>
            . The Hosts link in the tab strip below is the same destination.
          </span>
          <button
            type="button"
            onClick={dismissBanner}
            className="ml-auto px-2 py-0.5 text-xs text-slate-400 hover:text-slate-200 hover:bg-slate-800 rounded"
            title="Dismiss for this session"
          >
            Dismiss
          </button>
        </div>
      )}

      <TabStrip active={tab} onChange={setTab} />

      <div className="mt-4">
        {tab === 'banned' && <BannedIPsTab />}
        {tab === 'whitelist' && <WhitelistTab />}
        {tab === 'activity' && <ActivityTab />}
        {tab === 'scenarios' && <ScenariosTab />}
        {tab === 'appsec' && <AppSecTab />}
      </div>
    </div>
  );
}

// =============================================================
// Pending-reload badge (shared by Scenarios + AppSec tabs)
// =============================================================

function PendingReloadBadge({
  show,
  lastModifiedAt,
  onMarkApplied,
  busy,
}: {
  show: boolean;
  lastModifiedAt?: string;
  onMarkApplied: () => void;
  busy: boolean;
}) {
  if (!show) return null;
  return (
    <div className="mb-4 flex items-start gap-3 bg-amber-950/40 border border-amber-800 rounded-lg px-4 py-3 text-sm">
      <span className="flex-1 text-amber-100">
        <span className="font-semibold">Pending reload.</span>{' '}
        Panel state has changed
        {lastModifiedAt && (
          <>
            {' '}at{' '}
            <span className="font-mono text-xs text-amber-300">
              {new Date(lastModifiedAt).toLocaleString()}
            </span>
          </>
        )}
        . Run{' '}
        <code className="font-mono text-xs text-amber-300">
          docker compose exec crowdsec /setup-appsec.sh
        </code>
        , then click "Mark as applied". (If the script errored, the
        underlying CrowdSec state will not match -- re-run and check
        logs.)
      </span>
      <button
        type="button"
        onClick={onMarkApplied}
        disabled={busy}
        className="ml-auto px-3 py-1 rounded bg-amber-700 hover:bg-amber-600 disabled:opacity-50 text-white text-xs font-medium whitespace-nowrap"
      >
        {busy ? 'marking...' : 'Mark as applied'}
      </button>
    </div>
  );
}

// =============================================================
// Scenarios tab
// =============================================================

function ScenariosTab() {
  const toasts = useToasts();
  const [data, setData] = useState<SecurityScenariosResponse | null>(null);
  const [loading, setLoading] = useState(false);
  const [busy, setBusy] = useState<string | null>(null);
  const [markBusy, setMarkBusy] = useState(false);

  const refresh = useCallback(async () => {
    setLoading(true);
    try {
      const r = await api.securityListScenarios();
      setData(r);
    } catch (e) {
      toasts.push(e instanceof ApiError ? e.message : 'load failed', 'error');
    } finally {
      setLoading(false);
    }
  }, [toasts]);

  useEffect(() => {
    refresh();
  }, [refresh]);

  async function toggle(s: SecurityScenarioItem, disable: boolean) {
    if (
      disable &&
      !window.confirm(
        `Disable ${s.canonical_name}? It won't enforce until ` +
          `you run setup-appsec.sh.`,
      )
    )
      return;
    setBusy(s.canonical_name);
    try {
      await api.securityPatchScenario(s.canonical_name, disable);
      toasts.push(
        `${disable ? 'Disabled' : 'Enabled'} ${s.canonical_name}. Run \`docker compose exec crowdsec /setup-appsec.sh\` to apply.`,
        'success',
      );
      await refresh();
    } catch (err) {
      toasts.push(
        err instanceof ApiError ? err.message : 'patch failed',
        'error',
      );
    } finally {
      setBusy(null);
    }
  }

  async function markApplied() {
    setMarkBusy(true);
    try {
      await api.securityScenariosMarkApplied();
      toasts.push('Marked as applied', 'success');
      await refresh();
    } catch (err) {
      toasts.push(
        err instanceof ApiError ? err.message : 'mark failed',
        'error',
      );
    } finally {
      setMarkBusy(false);
    }
  }

  if (loading && !data) {
    return <p className="text-sm text-slate-500">loading...</p>;
  }
  if (!data) {
    return <p className="text-sm text-slate-500">No data.</p>;
  }
  if (!data.is_available) {
    return (
      <div className="bg-slate-900 border border-slate-800 rounded-lg p-6 text-sm text-slate-400">
        <p className="font-semibold mb-2">No scenarios detected.</p>
        <p>
          The panel reads installed scenarios from{' '}
          <code className="font-mono text-slate-300">{data.mount_path}/scenarios</code>.
          That directory is empty or unreadable. Possible causes:
        </p>
        <ul className="list-disc ml-6 mt-2 space-y-1">
          <li>The crowdsec service isn't running yet.</li>
          <li>
            The compose volume mount{' '}
            <code className="font-mono text-slate-300">crowdsec_config:/crowdsec-state:ro</code>{' '}
            is missing -- check{' '}
            <code className="font-mono text-slate-300">docker-compose.yml</code>.
          </li>
          <li>
            <code className="font-mono text-slate-300">setup-appsec.sh</code> hasn't
            installed any scenarios yet -- run it once, then refresh.
          </li>
        </ul>
      </div>
    );
  }

  const sources = Array.from(
    new Set(data.scenarios.map((s) => s.source ?? 'local').filter(Boolean)),
  ).sort();

  return (
    <div>
      <PendingReloadBadge
        show={data.reload_needed}
        lastModifiedAt={data.last_modified_at}
        onMarkApplied={markApplied}
        busy={markBusy}
      />

      <div className="text-xs text-slate-500 mb-3">
        {data.scenarios.length} scenarios installed —{' '}
        {data.disabled_count} disabled by panel —{' '}
        sources: {sources.join(', ')}
      </div>

      <div className="bg-slate-900 border border-slate-800 rounded-lg overflow-hidden">
        <table className="w-full text-sm">
          <thead className="bg-slate-950/60 text-slate-400 uppercase text-xs tracking-wide">
            <tr>
              <th className="text-left px-3 py-2">Scenario</th>
              <th className="text-left px-3 py-2">Source</th>
              <th className="text-left px-3 py-2">Status</th>
              <th className="text-right px-3 py-2"></th>
            </tr>
          </thead>
          <tbody>
            {data.scenarios.map((s) => (
              <tr
                key={s.canonical_name}
                className="border-t border-slate-800/50 hover:bg-slate-800/30"
              >
                <td className="px-3 py-2 font-mono text-slate-200">
                  {s.short_name}
                </td>
                <td className="px-3 py-2 text-slate-400 text-xs">
                  {s.source ?? '—'}
                </td>
                <td className="px-3 py-2">
                  {s.disabled ? (
                    <span className="px-2 py-0.5 rounded bg-amber-900/40 border border-amber-800 text-amber-200 text-xs">
                      disabled by panel
                    </span>
                  ) : (
                    <span className="px-2 py-0.5 rounded bg-emerald-900/30 border border-emerald-800 text-emerald-200 text-xs">
                      enabled
                    </span>
                  )}
                </td>
                <td className="px-3 py-2 text-right">
                  <button
                    type="button"
                    onClick={() => toggle(s, !s.disabled)}
                    disabled={busy !== null}
                    className={`px-2 py-1 rounded text-xs ${
                      s.disabled
                        ? 'border border-emerald-800 text-emerald-300 hover:bg-emerald-900/40'
                        : 'border border-amber-800 text-amber-300 hover:bg-amber-900/40'
                    } disabled:opacity-50`}
                  >
                    {busy === s.canonical_name
                      ? '...'
                      : s.disabled
                        ? 'Re-enable'
                        : 'Disable'}
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

// =============================================================
// AppSec tuning tab
// =============================================================

function AppSecTab() {
  const toasts = useToasts();
  const [data, setData] = useState<SecurityAppSecTuning | null>(null);
  const [loading, setLoading] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [markBusy, setMarkBusy] = useState(false);
  const [inbound, setInbound] = useState<string>('');
  const [outbound, setOutbound] = useState<string>('');

  const refresh = useCallback(async () => {
    setLoading(true);
    try {
      const r = await api.securityGetAppSecTuning();
      setData(r);
      setInbound(String(r.inbound_threshold));
      setOutbound(String(r.outbound_threshold));
    } catch (e) {
      toasts.push(e instanceof ApiError ? e.message : 'load failed', 'error');
    } finally {
      setLoading(false);
    }
  }, [toasts]);

  useEffect(() => {
    refresh();
  }, [refresh]);

  async function save(e: React.FormEvent) {
    e.preventDefault();
    const inN = parseInt(inbound, 10);
    const outN = parseInt(outbound, 10);
    if (Number.isNaN(inN) || Number.isNaN(outN) || inN < 1 || outN < 1 || inN > 100 || outN > 100) {
      toasts.push('thresholds must be integers in 1..100', 'error');
      return;
    }
    setSubmitting(true);
    try {
      const r = await api.securityPatchAppSecTuning({
        inbound_threshold: inN,
        outbound_threshold: outN,
      });
      setData(r);
      toasts.push(
        'Thresholds saved. Run `docker compose exec crowdsec /setup-appsec.sh` to apply.',
        'success',
      );
      await refresh();
    } catch (err) {
      toasts.push(
        err instanceof ApiError ? err.message : 'save failed',
        'error',
      );
    } finally {
      setSubmitting(false);
    }
  }

  async function markApplied() {
    setMarkBusy(true);
    try {
      await api.securityAppSecTuningMarkApplied();
      toasts.push('Marked as applied', 'success');
      await refresh();
    } catch (err) {
      toasts.push(
        err instanceof ApiError ? err.message : 'mark failed',
        'error',
      );
    } finally {
      setMarkBusy(false);
    }
  }

  if (loading && !data) {
    return <p className="text-sm text-slate-500">loading...</p>;
  }
  if (!data) return null;

  return (
    <div>
      <PendingReloadBadge
        show={data.reload_needed}
        lastModifiedAt={data.last_modified_at}
        onMarkApplied={markApplied}
        busy={markBusy}
      />

      <div className="bg-slate-900 border border-slate-800 rounded-lg p-6 max-w-2xl">
        <h2 className="text-lg font-semibold mb-1 text-slate-200">
          AppSec anomaly thresholds
        </h2>
        <p className="text-xs text-slate-400 mb-4">
          Bumps the OWASP CRS inbound + outbound anomaly score
          thresholds. Defaults (15 / 4) are the v1.3.19 homelab tune;
          CRS upstream defaults are 5 / 4 (enterprise tune). Higher
          inbound = more permissive (fewer false-positive blocks);
          lower = stricter. Outbound rarely needs adjustment.
        </p>

        <form onSubmit={save} className="space-y-4 text-sm">
          <div>
            <label className="block text-slate-300 mb-1">
              Inbound threshold
            </label>
            <input
              type="number"
              min={1}
              max={100}
              value={inbound}
              onChange={(e) => setInbound(e.target.value)}
              className="w-32 px-3 py-2 rounded bg-slate-800 border border-slate-700 font-mono"
            />
            <span className="ml-2 text-xs text-slate-500">
              (CRS default: 5; argos default: 15)
            </span>
          </div>

          <div>
            <label className="block text-slate-300 mb-1">
              Outbound threshold
            </label>
            <input
              type="number"
              min={1}
              max={100}
              value={outbound}
              onChange={(e) => setOutbound(e.target.value)}
              className="w-32 px-3 py-2 rounded bg-slate-800 border border-slate-700 font-mono"
            />
            <span className="ml-2 text-xs text-slate-500">
              (CRS default: 4; argos default: 4)
            </span>
          </div>

          <button
            type="submit"
            disabled={submitting}
            className="px-4 py-2 rounded bg-sky-600 hover:bg-sky-500 disabled:opacity-50 text-sm font-medium"
          >
            {submitting ? 'saving...' : 'Save thresholds'}
          </button>
        </form>
      </div>
    </div>
  );
}

// TabStrip renders the three real tabs plus a visually-distinct
// Hosts link. The link uses an external-link arrow + a separator
// so it reads as "leaving the tab shell" rather than another tab
// body inside this page.
function TabStrip({
  active,
  onChange,
}: {
  active: TabID;
  onChange: (id: TabID) => void;
}) {
  return (
    <div className="flex items-end border-b border-slate-800">
      {TABS.map((t) => {
        const isActive = t.id === active;
        return (
          <button
            key={t.id}
            type="button"
            onClick={() => onChange(t.id)}
            className={`px-4 py-2 text-sm font-medium border-b-2 -mb-px transition-colors ${
              isActive
                ? 'border-sky-500 text-sky-300'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            {t.label}
          </button>
        );
      })}
      <div className="ml-auto flex items-center gap-2 pl-4 border-l border-slate-800">
        <Link
          to="/security/hosts"
          className="px-4 py-2 text-sm text-slate-400 hover:text-slate-200 inline-flex items-center gap-1"
          title="Per-host WAF / rate-limit config (separate page)"
        >
          Hosts
          <span aria-hidden className="text-xs">↗</span>
        </Link>
      </div>
    </div>
  );
}

// =============================================================
// Banned IPs tab
// =============================================================

function BannedIPsTab() {
  const toasts = useToasts();
  const [data, setData] = useState<SecurityDecisionsListResponse | null>(null);
  const [loading, setLoading] = useState(false);
  const [busyID, setBusyID] = useState<number | null>(null);
  const [q, setQ] = useState('');
  const [scope, setScope] = useState('');
  const [origin, setOrigin] = useState('');
  const [offset, setOffset] = useState(0);

  const limit = 100;

  const refresh = useCallback(async () => {
    setLoading(true);
    try {
      const r = await api.securityListDecisions({
        q: q.trim() || undefined,
        scope: scope || undefined,
        origin: origin || undefined,
        limit,
        offset,
      });
      setData(r);
    } catch (e) {
      toasts.push(e instanceof ApiError ? e.message : 'load failed', 'error');
    } finally {
      setLoading(false);
    }
  }, [q, scope, origin, offset, toasts]);

  useEffect(() => {
    refresh();
  }, [refresh]);

  async function unban(id: number, value: string) {
    if (!window.confirm(`Unban ${value}?`)) return;
    setBusyID(id);
    try {
      const r = await api.securityDeleteDecisionByID(id);
      toasts.push(
        r.deleted ? `Unbanned ${value}` : `${value} was already gone`,
        'success',
      );
      // Optimistic remove + refresh.
      setData((prev) =>
        prev
          ? {
              ...prev,
              decisions: prev.decisions.filter((d) => d.id !== id),
              total: prev.total - (r.deleted ? 1 : 0),
            }
          : prev,
      );
    } catch (err) {
      toasts.push(err instanceof ApiError ? err.message : 'unban failed', 'error');
    } finally {
      setBusyID(null);
    }
  }

  // Distinct origins for the filter dropdown; populated from the
  // current page so a fresh stack with no decisions doesn't show
  // stale options.
  const distinctOrigins = useMemo(() => {
    const set = new Set<string>();
    data?.decisions.forEach((d) => set.add(d.origin));
    return Array.from(set).sort();
  }, [data]);

  return (
    <div>
      <div className="flex flex-wrap gap-2 items-end mb-3 text-sm">
        <div>
          <label className="block text-slate-400 text-xs mb-1">Search</label>
          <input
            type="text"
            value={q}
            onChange={(e) => {
              setQ(e.target.value);
              setOffset(0);
            }}
            placeholder="value or scenario"
            className="px-3 py-1.5 rounded bg-slate-800 border border-slate-700"
          />
        </div>
        <div>
          <label className="block text-slate-400 text-xs mb-1">Scope</label>
          <select
            value={scope}
            onChange={(e) => {
              setScope(e.target.value);
              setOffset(0);
            }}
            className="px-3 py-1.5 rounded bg-slate-800 border border-slate-700"
          >
            <option value="">All</option>
            <option value="Ip">Ip</option>
            <option value="Range">Range</option>
            <option value="Country">Country</option>
            <option value="AS">AS</option>
          </select>
        </div>
        <div>
          <label className="block text-slate-400 text-xs mb-1">Origin</label>
          <select
            value={origin}
            onChange={(e) => {
              setOrigin(e.target.value);
              setOffset(0);
            }}
            className="px-3 py-1.5 rounded bg-slate-800 border border-slate-700"
          >
            <option value="">All</option>
            {distinctOrigins.map((o) => (
              <option key={o} value={o}>
                {o}
              </option>
            ))}
          </select>
        </div>
        <div className="ml-auto text-xs text-slate-500">
          {data ? `${data.total} total` : ''}
        </div>
      </div>

      {loading && !data ? (
        <p className="text-sm text-slate-500">loading...</p>
      ) : !data || data.decisions.length === 0 ? (
        <p className="text-sm text-slate-500">No matching decisions.</p>
      ) : (
        <DecisionsTable
          rows={data.decisions}
          busyID={busyID}
          onUnban={unban}
        />
      )}

      <Pagination
        total={data?.total ?? 0}
        limit={limit}
        offset={offset}
        onChange={setOffset}
      />
    </div>
  );
}

function DecisionsTable({
  rows,
  busyID,
  onUnban,
}: {
  rows: SecurityDecision[];
  busyID: number | null;
  onUnban: (id: number, value: string) => void;
}) {
  return (
    <div className="bg-slate-900 border border-slate-800 rounded-lg overflow-hidden">
      <table className="w-full text-sm">
        <thead className="bg-slate-950/60 text-slate-400 uppercase text-xs tracking-wide">
          <tr>
            <th className="text-left px-3 py-2">Value</th>
            <th className="text-left px-3 py-2">Scope</th>
            <th className="text-left px-3 py-2">Type</th>
            <th className="text-left px-3 py-2">Origin</th>
            <th className="text-left px-3 py-2">Scenario</th>
            <th className="text-left px-3 py-2">Duration</th>
            <th className="text-right px-3 py-2"></th>
          </tr>
        </thead>
        <tbody>
          {rows.map((d) => (
            <tr
              key={d.id}
              className="border-t border-slate-800/50 hover:bg-slate-800/30"
            >
              <td className="px-3 py-2 font-mono text-slate-200">{d.value}</td>
              <td className="px-3 py-2 text-slate-400">{d.scope}</td>
              <td className="px-3 py-2 text-slate-400">{d.type}</td>
              <td className="px-3 py-2 text-slate-400 font-mono text-xs">
                {d.origin}
              </td>
              <td className="px-3 py-2 text-slate-400 truncate max-w-xs">
                {d.scenario}
              </td>
              <td className="px-3 py-2 text-slate-500 font-mono text-xs">
                {d.duration}
              </td>
              <td className="px-3 py-2 text-right">
                <button
                  type="button"
                  onClick={() => onUnban(d.id, d.value)}
                  disabled={busyID !== null}
                  className="px-2 py-1 rounded border border-red-800 text-red-300 hover:bg-red-900/40 disabled:opacity-50 text-xs"
                >
                  {busyID === d.id ? 'unbanning...' : 'Unban'}
                </button>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

// =============================================================
// Whitelist tab
// =============================================================

function WhitelistTab() {
  const toasts = useToasts();
  const [entries, setEntries] = useState<SecurityWhitelistEntry[]>([]);
  const [loading, setLoading] = useState(false);
  const [busyID, setBusyID] = useState<number | null>(null);
  const [scope, setScope] = useState<'ip' | 'range'>('ip');
  const [value, setValue] = useState('');
  const [reason, setReason] = useState('');
  const [submitting, setSubmitting] = useState(false);

  const refresh = useCallback(async () => {
    setLoading(true);
    try {
      const r = await api.securityListWhitelist();
      setEntries(r.entries ?? []);
    } catch (e) {
      toasts.push(e instanceof ApiError ? e.message : 'load failed', 'error');
    } finally {
      setLoading(false);
    }
  }, [toasts]);

  useEffect(() => {
    refresh();
  }, [refresh]);

  async function add(e: React.FormEvent) {
    e.preventDefault();
    if (!value.trim()) {
      toasts.push('value required', 'error');
      return;
    }
    setSubmitting(true);
    try {
      const r = await api.securityWhitelistAdd(scope, value.trim(), reason.trim());
      toasts.push(
        `Added ${scope}:${value.trim()}. Run \`${r.reload_command}\` for the whitelist to apply.`,
        'success',
      );
      setValue('');
      setReason('');
      await refresh();
    } catch (err) {
      if (err instanceof ApiError && err.status === 409) {
        toasts.push('That entry already exists', 'error');
      } else {
        toasts.push(
          err instanceof ApiError ? err.message : 'add failed',
          'error',
        );
      }
    } finally {
      setSubmitting(false);
    }
  }

  async function remove(id: number, label: string) {
    if (!window.confirm(`Remove whitelist entry ${label}?`)) return;
    setBusyID(id);
    try {
      const r = await api.securityDeleteWhitelistEntry(id);
      toasts.push(
        r.deleted
          ? `Removed. Run \`${r.reload_command}\` for CrowdSec to drop the entry.`
          : `Already gone`,
        'success',
      );
      await refresh();
    } catch (err) {
      toasts.push(
        err instanceof ApiError ? err.message : 'delete failed',
        'error',
      );
    } finally {
      setBusyID(null);
    }
  }

  return (
    <div>
      <form onSubmit={add} className="flex flex-wrap gap-2 items-end mb-4 text-sm">
        <div>
          <label className="block text-slate-400 text-xs mb-1">Scope</label>
          <select
            value={scope}
            onChange={(e) => setScope(e.target.value as 'ip' | 'range')}
            className="px-3 py-2 rounded bg-slate-800 border border-slate-700"
          >
            <option value="ip">ip</option>
            <option value="range">range</option>
          </select>
        </div>
        <div>
          <label className="block text-slate-400 text-xs mb-1">Value</label>
          <input
            type="text"
            value={value}
            onChange={(e) => setValue(e.target.value)}
            placeholder={scope === 'ip' ? '192.0.2.10' : '198.51.100.0/24'}
            className="px-3 py-2 rounded bg-slate-800 border border-slate-700 font-mono w-56"
          />
        </div>
        <div className="flex-1 min-w-[200px]">
          <label className="block text-slate-400 text-xs mb-1">Reason (optional)</label>
          <input
            type="text"
            value={reason}
            onChange={(e) => setReason(e.target.value)}
            placeholder="why this is whitelisted"
            className="w-full px-3 py-2 rounded bg-slate-800 border border-slate-700"
          />
        </div>
        <button
          type="submit"
          disabled={submitting}
          className="px-4 py-2 rounded bg-sky-600 hover:bg-sky-500 disabled:opacity-50 text-sm font-medium"
        >
          {submitting ? 'adding...' : 'Add entry'}
        </button>
      </form>

      <p className="text-xs text-slate-500 mb-3">
        Whitelist entries take effect after running{' '}
        <code className="font-mono text-slate-400">
          docker compose exec crowdsec /setup-appsec.sh
        </code>
        . The system ranges (RFC 1918 / loopback / ULA) are always
        whitelisted; the entries below are operator additions.
      </p>

      {loading && entries.length === 0 ? (
        <p className="text-sm text-slate-500">loading...</p>
      ) : entries.length === 0 ? (
        <p className="text-sm text-slate-500">No whitelist entries.</p>
      ) : (
        <div className="bg-slate-900 border border-slate-800 rounded-lg overflow-hidden">
          <table className="w-full text-sm">
            <thead className="bg-slate-950/60 text-slate-400 uppercase text-xs tracking-wide">
              <tr>
                <th className="text-left px-3 py-2">Scope</th>
                <th className="text-left px-3 py-2">Value</th>
                <th className="text-left px-3 py-2">Reason</th>
                <th className="text-left px-3 py-2">Created</th>
                <th className="text-right px-3 py-2"></th>
              </tr>
            </thead>
            <tbody>
              {entries.map((e) => (
                <tr
                  key={e.id}
                  className="border-t border-slate-800/50 hover:bg-slate-800/30"
                >
                  <td className="px-3 py-2 text-slate-400">{e.scope}</td>
                  <td className="px-3 py-2 font-mono text-slate-200">
                    {e.value}
                  </td>
                  <td className="px-3 py-2 text-slate-400 truncate max-w-xs">
                    {e.reason || <span className="text-slate-600">—</span>}
                  </td>
                  <td className="px-3 py-2 text-slate-500 text-xs">
                    {new Date(e.created_at).toLocaleString()}
                  </td>
                  <td className="px-3 py-2 text-right">
                    <button
                      type="button"
                      onClick={() => remove(e.id, `${e.scope}:${e.value}`)}
                      disabled={busyID !== null}
                      className="px-2 py-1 rounded border border-red-800 text-red-300 hover:bg-red-900/40 disabled:opacity-50 text-xs"
                    >
                      {busyID === e.id ? 'removing...' : 'Remove'}
                    </button>
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

// =============================================================
// Activity tab
// =============================================================

function ActivityTab() {
  const toasts = useToasts();
  const [data, setData] = useState<SecurityAuditLogResponse | null>(null);
  const [loading, setLoading] = useState(false);
  const [q, setQ] = useState('');
  const [offset, setOffset] = useState(0);

  const limit = 100;

  const refresh = useCallback(async () => {
    setLoading(true);
    try {
      const r = await api.securityAuditLog({
        q: q.trim() || undefined,
        limit,
        offset,
      });
      setData(r);
    } catch (e) {
      toasts.push(e instanceof ApiError ? e.message : 'load failed', 'error');
    } finally {
      setLoading(false);
    }
  }, [q, offset, toasts]);

  useEffect(() => {
    refresh();
  }, [refresh]);

  return (
    <div>
      <div className="flex flex-wrap gap-2 items-end mb-3 text-sm">
        <div>
          <label className="block text-slate-400 text-xs mb-1">Search</label>
          <input
            type="text"
            value={q}
            onChange={(e) => {
              setQ(e.target.value);
              setOffset(0);
            }}
            placeholder="action, resource, IP"
            className="px-3 py-1.5 rounded bg-slate-800 border border-slate-700"
          />
        </div>
        <div className="ml-auto text-xs text-slate-500">
          {data ? `${data.total} total` : ''}
        </div>
      </div>

      {loading && !data ? (
        <p className="text-sm text-slate-500">loading...</p>
      ) : !data || data.entries.length === 0 ? (
        <p className="text-sm text-slate-500">No matching audit entries.</p>
      ) : (
        <div className="bg-slate-900 border border-slate-800 rounded-lg overflow-hidden">
          <table className="w-full text-sm">
            <thead className="bg-slate-950/60 text-slate-400 uppercase text-xs tracking-wide">
              <tr>
                <th className="text-left px-3 py-2">When</th>
                <th className="text-left px-3 py-2">Action</th>
                <th className="text-left px-3 py-2">Resource</th>
                <th className="text-left px-3 py-2">Source IP</th>
                <th className="text-left px-3 py-2">User</th>
                <th className="text-left px-3 py-2">Diff</th>
              </tr>
            </thead>
            <tbody>
              {data.entries.map((e) => (
                <ActivityRow key={e.id} e={e} />
              ))}
            </tbody>
          </table>
        </div>
      )}

      <Pagination
        total={data?.total ?? 0}
        limit={limit}
        offset={offset}
        onChange={setOffset}
      />
    </div>
  );
}

function ActivityRow({ e }: { e: SecurityAuditLogEntry }) {
  const [expanded, setExpanded] = useState(false);
  const hasDiff = e.diff && Object.keys(e.diff).length > 0;
  const resource = e.resource_type
    ? `${e.resource_type}${e.resource_id ? `:${e.resource_id}` : ''}`
    : '—';
  return (
    <>
      <tr className="border-t border-slate-800/50 hover:bg-slate-800/30">
        <td className="px-3 py-2 text-slate-500 text-xs whitespace-nowrap">
          {new Date(e.timestamp).toLocaleString()}
        </td>
        <td className="px-3 py-2 text-slate-200 font-mono text-xs">
          {e.action}
        </td>
        <td className="px-3 py-2 text-slate-400 text-xs">{resource}</td>
        <td className="px-3 py-2 text-slate-400 font-mono text-xs">
          {e.source_ip || <span className="text-slate-600">—</span>}
        </td>
        <td className="px-3 py-2 text-slate-400 text-xs">
          {e.user_id || <span className="text-slate-600">—</span>}
        </td>
        <td className="px-3 py-2">
          {hasDiff ? (
            <button
              type="button"
              onClick={() => setExpanded((v) => !v)}
              className="text-xs text-sky-400 hover:underline"
            >
              {expanded ? 'hide' : 'show'}
            </button>
          ) : (
            <span className="text-slate-600 text-xs">—</span>
          )}
        </td>
      </tr>
      {expanded && hasDiff && (
        <tr className="border-t border-slate-800/30">
          <td colSpan={6} className="px-3 py-2 bg-slate-950/40">
            <pre className="text-xs text-slate-300 font-mono whitespace-pre-wrap break-words">
              {JSON.stringify(e.diff, null, 2)}
            </pre>
          </td>
        </tr>
      )}
    </>
  );
}

// =============================================================
// Pagination
// =============================================================

function Pagination({
  total,
  limit,
  offset,
  onChange,
}: {
  total: number;
  limit: number;
  offset: number;
  onChange: (n: number) => void;
}): ReactNode {
  if (total <= limit) return null;
  const page = Math.floor(offset / limit) + 1;
  const pages = Math.ceil(total / limit);
  const prev = Math.max(0, offset - limit);
  const next = Math.min(total - 1, offset + limit);
  return (
    <div className="mt-3 flex items-center gap-2 text-sm">
      <button
        type="button"
        onClick={() => onChange(prev)}
        disabled={offset === 0}
        className="px-3 py-1 rounded border border-slate-700 text-slate-300 hover:bg-slate-800 disabled:opacity-50"
      >
        Prev
      </button>
      <span className="text-xs text-slate-500">
        Page {page} of {pages}
      </span>
      <button
        type="button"
        onClick={() => onChange(next)}
        disabled={offset + limit >= total}
        className="px-3 py-1 rounded border border-slate-700 text-slate-300 hover:bg-slate-800 disabled:opacity-50"
      >
        Next
      </button>
    </div>
  );
}
