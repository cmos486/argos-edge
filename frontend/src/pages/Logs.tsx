import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { useUrlFilters } from '../hooks/useUrlFilters';
import { FilterBar, type Field } from '../components/FilterBar';
import { type RangeKey, type Schema } from '../lib/filters';
import { Link } from 'react-router-dom';
import { Download, Play, Radio, X } from 'lucide-react';
import {
  ApiError,
  GeoEnrichment,
  LogEntry,
  LogPreset,
  LogStats,
  LogsPipeline,
  api,
} from '../api/client';
import { getLastKnown, setLastKnown } from '../api/lastKnown';
import GeoFlag from '../components/GeoFlag';
import RelativeTime from '../components/RelativeTime';
import { SkeletonCards, SkeletonTable } from '../components/Skeleton';
import { useToasts } from '../components/toastsContext';

const LOG_RANGES: RangeKey[] = ['15m', '1h', '6h', '24h', '7d', '30d'];

// v1.3.42.1: every filter lives in the URL (useUrlFilters), so links
// from the Dashboard, the certificate panel and the header search
// land filtered, a reload keeps the view and back walks views.
const LOGS_SCHEMA = {
  range: { kind: 'range', allowed: LOG_RANGES, default: '1h' },
  source: { kind: 'enum', values: ['', 'caddy_access', 'caddy_error', 'audit', 'waf_audit'], default: '' },
  status: { kind: 'text' },
  method: { kind: 'text' },
  path: { kind: 'text' },
  regex: { kind: 'bool' },
  host_id: { kind: 'text' },
  ip: { kind: 'text' },
  q: { kind: 'text' },
  limit: { kind: 'int', default: 100, min: 1, max: 500 },
  offset: { kind: 'int', default: 0, min: 0 },
} satisfies Schema;

const LOG_FIELDS: Field[] = [
  { kind: 'range', key: 'range', presets: LOG_RANGES },
  {
    kind: 'select', key: 'source', label: 'All sources',
    options: [
      { value: 'caddy_access', label: 'caddy_access' },
      { value: 'caddy_error', label: 'caddy_error' },
      { value: 'audit', label: 'audit' },
      { value: 'waf_audit', label: 'waf_audit (Coraza)' },
    ],
  },
  { kind: 'text', key: 'q', placeholder: 'search (q)', wide: true },
  { kind: 'text', key: 'ip', placeholder: 'ip (exact or prefix)', mono: true },
  { kind: 'text', key: 'status', placeholder: 'status (200, 4xx, 200-299)', mono: true },
  { kind: 'text', key: 'method', placeholder: 'method (GET,POST)', mono: true },
  { kind: 'text', key: 'path', placeholder: 'path', mono: true },
];

interface LogsLastKnown {
  entries: LogEntry[];
  total: number;
  stats: LogStats | null;
}

// droppedSummary groups the per-rule counters by kind for the one-line
// notice: "20,400 monitor requests, 2,880 health-checker lines".
function droppedSummary(byRule: Record<string, number>): string {
  let ua = 0, logger = 0, path = 0;
  for (const [k, v] of Object.entries(byRule)) {
    if (k.startsWith('user_agent:')) ua += v;
    else if (k.startsWith('logger:')) logger += v;
    else if (k.startsWith('path:')) path += v;
  }
  const parts: string[] = [];
  if (ua) parts.push(`${ua.toLocaleString()} monitor requests`);
  if (logger) parts.push(`${logger.toLocaleString()} health-checker lines`);
  if (path) parts.push(`${path.toLocaleString()} by path`);
  return parts.join(', ');
}

// appsecWindowLink carries the Logs range to the AppSec page; a preset
// AppSec does not mount (15m, 7d, 30d) falls back to its default there
// (pickRange). The preset's fallback path wins when present.
function appsecWindowLink(k: RangeKey, fallback: string | null): string {
  if (fallback) return fallback;
  return `/appsec?range=${k}`;
}

// hostsOnce: the hosts list fetched once per session, used to degrade
// a link with a host_id that no longer exists to "no host filter".
let hostsOnce: Promise<{ id: number; domain: string }[]> | null = null;
function loadHostsOnce() {
  if (!hostsOnce) hostsOnce = api.listHosts().then((hs) => hs.map((h) => ({ id: h.id, domain: h.domain })));
  return hostsOnce;
}

export default function Logs() {
  const toasts = useToasts();
  const { values: filters, debounced, set, reset } = useUrlFilters(LOGS_SCHEMA);
  const range = filters.range;
  const limit = filters.limit;
  const offset = filters.offset;
  // change: a filter edit goes back to the first page; keystrokes
  // replace the history entry, selects and ranges push one.
  const change = useCallback(
    (patch: Record<string, string | number | boolean>, push: boolean) => set({ ...patch, offset: 0 } as Partial<typeof filters>, { push }),
    [set],
  );
  const setOffset = useCallback((n: number) => set({ offset: n } as Partial<typeof filters>, { push: true }), [set]);
  // v1.3.42.1: a host_id that no longer exists (deleted host) degrades
  // to no host filter with a notice instead of an unexplained empty list.
  const [hostNames, setHostNames] = useState<Map<number, string>>(new Map());
  useEffect(() => {
    loadHostsOnce()
      .then((hs) => setHostNames(new Map(hs.map((h) => [h.id, h.domain]))))
      .catch(() => {});
  }, []);
  useEffect(() => {
    if (!filters.host_id || hostNames.size === 0) return;
    const ids = filters.host_id.split(',').map((x) => parseInt(x, 10)).filter((n) => Number.isFinite(n));
    if (ids.length > 0 && ids.every((id) => hostNames.has(id))) return;
    toasts.push(`host ${filters.host_id} no longer exists; showing all hosts`, 'info');
    set({ host_id: '' } as Partial<typeof filters>);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [filters.host_id, hostNames]);
  const [loading, setLoading] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [live, setLive] = useState(false);
  const [selected, setSelected] = useState<LogEntry | null>(null);
  const [presets, setPresets] = useState<LogPreset[]>([]);
  // v1.3.39: the Coraza presets carry an AppSec fallback link; when the
  // waf_audit table has nothing for the query the page offers it
  // instead of an empty list.
  const [appsecFallback, setAppsecFallback] = useState<string | null>(null);
  // v1.3.40.0: what the ingest filter left out today, and the notes
  // the list endpoint attaches (raw JSON search window).
  const [pipeline, setPipeline] = useState<LogsPipeline | null>(null);
  const [notes, setNotes] = useState<string[]>([]);

  // Never put `filters` (an object) in a hook dep array: React
  // compares deps with Object.is so a brand-new {...EMPTY_FILTERS}
  // reference registers as "changed" even when the values are
  // identical, which cycles every memo and effect that chains off
  // it. Destructure into primitive fields.
  const query = useMemo(() => {
    const q: Record<string, string | number> = { limit: debounced.limit, offset: debounced.offset };
    if (!live) q.range = debounced.range;
    if (debounced.source) q.source = debounced.source;
    if (debounced.status) q.status = debounced.status;
    if (debounced.method) q.method = debounced.method;
    if (debounced.host_id) q.host_id = debounced.host_id;
    if (debounced.ip) q.remote_ip = debounced.ip;
    if (debounced.q) q.q = debounced.q;
    if (debounced.path) q.path = debounced.regex ? `re:${debounced.path}` : debounced.path;
    return q;
  }, [
    live,
    debounced.range, debounced.limit, debounced.offset,
    debounced.source, debounced.status, debounced.method,
    debounced.host_id, debounced.ip, debounced.q, debounced.path, debounced.regex,
  ]);

  // v1.3.38.5: the last list + stats for this exact query (minus the
  // moving `from` timestamp) are kept in memory, so a revisit paints
  // the previous rows at once and a skeleton only shows on a query
  // this session has never seen. On a filter change the previous rows
  // stay on screen while the new ones load.
  const lastKey = useMemo(
    () => 'logs:' + JSON.stringify({ ...query, from: undefined }),
    [query],
  );
  const [entries, setEntries] = useState<LogEntry[]>(() => getLastKnown<LogsLastKnown>(lastKey)?.entries ?? []);
  const [total, setTotal] = useState(() => getLastKnown<LogsLastKnown>(lastKey)?.total ?? 0);
  const [stats, setStats] = useState<LogStats | null>(() => getLastKnown<LogsLastKnown>(lastKey)?.stats ?? null);

  const refresh = useCallback(async () => {
    if (live) return;
    setLoading(true);
    setErr(null);
    try {
      const [list, s] = await Promise.all([
        api.listLogs(query),
        api.logStats(query),
      ]);
      setLastKnown<LogsLastKnown>(lastKey, { entries: list.entries, total: list.total_count, stats: s });
      setEntries(list.entries);
      setTotal(list.total_count);
      setStats(s);
      setNotes(list.notes ?? []);
    } catch (e) {
      setErr(e instanceof ApiError ? e.message : 'load failed');
    } finally {
      setLoading(false);
    }
  }, [query, live, lastKey]);

  useEffect(() => {
    refresh();
  }, [refresh]);

  useEffect(() => {
    api.logPresets().then(setPresets).catch(() => {});
    api.logsPipeline().then(setPipeline).catch(() => {});
  }, []);

  // SSE live mode. EventSource is same-origin so cookies flow by
  // default; withCredentials is set defensively for dev setups where
  // Vite serves the SPA from a different origin than the backend.
  const esRef = useRef<EventSource | null>(null);
  useEffect(() => {
    if (!live) {
      esRef.current?.close();
      esRef.current = null;
      return;
    }
    const qs = new URLSearchParams();
    if (debounced.source) qs.set('source', debounced.source);
    if (debounced.status) qs.set('status', debounced.status);
    if (debounced.method) qs.set('method', debounced.method);
    if (debounced.host_id) qs.set('host_id', debounced.host_id);
    if (debounced.ip) qs.set('remote_ip', debounced.ip);
    if (debounced.q) qs.set('q', debounced.q);
    if (debounced.path) qs.set('path', debounced.regex ? `re:${debounced.path}` : debounced.path);

    const url = `/api/logs/stream?${qs.toString()}`;
    const es = new EventSource(url, { withCredentials: true });
    const seen = new Set<number>();

    const handleData = (data: string) => {
      try {
        const e = JSON.parse(data) as LogEntry;
        if (!e || typeof e.id !== 'number') return;
        // The backend mirrors each row as both a named `entry` event
        // and a default `message` event so proxies that strip the
        // event name still deliver payloads; dedupe by id.
        if (seen.has(e.id)) return;
        seen.add(e.id);
        setEntries((prev) => [e, ...prev].slice(0, 500));
      } catch {
        // Ignore parse errors (partial frames, heartbeats, etc.).
      }
    };

    es.onopen = () => console.debug('[logs/sse] open', url);
    es.onerror = (ev) => console.debug('[logs/sse] error', ev);
    es.addEventListener('entry', (ev) => handleData((ev as MessageEvent).data));
    es.onmessage = (ev) => handleData(ev.data);

    esRef.current = es;
    return () => {
      es.close();
      esRef.current = null;
    };
  }, [
    live,
    debounced.source, debounced.status, debounced.method,
    debounced.host_id, debounced.ip, debounced.q, debounced.path, debounced.regex,
  ]);

  function applyPreset(p: LogPreset) {
    const src = p.filters['source'];
    const status = p.filters['status'];
    const q = p.filters['q'];
    const fb = p.filters['appsec_fallback'];
    setAppsecFallback(typeof fb === 'string' ? fb : null);
    set({
      source: typeof src === 'string' ? src : '',
      status: typeof status === 'string' ? status : '',
      q: typeof q === 'string' ? q : '',
      method: '', path: '', regex: false, host_id: '', ip: '', offset: 0,
    } as Partial<typeof filters>, { push: true });
    toasts.push(`preset applied: ${p.name}`, 'info');
  }

  function clear() {
    reset();
  }

  function exportCSV() {
    const qs = new URLSearchParams();
    qs.set('range', range);
    if (filters.source) qs.set('source', filters.source);
    if (filters.status) qs.set('status', filters.status);
    if (filters.method) qs.set('method', filters.method);
    if (filters.host_id) qs.set('host_id', filters.host_id);
    if (filters.ip) qs.set('remote_ip', filters.ip);
    if (filters.q) qs.set('q', filters.q);
    if (filters.path) qs.set('path', filters.regex ? `re:${filters.path}` : filters.path);
    window.location.assign(`/api/logs/export.csv?${qs.toString()}`);
  }

  return (
    <div className="p-6 max-w-[1400px] mx-auto">
      <div className="flex items-center justify-between mb-4">
        <h1 className="text-2xl font-semibold">Logs</h1>
        <div className="flex items-center gap-2">
          <select
            value=""
            onChange={(e) => {
              const p = presets.find((x) => x.id === e.target.value);
              if (p) applyPreset(p);
            }}
            className="px-3 py-1.5 rounded bg-slate-800 border border-slate-700 text-sm"
          >
            <option value="">Preset...</option>
            {presets.map((p) => (
              <option key={p.id} value={p.id}>{p.name}</option>
            ))}
          </select>
          <button
            type="button"
            onClick={() => setLive((v) => !v)}
            className={`flex items-center gap-1 px-3 py-1.5 rounded text-sm ${
              live ? 'bg-red-900 text-red-200' : 'border border-slate-700 hover:bg-slate-800'
            }`}
          >
            {live ? <Radio className="w-4 h-4" /> : <Play className="w-4 h-4" />}
            {live ? 'Live' : 'Live off'}
          </button>
          <button
            type="button"
            onClick={exportCSV}
            disabled={live}
            className="flex items-center gap-1 px-3 py-1.5 rounded border border-slate-700 hover:bg-slate-800 disabled:opacity-40 text-sm"
          >
            <Download className="w-4 h-4" />
            CSV
          </button>
        </div>
      </div>

      <FilterBar
        fields={live ? LOG_FIELDS.filter((f) => f.kind !== 'range') : LOG_FIELDS}
        values={filters}
        onChange={change}
        onReset={clear}
        extra={
          <>
            {hostNames.size > 0 && (
              <select
                value={filters.host_id}
                onChange={(e) => change({ host_id: e.target.value }, true)}
                className="px-3 py-1.5 rounded bg-slate-800 border border-slate-700 text-sm"
                aria-label="host"
              >
                <option value="">all hosts</option>
                {[...hostNames.entries()].map(([id, domain]) => (
                  <option key={id} value={String(id)}>{domain}</option>
                ))}
              </select>
            )}
            <label className="text-xs flex items-center gap-1 text-slate-400">
              <input
                type="checkbox"
                checked={filters.regex}
                onChange={(e) => change({ regex: e.target.checked }, true)}
                className="w-3 h-3 accent-sky-600"
              />
              path is regex
            </label>
          </>
        }
      />

      {!stats && loading && <div className="mb-3"><SkeletonCards count={5} cols="grid-cols-5" /></div>}

      {pipeline?.ingest.dropped && pipeline.ingest.dropped.total > 0 && (
        <div className="mb-3 text-xs text-slate-400" title={Object.entries(pipeline.ingest.dropped.by_rule).map(([k, v]) => `${k}: ${v.toLocaleString()}`).join('\n')}>
          <span className="text-slate-300">{pipeline.ingest.dropped.total.toLocaleString()}</span>
          {' '}rows excluded by the ingest filter today ({droppedSummary(pipeline.ingest.dropped.by_rule)}); they are counted, not stored.{' '}
          <Link to="/settings" className="underline text-sky-300">Rules</Link>
        </div>
      )}

      {notes.map((n) => (
        <div key={n} className="mb-3 px-3 py-2 rounded bg-slate-800/60 border border-slate-700 text-xs text-slate-300">
          {n}
        </div>
      ))}

      {stats && (
        <div className="grid grid-cols-5 gap-2 mb-3 text-sm">
          <Card label="Total" value={String(stats.total)} />
          <Card label="2xx" value={String(stats.by_status_class['2xx'] ?? 0)} cls="text-emerald-300" />
          <Card label="4xx" value={String(stats.by_status_class['4xx'] ?? 0)} cls="text-amber-300" />
          <Card label="5xx" value={String(stats.by_status_class['5xx'] ?? 0)} cls="text-red-300" />
          <Card
            label={
              stats.percentile_method === 'histogram'
                ? 'avg ms / p95, histogram (bucket edges)'
                : stats.percentile_method === 'sample'
                  ? 'avg ms / p95 (newest 20,000 rows)'
                  : 'avg ms / p95'
            }
            title={
              stats.percentile_method === 'histogram'
                ? 'Closed hours from the hourly rollup, the hour in progress from rows. p95 is the upper edge of the duration bucket holding the rank: 50, 100, 250, 500, 1000, 2500 ms; 5000 means 5,000 ms or more (the open bucket; the maximum is never shown).'
                : undefined
            }
            value={`${stats.avg_duration_ms} / ${
              stats.percentile_method === 'histogram' && stats.p95_duration_ms >= 5000
                ? '5,000 or more'
                : stats.p95_duration_ms
            }`}
          />
        </div>
      )}

      {err && (
        <div className="mb-3 px-3 py-2 rounded bg-red-950/40 border border-red-900 text-sm text-red-300">
          {err}
        </div>
      )}

      {filters.source === 'waf_audit' && !live && !loading && total === 0 && (
        <div className="mb-3 px-3 py-2 rounded bg-sky-950/40 border border-sky-900 text-sm text-sky-200">
          No Coraza audit rows for this query: the per-host Coraza WAF writes them and it is
          off on this stack. WAF blocking is done by CrowdSec AppSec, whose alerts live on the
          AppSec page.{' '}
          <Link to={appsecWindowLink(range, appsecFallback)} className="underline text-sky-300">
            Open AppSec for the same window
          </Link>
        </div>
      )}

      <div className="bg-slate-900 border border-slate-800 rounded-lg overflow-hidden">
        <table className="w-full text-xs">
          <thead className="bg-slate-950/60 text-slate-400 uppercase tracking-wide">
            <tr>
              <th className="text-left px-3 py-1.5 w-40">Time</th>
              <th className="text-left px-3 py-1.5 w-28">Source</th>
              <th className="text-left px-3 py-1.5 w-48">Host</th>
              <th className="text-left px-3 py-1.5 w-20">Method</th>
              <th className="text-left px-3 py-1.5">Path / Message</th>
              <th className="text-left px-3 py-1.5 w-16">Status</th>
              <th className="text-left px-3 py-1.5 w-16">Dur</th>
              <th className="text-left px-3 py-1.5 w-32">Remote IP</th>
            </tr>
          </thead>
          <tbody>
            {entries.length === 0 && loading && (
              <tr>
                <td colSpan={8} className="px-3 py-2">
                  <SkeletonTable rows={10} cols={8} />
                </td>
              </tr>
            )}
            {entries.length === 0 && !loading && (
              <tr>
                <td colSpan={8} className="px-3 py-4 text-slate-500">
                  No logs match your filters.
                </td>
              </tr>
            )}
            {entries.map((e) => (
              <tr
                key={e.id}
                onClick={() => setSelected(e)}
                className={`border-t border-slate-800 cursor-pointer hover:bg-slate-800/40 ${statusRowCls(e)}`}
              >
                <td className="px-3 py-1 text-slate-300 whitespace-nowrap">
                  <RelativeTime iso={e.timestamp} thresholdHours={24} />
                </td>
                <td className="px-3 py-1">
                  <span className="text-[10px] px-1.5 py-0.5 rounded bg-slate-800 text-slate-300">
                    {e.source}
                  </span>
                </td>
                <td className="px-3 py-1 font-mono text-slate-300 truncate">{e.host_domain || ''}</td>
                <td className="px-3 py-1 font-mono text-slate-300">{e.method || ''}</td>
                <td className="px-3 py-1 font-mono text-slate-200 truncate max-w-[500px]">
                  {e.source === 'audit' ? e.message : e.path || e.message}
                </td>
                <td className="px-3 py-1 font-mono">
                  {e.status ? <StatusBadge status={e.status} /> : ''}
                </td>
                <td className="px-3 py-1 font-mono text-slate-400">
                  {e.duration_ms ? `${e.duration_ms}ms` : ''}
                </td>
                <td className="px-3 py-1 font-mono text-slate-400">{e.remote_ip || ''}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {!live && (
        <div className="flex items-center justify-between mt-3 text-sm">
          <div className="text-slate-400">
            {total > 0 ? `${offset + 1}-${Math.min(offset + entries.length, total)} of ${total}` : 'no results'}
          </div>
          <div className="flex items-center gap-2">
            <select
              value={limit}
              onChange={(e) => change({ limit: parseInt(e.target.value, 10) }, true)}
              className="px-2 py-1 rounded bg-slate-800 border border-slate-700 text-xs"
            >
              {[50, 100, 200, 500].map((n) => (
                <option key={n} value={n}>{n}/page</option>
              ))}
            </select>
            <button
              type="button"
              onClick={() => setOffset(Math.max(0, offset - limit))}
              disabled={offset === 0}
              className="px-2 py-1 rounded border border-slate-700 disabled:opacity-40 text-xs"
            >
              Prev
            </button>
            <button
              type="button"
              onClick={() => setOffset(offset + limit)}
              disabled={offset + entries.length >= total}
              className="px-2 py-1 rounded border border-slate-700 disabled:opacity-40 text-xs"
            >
              Next
            </button>
            {(filters.q || filters.ip || filters.source || filters.status || filters.method || filters.path || filters.host_id) && (
              <button
                type="button"
                onClick={clear}
                className="flex items-center gap-1 px-2 py-1 rounded border border-slate-700 text-xs text-slate-300"
              >
                <X className="w-3 h-3" />
                Clear filters
              </button>
            )}
          </div>
        </div>
      )}

      {selected && (
        <Drawer entry={selected} onClose={() => setSelected(null)} onTraceSimilar={(e) => {
          set({
            source: e.source ?? '',
            status: e.status ? String(e.status) : '',
            method: e.method ?? '',
            path: e.path ?? '',
            host_id: e.host_id ? String(e.host_id) : '',
            ip: '', regex: false, q: '', offset: 0,
          } as Partial<typeof filters>, { push: true });
          setSelected(null);
        }} />
      )}
    </div>
  );
}

function Card({ label, value, cls, title }: { label: string; value: string; cls?: string; title?: string }) {
  return (
    <div className="bg-slate-900 border border-slate-800 rounded p-3" title={title}>
      <div className="text-xs uppercase text-slate-500 tracking-wide">{label}</div>
      <div className={`text-xl font-semibold ${cls ?? 'text-slate-200'}`}>{value}</div>
    </div>
  );
}

function StatusBadge({ status }: { status: number }) {
  let cls = 'bg-slate-800 text-slate-300';
  if (status >= 200 && status < 300) cls = 'bg-emerald-900 text-emerald-200';
  else if (status >= 300 && status < 400) cls = 'bg-amber-900 text-amber-200';
  else if (status >= 400 && status < 500) cls = 'bg-orange-900 text-orange-200';
  else if (status >= 500) cls = 'bg-red-900 text-red-200';
  return <span className={`px-1.5 py-0.5 rounded text-xs ${cls}`}>{status}</span>;
}

function statusRowCls(e: LogEntry): string {
  if (e.source === 'audit') return '';
  if (!e.status) return '';
  if (e.status >= 500) return 'bg-red-950/30';
  if (e.status >= 400) return 'bg-orange-950/30';
  if (e.status >= 300) return 'bg-amber-950/20';
  if (e.status >= 200) return '';
  return '';
}

function Drawer({ entry, onClose, onTraceSimilar }: { entry: LogEntry; onClose: () => void; onTraceSimilar: (e: LogEntry) => void }) {
  const [geo, setGeo] = useState<GeoEnrichment | null>(null);
  useEffect(() => {
    setGeo(null);
    if (!entry.remote_ip) return;
    let cancelled = false;
    // Fetch geo via the dedicated endpoint so the cache is shared
    // with the Dashboard Top IPs + Threats decisions surfaces. We
    // don't block the drawer on this; the Row appears once the hit
    // returns.
    fetch(`/api/geoip/lookup?ip=${encodeURIComponent(entry.remote_ip)}`, { credentials: 'same-origin' })
      .then((r) => (r.ok ? r.json() : null))
      .then((g) => { if (!cancelled) setGeo(g); })
      .catch(() => {});
    return () => { cancelled = true; };
  }, [entry.remote_ip]);
  // reference to GeoFlag / GeoEnrichment so the named imports stay
  // used when the JSX below refers to them
  void GeoFlag;
  function copyRaw() {
    navigator.clipboard.writeText(entry.raw || JSON.stringify(entry, null, 2));
  }
  return (
    <div className="fixed inset-0 z-40 flex" onClick={onClose}>
      <div className="flex-1 bg-black/50" />
      <aside
        onClick={(e) => e.stopPropagation()}
        className="w-[480px] bg-slate-900 border-l border-slate-800 h-full overflow-auto text-sm"
      >
        <div className="flex items-center justify-between px-4 py-3 border-b border-slate-800">
          <h2 className="font-semibold">Entry #{entry.id}</h2>
          <button onClick={onClose} className="p-1 rounded hover:bg-slate-800">
            <X className="w-4 h-4" />
          </button>
        </div>
        <div className="p-4 space-y-2">
          <Row label="Time" value={entry.timestamp} />
          <Row label="Source" value={entry.source} />
          {entry.level && <Row label="Level" value={entry.level} />}
          {entry.host_domain && <Row label="Host" value={entry.host_domain} />}
          {entry.host_id != null && <Row label="Host ID" value={String(entry.host_id)} />}
          {entry.rule_id != null && <Row label="Rule ID" value={String(entry.rule_id)} />}
          {entry.method && <Row label="Method" value={entry.method} />}
          {entry.path && <Row label="Path" value={entry.path} />}
          {entry.status != null && <Row label="Status" value={String(entry.status)} />}
          {entry.duration_ms != null && <Row label="Duration" value={`${entry.duration_ms}ms`} />}
          {entry.size_bytes != null && <Row label="Size" value={`${entry.size_bytes}B`} />}
          {entry.remote_ip && <Row label="Remote IP" value={entry.remote_ip} />}
          {entry.remote_ip && geo && (
            <div className="flex items-baseline gap-2 pl-32 -mt-1 text-xs text-slate-400">
              <GeoFlag countryCode={geo.country_code} isPrivate={geo.is_private} />
              <span>
                {geo.is_private
                  ? 'LAN'
                  : geo.country_name
                    ? `${geo.country_name}${geo.country_code ? ` (${geo.country_code})` : ''}`
                    : 'Unknown'}
              </span>
              {geo.asn_org && (
                <span className="font-mono truncate max-w-[220px]" title={geo.asn_org}>
                  · AS{geo.asn} {geo.asn_org}
                </span>
              )}
            </div>
          )}
          {entry.user_agent && <Row label="User-Agent" value={entry.user_agent} />}
          {entry.upstream && <Row label="Upstream" value={entry.upstream} />}
          {entry.message && <Row label="Message" value={entry.message} />}
          {entry.waf_rule_id != null && entry.waf_rule_id > 0 && (
            <Row label="WAF Rule ID" value={String(entry.waf_rule_id)} />
          )}
          {entry.waf_severity && <Row label="WAF Severity" value={entry.waf_severity} />}
          {entry.waf_rule_message && <Row label="WAF Message" value={entry.waf_rule_message} />}
          <div className="pt-2">
            <div className="text-xs uppercase text-slate-500 mb-1">Raw</div>
            {entry.raw_stripped && (
              <div className="mb-1 px-2 py-1 rounded bg-slate-800/60 border border-slate-700 text-xs text-slate-300">
                {entry.raw_note ?? 'raw JSON removed by the retention policy; the columns are complete'}
              </div>
            )}
            <pre className="text-xs p-2 rounded bg-slate-950 border border-slate-800 whitespace-pre-wrap break-all">
              {entry.raw || JSON.stringify(entry, null, 2)}
            </pre>
          </div>
          <div className="flex gap-2 pt-2">
            <button
              type="button"
              onClick={copyRaw}
              className="px-3 py-1 rounded border border-slate-700 hover:bg-slate-800 text-xs"
            >
              Copy raw
            </button>
            <button
              type="button"
              onClick={() => onTraceSimilar(entry)}
              className="px-3 py-1 rounded border border-sky-800 text-sky-300 hover:bg-sky-950 text-xs"
            >
              Trace similar
            </button>
          </div>
        </div>
      </aside>
    </div>
  );
}

function Row({ label, value }: { label: string; value: string }) {
  return (
    <div>
      <div className="text-xs uppercase text-slate-500">{label}</div>
      <div className="font-mono text-slate-200 break-all">{value}</div>
    </div>
  );
}
