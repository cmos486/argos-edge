import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { Download, Play, Radio, X } from 'lucide-react';
import {
  ApiError,
  LogEntry,
  LogPreset,
  LogStats,
  api,
} from '../api/client';
import { useToasts } from '../components/toastsContext';

type TimeRangeKey = '15m' | '1h' | '6h' | '24h' | '7d';

interface Filters {
  source: string;
  status: string;
  method: string;
  path: string;
  host_id: string;
  q: string;
  regex: boolean;
}

const EMPTY_FILTERS: Filters = {
  source: '',
  status: '',
  method: '',
  path: '',
  host_id: '',
  q: '',
  regex: false,
};

function rangeFrom(k: TimeRangeKey): string {
  const d = new Date();
  const m = { '15m': 15, '1h': 60, '6h': 360, '24h': 1440, '7d': 10080 }[k];
  return new Date(d.getTime() - m * 60_000).toISOString();
}

export default function Logs() {
  const toasts = useToasts();
  const [range, setRange] = useState<TimeRangeKey>('1h');
  const [filters, setFilters] = useState<Filters>(() => {
    const f = { ...EMPTY_FILTERS };
    const qs = new URLSearchParams(window.location.search);
    const hid = qs.get('host_id');
    if (hid) f.host_id = hid;
    const src = qs.get('source');
    if (src) f.source = src;
    return f;
  });
  const [entries, setEntries] = useState<LogEntry[]>([]);
  const [total, setTotal] = useState(0);
  const [limit, setLimit] = useState(100);
  const [offset, setOffset] = useState(0);
  const [stats, setStats] = useState<LogStats | null>(null);
  const [loading, setLoading] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [live, setLive] = useState(false);
  const [selected, setSelected] = useState<LogEntry | null>(null);
  const [presets, setPresets] = useState<LogPreset[]>([]);

  const query = useMemo(() => {
    const q: Record<string, string | number> = { limit, offset };
    if (!live) q.from = rangeFrom(range);
    if (filters.source) q.source = filters.source;
    if (filters.status) q.status = filters.status;
    if (filters.method) q.method = filters.method;
    if (filters.host_id) q.host_id = filters.host_id;
    if (filters.q) q.q = filters.q;
    if (filters.path) q.path = filters.regex ? `re:${filters.path}` : filters.path;
    return q;
  }, [range, filters, limit, offset, live]);

  const refresh = useCallback(async () => {
    if (live) return;
    setLoading(true);
    setErr(null);
    try {
      const [list, s] = await Promise.all([
        api.listLogs(query),
        api.logStats(query),
      ]);
      setEntries(list.entries);
      setTotal(list.total_count);
      setStats(s);
    } catch (e) {
      setErr(e instanceof ApiError ? e.message : 'load failed');
    } finally {
      setLoading(false);
    }
  }, [query, live]);

  useEffect(() => {
    refresh();
  }, [refresh]);

  useEffect(() => {
    api.logPresets().then(setPresets).catch(() => {});
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
    if (filters.source) qs.set('source', filters.source);
    if (filters.status) qs.set('status', filters.status);
    if (filters.method) qs.set('method', filters.method);
    if (filters.host_id) qs.set('host_id', filters.host_id);
    if (filters.q) qs.set('q', filters.q);
    if (filters.path) qs.set('path', filters.regex ? `re:${filters.path}` : filters.path);

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
  }, [live, filters]);

  function applyPreset(p: LogPreset) {
    const f = { ...EMPTY_FILTERS };
    const src = p.filters['source'];
    const status = p.filters['status'];
    const q = p.filters['q'];
    if (typeof src === 'string') f.source = src;
    if (typeof status === 'string') f.status = status;
    if (typeof q === 'string') f.q = q;
    setFilters(f);
    setOffset(0);
    toasts.push(`preset applied: ${p.name}`, 'info');
  }

  function clear() {
    setFilters(EMPTY_FILTERS);
    setOffset(0);
  }

  function exportCSV() {
    const qs = new URLSearchParams();
    qs.set('from', rangeFrom(range));
    if (filters.source) qs.set('source', filters.source);
    if (filters.status) qs.set('status', filters.status);
    if (filters.method) qs.set('method', filters.method);
    if (filters.host_id) qs.set('host_id', filters.host_id);
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

      {!live && (
        <div className="flex items-center gap-2 mb-3 text-sm">
          <span className="text-slate-400">Range:</span>
          {(['15m', '1h', '6h', '24h', '7d'] as TimeRangeKey[]).map((k) => (
            <button
              type="button"
              key={k}
              onClick={() => {
                setRange(k);
                setOffset(0);
              }}
              className={`px-2 py-0.5 rounded text-xs ${
                range === k ? 'bg-sky-900 text-sky-200' : 'border border-slate-700 hover:bg-slate-800'
              }`}
            >
              {k}
            </button>
          ))}
        </div>
      )}

      <div className="grid grid-cols-6 gap-2 mb-3 text-sm">
        <input
          type="text"
          placeholder="search (q)"
          value={filters.q}
          onChange={(e) => setFilters({ ...filters, q: e.target.value })}
          className="col-span-2 px-3 py-1.5 rounded bg-slate-800 border border-slate-700"
        />
        <select
          value={filters.source}
          onChange={(e) => setFilters({ ...filters, source: e.target.value })}
          className="px-3 py-1.5 rounded bg-slate-800 border border-slate-700"
        >
          <option value="">All sources</option>
          <option value="caddy_access">caddy_access</option>
          <option value="caddy_error">caddy_error</option>
          <option value="audit">audit</option>
        </select>
        <input
          type="text"
          placeholder="status (200, 4xx, 200-299)"
          value={filters.status}
          onChange={(e) => setFilters({ ...filters, status: e.target.value })}
          className="px-3 py-1.5 rounded bg-slate-800 border border-slate-700 font-mono"
        />
        <input
          type="text"
          placeholder="method (GET,POST)"
          value={filters.method}
          onChange={(e) => setFilters({ ...filters, method: e.target.value })}
          className="px-3 py-1.5 rounded bg-slate-800 border border-slate-700 font-mono"
        />
        <div className="flex items-center gap-1">
          <input
            type="text"
            placeholder="path"
            value={filters.path}
            onChange={(e) => setFilters({ ...filters, path: e.target.value })}
            className="flex-1 px-3 py-1.5 rounded bg-slate-800 border border-slate-700 font-mono"
          />
          <label className="text-xs flex items-center gap-1 text-slate-400">
            <input
              type="checkbox"
              checked={filters.regex}
              onChange={(e) => setFilters({ ...filters, regex: e.target.checked })}
              className="w-3 h-3 accent-sky-600"
            />
            re
          </label>
        </div>
      </div>

      {stats && (
        <div className="grid grid-cols-5 gap-2 mb-3 text-sm">
          <Card label="Total" value={String(stats.total)} />
          <Card label="2xx" value={String(stats.by_status_class['2xx'] ?? 0)} cls="text-emerald-300" />
          <Card label="4xx" value={String(stats.by_status_class['4xx'] ?? 0)} cls="text-amber-300" />
          <Card label="5xx" value={String(stats.by_status_class['5xx'] ?? 0)} cls="text-red-300" />
          <Card label="avg ms / p95" value={`${stats.avg_duration_ms} / ${stats.p95_duration_ms}`} />
        </div>
      )}

      {err && (
        <div className="mb-3 px-3 py-2 rounded bg-red-950/40 border border-red-900 text-sm text-red-300">
          {err}
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
                <td className="px-3 py-1 font-mono text-slate-300 whitespace-nowrap">
                  {formatTime(e.timestamp)}
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
              onChange={(e) => {
                setLimit(parseInt(e.target.value, 10));
                setOffset(0);
              }}
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
            {(filters.q || filters.source || filters.status || filters.method || filters.path) && (
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
          setFilters({
            ...EMPTY_FILTERS,
            source: e.source ?? '',
            status: e.status ? String(e.status) : '',
            method: e.method ?? '',
            path: e.path ?? '',
            host_id: e.host_id ? String(e.host_id) : '',
            regex: false,
            q: '',
          });
          setOffset(0);
          setSelected(null);
        }} />
      )}
    </div>
  );
}

function Card({ label, value, cls }: { label: string; value: string; cls?: string }) {
  return (
    <div className="bg-slate-900 border border-slate-800 rounded p-3">
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

function formatTime(iso: string): string {
  const d = new Date(iso);
  return d.toLocaleTimeString() + '.' + String(d.getMilliseconds()).padStart(3, '0');
}

function Drawer({ entry, onClose, onTraceSimilar }: { entry: LogEntry; onClose: () => void; onTraceSimilar: (e: LogEntry) => void }) {
  function copyRaw() {
    navigator.clipboard.writeText(entry.raw ?? JSON.stringify(entry, null, 2));
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
