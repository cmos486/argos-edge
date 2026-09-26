import { useCallback, useEffect, useRef, useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { Search, X } from 'lucide-react';
import { api } from '../api/client';
import { classifySearch, rangeFrom, type SearchKind } from '../lib/filters';

// GlobalSearch (v1.3.42.1): one input in the header. A pasted IP,
// domain, scenario or free text is classified client-side and, on
// Enter or after 500 ms idle with at least 3 characters, fanned out to
// the endpoints that already exist. Each section names its window and
// its total and links to the owning page with the filter applied.
// "/" focuses the input, Esc closes the panel. Nothing here polls.

const IDLE_MS = 500;
const MIN_CHARS = 3;

interface Section {
  title: string;
  window: string; // "live decisions", "last 24 h", "all hosts"
  total: number | null; // null = not applicable / unknown
  items: { label: string; to: string }[];
  to: string; // "open in page" link with the filter applied
  error?: string;
}

function kindLabel(k: SearchKind): string {
  return k === 'ip' ? 'IP or CIDR' : k === 'domain' ? 'domain' : k === 'scenario' ? 'scenario or rule' : 'text';
}

async function runSearch(kind: SearchKind, value: string, signal: AbortSignal): Promise<Section[]> {
  const enc = encodeURIComponent(value);
  const sections: Section[] = [];
  const guard = <T,>(p: Promise<T>): Promise<T | Error> => p.catch((e: unknown) => (e instanceof Error ? e : new Error('failed')));

  // Decisions (live LAPI list).
  const decisionsQuery =
    kind === 'ip' ? { ip: value } : kind === 'scenario' ? { scenario: value } : { search: value };
  const decisionsTo =
    kind === 'ip' ? `/threats?ip=${enc}` : kind === 'scenario' ? `/threats?scenario=${enc}` : `/threats?q=${enc}`;
  // Logs, newest 24 h.
  const from = rangeFrom('24h');
  const logsQuery: Record<string, string | number> = { from, limit: 5 };
  if (kind === 'ip') logsQuery.remote_ip = value;
  else if (kind === 'domain') logsQuery.q = value; // resolved to host_id below when the domain is a host
  else logsQuery.q = value;
  const logsTo = kind === 'ip' ? `/logs?ip=${enc}&range=24h` : `/logs?q=${enc}&range=24h`;

  const [decisions, logs, hosts, whitelist, collections, appsec] = await Promise.all([
    guard(api.threatsDecisions({ page: 1, per_page: 5, ...decisionsQuery })),
    guard(api.listLogs(logsQuery)),
    guard(api.listHosts()),
    guard(api.securityListWhitelist()),
    guard(api.threatsScenarios()),
    guard(api.appsecMetrics('24h')),
  ]);
  if (signal.aborted) return [];

  if (decisions instanceof Error) {
    sections.push({ title: 'Decisions (bans)', window: 'live', total: null, items: [], to: decisionsTo, error: decisions.message });
  } else {
    sections.push({
      title: 'Decisions (bans)',
      window: 'live',
      total: decisions.total,
      items: decisions.decisions.slice(0, 5).map((d) => ({
        label: `${d.value} ${d.type} ${d.scenario} (${d.origin})`,
        to: `/threats?ip=${encodeURIComponent(d.value)}`,
      })),
      to: decisionsTo,
    });
  }

  const needle = value.toLowerCase();
  if (!(hosts instanceof Error)) {
    const matched = hosts.filter(
      (h) => h.domain.toLowerCase().includes(needle) || (h.target_group?.name ?? '').toLowerCase().includes(needle),
    );
    if (kind === 'domain' || kind === 'text') {
      sections.push({
        title: 'Hosts',
        window: 'all hosts',
        total: matched.length,
        items: matched.slice(0, 5).map((h) => ({ label: h.domain, to: `/hosts/${h.id}/security` })),
        to: `/hosts?q=${enc}`,
      });
    }
    // A domain that is a host: link Logs by host_id too.
    const exact = hosts.find((h) => h.domain.toLowerCase() === needle);
    if (exact && !(logs instanceof Error)) {
      sections.push({
        title: `Logs for ${exact.domain}`,
        window: 'last 24 h',
        total: null,
        items: [],
        to: `/logs?host_id=${exact.id}&range=24h`,
      });
    }
  }

  if (logs instanceof Error) {
    sections.push({ title: 'Logs', window: 'last 24 h', total: null, items: [], to: logsTo, error: logs.message });
  } else {
    sections.push({
      title: 'Logs',
      window: 'last 24 h',
      total: logs.total_count,
      items: logs.entries.slice(0, 5).map((e) => ({
        label: `${e.timestamp.slice(11, 19)} ${e.source} ${e.host_domain ?? ''} ${e.method ?? ''} ${e.path ?? e.message ?? ''} ${e.status ?? ''}`.trim(),
        to: logsTo,
      })),
      to: logsTo,
    });
  }

  if (!(whitelist instanceof Error) && kind !== 'scenario') {
    const matched = whitelist.entries.filter((w) => w.value.toLowerCase().includes(needle) || w.reason.toLowerCase().includes(needle));
    sections.push({
      title: 'Whitelist',
      window: 'all entries',
      total: matched.length,
      items: matched.slice(0, 5).map((w) => ({ label: `${w.value} (${w.reason || 'no reason'})`, to: `/security?tab=whitelist&ip=${encodeURIComponent(w.value)}` })),
      to: `/security?tab=whitelist&ip=${enc}`,
    });
  }

  if (!(collections instanceof Error) && (kind === 'scenario' || kind === 'text')) {
    const names = collections.flatMap((c) => (c.scenarios ?? []).map((s) => ({ s, c: c.name })));
    const matched = names.filter((n) => n.s.toLowerCase().includes(needle));
    sections.push({
      title: 'Scenarios',
      window: 'installed collections',
      total: matched.length,
      items: matched.slice(0, 5).map((n) => ({ label: `${n.s} (${n.c})`, to: `/security?tab=scenarios&q=${encodeURIComponent(n.s)}` })),
      to: `/security?tab=scenarios&q=${enc}`,
    });
  }

  if (!(appsec instanceof Error)) {
    const hits: { label: string; to: string }[] = [];
    if (kind === 'ip') {
      for (const ip of appsec.top_ips) if (ip.ip.toLowerCase().includes(needle)) hits.push({ label: `${ip.ip}: ${ip.count} hits`, to: '/appsec?range=24h' });
    } else if (kind === 'domain') {
      for (const p of appsec.top_paths) if ((p.host ?? '').toLowerCase().includes(needle)) hits.push({ label: `${p.host} ${p.path}: ${p.count}`, to: '/appsec?range=24h' });
    } else {
      for (const r of appsec.top_rules) if (r.rule.toLowerCase().includes(needle) || (r.message ?? '').toLowerCase().includes(needle)) hits.push({ label: `${r.rule} ${r.message ?? ''}: ${r.count}`, to: '/appsec?range=24h' });
    }
    sections.push({ title: 'WAF alerts (AppSec)', window: 'last 24 h, top lists', total: hits.length, items: hits.slice(0, 5), to: '/appsec?range=24h' });
  }
  return sections;
}

export function GlobalSearch() {
  const [text, setText] = useState('');
  const [open, setOpen] = useState(false);
  const [busy, setBusy] = useState(false);
  const [kind, setKind] = useState<SearchKind>('text');
  const [sections, setSections] = useState<Section[] | null>(null);
  const inputRef = useRef<HTMLInputElement>(null);
  const abortRef = useRef<AbortController | null>(null);
  const idleRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const navigate = useNavigate();

  const cancel = useCallback(() => {
    abortRef.current?.abort();
    abortRef.current = null;
    if (idleRef.current) clearTimeout(idleRef.current);
    idleRef.current = null;
  }, []);

  const run = useCallback(
    async (raw: string) => {
      cancel();
      const c = classifySearch(raw);
      if (c.value.length < MIN_CHARS) return;
      const ac = new AbortController();
      abortRef.current = ac;
      setKind(c.kind);
      setBusy(true);
      setOpen(true);
      try {
        const out = await runSearch(c.kind, c.value, ac.signal);
        if (!ac.signal.aborted) setSections(out);
      } finally {
        if (abortRef.current === ac) {
          abortRef.current = null;
          setBusy(false);
        }
      }
    },
    [cancel],
  );

  // Typing: abort any in-flight search; schedule one after 500 ms idle
  // with at least 3 characters. Never one request per keystroke.
  const onChange = (v: string) => {
    setText(v);
    cancel();
    if (v.trim().length >= MIN_CHARS) idleRef.current = setTimeout(() => run(v), IDLE_MS);
  };

  // "/" focuses the input (outside other inputs), Esc closes.
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      const target = e.target as HTMLElement | null;
      const typing = target && (target.tagName === 'INPUT' || target.tagName === 'TEXTAREA' || target.tagName === 'SELECT' || target.isContentEditable);
      if (e.key === '/' && !typing) {
        e.preventDefault();
        inputRef.current?.focus();
      } else if (e.key === 'Escape' && open) {
        setOpen(false);
        cancel();
      }
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [open, cancel]);

  const go = (to: string) => {
    setOpen(false);
    cancel();
    navigate(to);
  };

  return (
    <div className="relative hidden md:block">
      <div className="flex items-center gap-1 px-2 py-1 rounded border border-slate-700 bg-slate-950/60 focus-within:border-sky-700">
        <Search className="w-4 h-4 text-slate-500" />
        <input
          ref={inputRef}
          type="text"
          value={text}
          onChange={(e) => onChange(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === 'Enter') run(text);
          }}
          onFocus={() => sections && setOpen(true)}
          placeholder="IP, domain, scenario... ( / )"
          className="bg-transparent text-sm outline-none w-56 placeholder:text-slate-600"
          aria-label="Global search"
        />
        {text && (
          <button type="button" onClick={() => { setText(''); setSections(null); setOpen(false); cancel(); }} aria-label="Clear search">
            <X className="w-3.5 h-3.5 text-slate-500 hover:text-slate-300" />
          </button>
        )}
      </div>
      {open && (
        <div className="absolute right-0 mt-1 w-[34rem] max-h-[70vh] overflow-auto rounded-lg border border-slate-700 bg-slate-900 shadow-xl z-40 text-sm">
          <div className="px-3 py-2 border-b border-slate-800 text-xs text-slate-400 flex justify-between">
            <span>
              {busy ? 'searching' : 'where it appears'}: <span className="text-slate-200">{kindLabel(kind)}</span>
            </span>
            <span>Esc closes</span>
          </div>
          {sections?.length === 0 && !busy && <div className="px-3 py-3 text-slate-500">nothing found</div>}
          {sections?.map((s) => (
            <div key={s.title} className="px-3 py-2 border-b border-slate-800 last:border-0">
              <div className="flex items-center justify-between">
                <button type="button" onClick={() => go(s.to)} className="text-sky-400 hover:underline font-medium">
                  {s.title}
                </button>
                <span className="text-xs text-slate-500">
                  {s.window}
                  {s.total !== null ? ` - ${s.total.toLocaleString()} total` : ''}
                  {s.error ? ` - ${s.error}` : ''}
                </span>
              </div>
              {s.items.length > 0 && (
                <ul className="mt-1 space-y-0.5">
                  {s.items.map((it) => (
                    <li key={it.to + it.label} className="truncate">
                      <Link to={it.to} onClick={() => { setOpen(false); cancel(); }} className="font-mono text-xs text-slate-300 hover:text-sky-300">
                        {it.label}
                      </Link>
                    </li>
                  ))}
                </ul>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
