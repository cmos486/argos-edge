import { useEffect, useState } from 'react';
import {
  Activity,
  Cpu,
  Database,
  HardDrive,
  Info,
  Pause,
  Play,
  ServerCog,
  Shield,
  Timer,
  Workflow,
} from 'lucide-react';
import { ApiError, SystemHealth, api } from '../api/client';

const REFRESH_MS = 10_000;

export default function System() {
  const [data, setData] = useState<SystemHealth | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [paused, setPaused] = useState(false);

  useEffect(() => {
    let cancelled = false;
    async function load() {
      try {
        const d = await api.systemHealth();
        if (!cancelled) {
          setData(d);
          setErr(null);
        }
      } catch (e) {
        if (!cancelled) setErr(e instanceof ApiError ? e.message : 'load failed');
      }
    }
    load();
    if (paused) return;
    const id = setInterval(load, REFRESH_MS);
    return () => {
      cancelled = true;
      clearInterval(id);
    };
  }, [paused]);

  return (
    <div className="p-6 max-w-5xl mx-auto space-y-4">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-semibold flex items-center gap-2">
          <ServerCog className="w-6 h-6 text-sky-400" /> System
        </h1>
        <button
          type="button"
          onClick={() => setPaused((p) => !p)}
          className="flex items-center gap-1 px-2 py-1 rounded border border-slate-700 hover:bg-slate-800 text-xs"
        >
          {paused ? <Play className="w-3 h-3" /> : <Pause className="w-3 h-3" />}
          <span>{paused ? 'paused' : 'auto 10s'}</span>
        </button>
      </div>

      {err && (
        <div className="mb-4 px-3 py-2 rounded bg-red-950/40 border border-red-900 text-sm text-red-300">
          {err}
        </div>
      )}

      {data && data.panel_mode === 'lan' && (
        <div className="flex items-start gap-2 px-3 py-2 rounded bg-amber-950/40 border border-amber-900 text-amber-200 text-sm">
          <Info className="w-4 h-4 mt-0.5 flex-shrink-0" />
          <span>
            Panel is served over HTTP on LAN. Browser Push and HTTPS-only features are
            disabled. To enable HTTPS, set <code className="font-mono text-xs">ARGOS_PANEL_MODE=behind_caddy</code>
            {' '}and <code className="font-mono text-xs">ARGOS_PANEL_DOMAIN=...</code> in <code>.env</code>.
          </span>
        </div>
      )}

      {!data ? (
        <div className="text-slate-400 text-sm">loading...</div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
          <Card title="Panel mode" icon={<Shield className="w-4 h-4" />}>
            <Row label="mode" value={<ModeBadge mode={data.panel_mode} />} />
            {data.panel_domain && <Row label="domain" value={<code className="font-mono">{data.panel_domain}</code>} />}
            <Row label="uptime" value={fmtUptime(data.uptime_seconds)} />
          </Card>

          <Card title="Memory" icon={<Cpu className="w-4 h-4" />}>
            <Row label="alloc" value={`${data.memory.alloc_mb} MiB`} />
            <Row label="sys" value={`${data.memory.sys_mb} MiB`} />
            <Row label="gc cycles" value={String(data.memory.num_gc)} />
          </Card>

          <Card title="Runtime" icon={<Activity className="w-4 h-4" />}>
            <Row label="goroutines" value={String(data.goroutines)} />
          </Card>

          <Card title="SQLite" icon={<Database className="w-4 h-4" />}>
            <Row label="db size" value={humanSize(data.db.size_bytes)} />
            <Row label="wal size" value={humanSize(data.db.wal_size_bytes)} />
            <Row label="connections" value={`${data.db.in_use_connections} in use / ${data.db.idle_connections} idle`} />
          </Card>

          <Card title="Workers" icon={<Workflow className="w-4 h-4" />}>
            <Row
              label="notif queue"
              value={`${data.workers.notification_queue_depth} / ${data.workers.notification_queue_cap}`}
            />
            <Row
              label="notif dropped"
              value={String(data.workers.notification_dropped_total)}
            />
          </Card>

          <Card title="Scheduler" icon={<Timer className="w-4 h-4" />}>
            <Row
              label="last backup"
              value={
                data.scheduler.last_backup_attempt
                  ? new Date(data.scheduler.last_backup_attempt).toLocaleString()
                  : '—'
              }
            />
            <Row label="status" value={<StatusBadge status={data.scheduler.last_backup_status} />} />
            {data.scheduler.last_backup_kind && (
              <Row label="kind" value={data.scheduler.last_backup_kind} />
            )}
          </Card>

          <Card title="Storage" icon={<HardDrive className="w-4 h-4" />}>
            <Row label="db+wal" value={humanSize(data.db.size_bytes + data.db.wal_size_bytes)} />
          </Card>
        </div>
      )}
    </div>
  );
}

function Card({
  title,
  icon,
  children,
}: {
  title: string;
  icon: React.ReactNode;
  children: React.ReactNode;
}) {
  return (
    <section className="bg-slate-900 border border-slate-800 rounded-lg p-4">
      <div className="flex items-center gap-2 text-slate-300 mb-3">
        {icon}
        <span className="font-medium">{title}</span>
      </div>
      <dl className="text-sm space-y-1">{children}</dl>
    </section>
  );
}

function Row({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div className="flex items-center justify-between py-1">
      <dt className="text-slate-400">{label}</dt>
      <dd className="font-mono">{value}</dd>
    </div>
  );
}

function ModeBadge({ mode }: { mode: 'lan' | 'behind_caddy' }) {
  const cls =
    mode === 'behind_caddy'
      ? 'bg-emerald-900 text-emerald-200'
      : 'bg-amber-900 text-amber-200';
  return <span className={`text-xs px-2 py-0.5 rounded ${cls}`}>{mode}</span>;
}

function StatusBadge({ status }: { status: string }) {
  const cls: Record<string, string> = {
    ok: 'bg-emerald-900 text-emerald-200',
    stale: 'bg-red-900 text-red-200',
    missing: 'bg-slate-800 text-slate-400',
  };
  return (
    <span className={`text-xs px-2 py-0.5 rounded ${cls[status] ?? 'bg-slate-800 text-slate-300'}`}>
      {status}
    </span>
  );
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

function fmtUptime(seconds: number): string {
  const d = Math.floor(seconds / 86400);
  const h = Math.floor((seconds % 86400) / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  if (d > 0) return `${d}d ${h}h`;
  if (h > 0) return `${h}h ${m}m`;
  return `${m}m ${seconds % 60}s`;
}
