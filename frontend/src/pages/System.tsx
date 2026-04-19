import { useCallback, useEffect, useState } from 'react';
import {
  Activity,
  AlertTriangle,
  Cpu,
  Database,
  HardDrive,
  Info,
  KeyRound,
  Pause,
  Play,
  ServerCog,
  Shield,
  ShieldCheck,
  ShieldOff,
  Timer,
  Workflow,
} from 'lucide-react';
import { ApiError, SystemHealth, TOTPStatus, api } from '../api/client';
import Modal from '../components/Modal';
import SSOSection from '../components/SSOSection';
import TOTPSetup from '../components/TOTPSetup';
import TOTPDisable from '../components/TOTPDisable';

const REFRESH_MS = 10_000;

export default function System() {
  const [data, setData] = useState<SystemHealth | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [paused, setPaused] = useState(false);

  // 2FA state is loaded on mount and refreshed after every
  // enable/disable. It has its own loader (not on the SystemHealth
  // timer) because its cadence is user-triggered, not clockwork.
  const [totp, setTotp] = useState<TOTPStatus | null>(null);
  const [totpErr, setTotpErr] = useState<string | null>(null);
  const [showSetup, setShowSetup] = useState(false);
  const [showDisable, setShowDisable] = useState(false);

  const loadTOTP = useCallback(async () => {
    try {
      const s = await api.totpStatus();
      setTotp(s);
      setTotpErr(null);
    } catch (e) {
      setTotpErr(e instanceof ApiError ? e.message : 'load failed');
    }
  }, []);

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

  useEffect(() => {
    void loadTOTP();
  }, [loadTOTP]);

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

      <TwoFactorSection
        status={totp}
        err={totpErr}
        onEnable={() => setShowSetup(true)}
        onDisable={() => setShowDisable(true)}
      />

      <SSOSection />

      <Modal
        open={showSetup}
        title="Enable two-factor authentication"
        onClose={() => setShowSetup(false)}
      >
        <TOTPSetup
          onCancel={() => setShowSetup(false)}
          onDone={() => {
            setShowSetup(false);
            void loadTOTP();
          }}
        />
      </Modal>

      <Modal
        open={showDisable}
        title="Disable two-factor authentication"
        onClose={() => setShowDisable(false)}
      >
        <TOTPDisable
          onCancel={() => setShowDisable(false)}
          onDone={() => {
            setShowDisable(false);
            void loadTOTP();
          }}
        />
      </Modal>

      <div className="pt-4 text-xs text-slate-500 border-t border-slate-800 mt-6">
        IP geolocation by{' '}
        <a
          href="https://db-ip.com"
          target="_blank"
          rel="noreferrer"
          className="text-sky-400 hover:underline"
        >
          DB-IP
        </a>
        {' '}(CC-BY 4.0)
      </div>
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

function fmtEnabledAt(iso?: string): string {
  if (!iso) return '';
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  // "Enabled since YYYY-MM-DD" per spec; keep the local tz so it reads
  // naturally to the admin running this homelab panel.
  const y = d.getFullYear();
  const m = String(d.getMonth() + 1).padStart(2, '0');
  const day = String(d.getDate()).padStart(2, '0');
  return `${y}-${m}-${day}`;
}

// TwoFactorSection renders the 2FA status card. Three visual states:
//   loading / error:   one-line placeholder
//   enabled=false:     big "Enable 2FA" CTA button
//   enabled=true:      enabled-at date, remaining recovery codes,
//                      optional amber warning when <=3 left, and a
//                      "Disable" button that opens the disable modal
function TwoFactorSection({
  status,
  err,
  onEnable,
  onDisable,
}: {
  status: TOTPStatus | null;
  err: string | null;
  onEnable: () => void;
  onDisable: () => void;
}) {
  return (
    <section className="bg-slate-900 border border-slate-800 rounded-lg p-4">
      <div className="flex items-center gap-2 text-slate-300 mb-3">
        <Shield className="w-4 h-4" />
        <span className="font-medium">Two-factor authentication</span>
      </div>

      {err && (
        <div className="text-sm text-red-400 bg-red-950/40 border border-red-900 rounded px-3 py-2">
          {err}
        </div>
      )}

      {!status ? (
        <div className="text-sm text-slate-400">loading...</div>
      ) : status.enabled ? (
        <div className="space-y-3">
          <div className="flex items-center gap-2 text-sm text-emerald-300">
            <ShieldCheck className="w-4 h-4" />
            <span>
              Enabled{status.enabled_at ? ` since ${fmtEnabledAt(status.enabled_at)}` : ''}
            </span>
          </div>

          <div className="flex items-center gap-2 text-sm text-slate-300">
            <KeyRound className="w-4 h-4 text-slate-400" />
            <span>
              Recovery codes remaining:{' '}
              <span className="font-mono">{status.recovery_codes_remaining}</span>
            </span>
          </div>

          {status.recovery_codes_remaining <= 3 && (
            <div className="flex items-start gap-2 bg-amber-950/40 border border-amber-900 rounded px-3 py-2 text-sm text-amber-200">
              <AlertTriangle className="w-4 h-4 mt-0.5 flex-shrink-0" />
              <span>
                You are low on recovery codes. Regenerating is not yet available
                in the UI -- disable and re-enable 2FA to get a fresh batch.
              </span>
            </div>
          )}

          <div className="pt-1">
            <button
              type="button"
              onClick={onDisable}
              className="inline-flex items-center gap-1 px-3 py-1.5 text-sm rounded border border-red-900 text-red-300 hover:bg-red-950/50"
            >
              <ShieldOff className="w-3.5 h-3.5" /> Disable
            </button>
          </div>
        </div>
      ) : (
        <div className="space-y-3">
          <p className="text-sm text-slate-400">
            Require a one-time code from an authenticator app on every sign-in.
            {status.setup_pending && (
              <span className="block mt-1 text-amber-300">
                A previous setup was started but never confirmed. Starting a
                new setup will overwrite it.
              </span>
            )}
          </p>
          <button
            type="button"
            onClick={onEnable}
            className="inline-flex items-center gap-1 px-3 py-1.5 text-sm rounded bg-sky-600 hover:bg-sky-500 font-medium"
          >
            <ShieldCheck className="w-3.5 h-3.5" /> Enable 2FA
          </button>
        </div>
      )}
    </section>
  );
}
