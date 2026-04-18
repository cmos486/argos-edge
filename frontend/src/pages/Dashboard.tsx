import { useEffect, useState } from 'react';
import { Activity, Server } from 'lucide-react';
import {
  ApiError,
  CaddyStatus,
  HealthStatus,
  api,
} from '../api/client';

type Loadable<T> =
  | { state: 'loading' }
  | { state: 'ok'; value: T }
  | { state: 'error'; error: string };

function initial<T>(): Loadable<T> {
  return { state: 'loading' };
}

export default function Dashboard() {
  const [health, setHealth] = useState<Loadable<HealthStatus>>(initial);
  const [caddy, setCaddy] = useState<Loadable<CaddyStatus>>(initial);

  useEffect(() => {
    let cancelled = false;

    Promise.allSettled([api.health(), api.caddyStatus()]).then((results) => {
      if (cancelled) return;
      const [h, c] = results;
      setHealth(toLoadable<HealthStatus>(h));
      setCaddy(toLoadable<CaddyStatus>(c));
    });

    return () => {
      cancelled = true;
    };
  }, []);

  return (
    <div className="p-6 max-w-5xl mx-auto">
      <h1 className="text-2xl font-semibold mb-6">Dashboard</h1>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <StatusCard
          title="Panel API"
          icon={<Activity className="w-5 h-5" />}
          status={health}
          render={(v) => (
            <div className="text-sm text-slate-300">response: {v.detail}</div>
          )}
        />
        <StatusCard
          title="Caddy Admin"
          icon={<Server className="w-5 h-5" />}
          status={caddy}
          ok={(v) => v.ok}
          render={(v) => (
            <div className="text-sm text-slate-300 space-y-1">
              <div>address: {v.address}</div>
              <div>http app loaded: {v.has_http ? 'yes' : 'no'}</div>
              {v.error && (
                <div className="text-red-400 break-all">error: {v.error}</div>
              )}
            </div>
          )}
        />
      </div>
    </div>
  );
}

function toLoadable<T>(r: PromiseSettledResult<T>): Loadable<T> {
  if (r.status === 'fulfilled') {
    return { state: 'ok', value: r.value };
  }
  const reason = r.reason;
  const msg =
    reason instanceof ApiError
      ? reason.message
      : reason instanceof Error
        ? reason.message
        : 'request failed';
  return { state: 'error', error: msg };
}

interface StatusCardProps<T> {
  title: string;
  icon: React.ReactNode;
  status: Loadable<T>;
  render: (value: T) => React.ReactNode;
  ok?: (value: T) => boolean;
}

function StatusCard<T>({ title, icon, status, render, ok }: StatusCardProps<T>) {
  let pill: { label: string; cls: string };
  if (status.state === 'loading') {
    pill = { label: 'checking', cls: 'bg-slate-700 text-slate-200' };
  } else if (status.state === 'error') {
    pill = { label: 'KO', cls: 'bg-red-900 text-red-200' };
  } else {
    const good = ok ? ok(status.value) : true;
    pill = good
      ? { label: 'OK', cls: 'bg-emerald-900 text-emerald-200' }
      : { label: 'KO', cls: 'bg-red-900 text-red-200' };
  }

  return (
    <div className="bg-slate-900 border border-slate-800 rounded-lg p-4">
      <div className="flex items-center justify-between mb-3">
        <div className="flex items-center gap-2 text-slate-200 font-medium">
          {icon}
          <span>{title}</span>
        </div>
        <span className={`px-2 py-0.5 text-xs rounded ${pill.cls}`}>
          {pill.label}
        </span>
      </div>
      {status.state === 'loading' && (
        <div className="text-sm text-slate-500">loading...</div>
      )}
      {status.state === 'error' && (
        <div className="text-sm text-red-400">{status.error}</div>
      )}
      {status.state === 'ok' && render(status.value)}
    </div>
  );
}
