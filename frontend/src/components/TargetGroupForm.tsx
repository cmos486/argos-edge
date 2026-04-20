import { ChangeEvent, useState } from 'react';
import { ChevronDown, ChevronRight } from 'lucide-react';
import {
  Algorithm,
  HealthCheckMethod,
  Protocol,
  TargetInput,
} from '../api/client';
import { TargetGroupFormValue } from './targetGroupFormValue';

interface Props {
  value: TargetGroupFormValue;
  onChange: (next: TargetGroupFormValue) => void;
  showName?: boolean;
  requireTargets?: boolean;
}

export default function TargetGroupForm({ value, onChange, showName = true, requireTargets = false }: Props) {
  const [advancedOpen, setAdvancedOpen] = useState(value.health_check_enabled === true);

  function patch<K extends keyof TargetGroupFormValue>(key: K, v: TargetGroupFormValue[K]) {
    onChange({ ...value, [key]: v });
  }

  return (
    <div className="space-y-3 text-sm">
      {showName && (
        <Row label="Name">
          <input
            type="text"
            required
            value={value.name}
            onChange={(e) => patch('name', e.target.value)}
            placeholder="web-app-pool"
            className={inputClass + ' font-mono'}
          />
        </Row>
      )}

      <div className="grid grid-cols-2 gap-3">
        <Row label="Protocol">
          <select
            value={value.protocol}
            onChange={(e) => patch('protocol', e.target.value as Protocol)}
            className={inputClass}
          >
            <option value="http">http</option>
            <option value="https">https</option>
          </select>
        </Row>
        <Row label="Algorithm">
          <select
            value={value.algorithm}
            onChange={(e) => patch('algorithm', e.target.value as Algorithm)}
            className={inputClass}
          >
            <option value="round_robin">round_robin</option>
            <option value="least_conn">least_conn</option>
            <option value="ip_hash">ip_hash</option>
            <option value="random">random</option>
          </select>
        </Row>
      </div>

      {value.protocol === 'https' && (
        <label className="flex items-center gap-2 text-slate-200">
          <input
            type="checkbox"
            checked={value.verify_tls ?? true}
            onChange={(e) => patch('verify_tls', e.target.checked)}
            className="w-4 h-4 accent-sky-600"
          />
          <span>Verify upstream TLS certificate</span>
        </label>
      )}

      <button
        type="button"
        onClick={() => setAdvancedOpen((v) => !v)}
        className="flex items-center gap-1 text-slate-400 hover:text-slate-200 text-xs uppercase tracking-wide pt-1"
      >
        {advancedOpen ? <ChevronDown className="w-3 h-3" /> : <ChevronRight className="w-3 h-3" />}
        Advanced: health check
      </button>

      {advancedOpen && (
        <div className="pl-4 border-l border-slate-800 space-y-3">
          <label className="flex items-center gap-2 text-slate-200">
            <input
              type="checkbox"
              checked={value.health_check_enabled ?? false}
              onChange={(e) => patch('health_check_enabled', e.target.checked)}
              className="w-4 h-4 accent-sky-600"
            />
            <span>Enable active health checks</span>
          </label>

          {value.health_check_enabled && (
            <div className="space-y-3">
              <Row label="Path">
                <input
                  type="text"
                  value={value.health_check_path ?? '/'}
                  onChange={(e) => patch('health_check_path', e.target.value)}
                  placeholder="/healthz"
                  className={inputClass + ' font-mono'}
                />
              </Row>
              <Row label="Method">
                <select
                  value={value.health_check_method ?? 'GET'}
                  onChange={(e) => patch('health_check_method', e.target.value as HealthCheckMethod)}
                  className={inputClass}
                >
                  <option value="GET">GET</option>
                  <option value="HEAD">HEAD</option>
                  <option value="POST">POST</option>
                </select>
              </Row>
              <Row label="Expect status">
                <input
                  type="text"
                  value={value.health_check_expect_status ?? '200'}
                  onChange={(e) => patch('health_check_expect_status', e.target.value)}
                  placeholder="200"
                  className={inputClass + ' font-mono'}
                />
                <p className="mt-1 text-xs text-slate-500">
                  Examples: <code>200</code>, <code>200,301,302</code>,{' '}
                  <code>200-299</code>, <code>200-204,301</code>.
                </p>
              </Row>
              <div className="grid grid-cols-2 gap-3">
                <Row label="Interval (s)">
                  <NumberInput
                    min={5}
                    max={300}
                    value={value.health_check_interval_seconds ?? 30}
                    onChange={(v) => patch('health_check_interval_seconds', v)}
                  />
                </Row>
                <Row label="Timeout (s)">
                  <NumberInput
                    min={1}
                    max={30}
                    value={value.health_check_timeout_seconds ?? 5}
                    onChange={(v) => patch('health_check_timeout_seconds', v)}
                  />
                </Row>
                <Row label="Fails -> unhealthy">
                  <NumberInput
                    min={1}
                    max={10}
                    value={value.health_check_fails_to_unhealthy ?? 2}
                    onChange={(v) => patch('health_check_fails_to_unhealthy', v)}
                  />
                </Row>
                <Row label="Passes -> healthy">
                  <NumberInput
                    min={1}
                    max={10}
                    value={value.health_check_passes_to_healthy ?? 2}
                    onChange={(v) => patch('health_check_passes_to_healthy', v)}
                  />
                </Row>
              </div>
            </div>
          )}
        </div>
      )}

      {requireTargets && <TargetsEditor value={value} onChange={onChange} />}
    </div>
  );
}

function TargetsEditor({ value, onChange }: Props) {
  const targets = value.targets ?? [];

  function update(i: number, patch: Partial<TargetInput>) {
    const next = targets.slice();
    next[i] = { ...(next[i] as TargetInput), ...patch };
    onChange({ ...value, targets: next });
  }
  function add() {
    onChange({
      ...value,
      targets: [...targets, { host: '', port: 80, weight: 1, enabled: true }],
    });
  }
  function remove(i: number) {
    onChange({ ...value, targets: targets.filter((_, j) => j !== i) });
  }

  return (
    <div className="pt-2">
      <div className="flex items-center justify-between mb-1">
        <span className="text-slate-300 uppercase text-xs tracking-wide">Initial targets</span>
        <button
          type="button"
          onClick={add}
          className="text-xs px-2 py-0.5 rounded border border-slate-700 hover:bg-slate-800"
        >
          + Add
        </button>
      </div>
      {targets.length === 0 && (
        <p className="text-xs text-slate-500">
          Add at least one target (host + port) so caddy has something to proxy to.
        </p>
      )}
      {targets.length > 0 && (
        <div className="flex items-center gap-2 mb-1 text-[10px] text-slate-500 uppercase tracking-wide">
          <span className="flex-1">Host</span>
          <span className="w-24">Port</span>
          <span className="w-16">Weight</span>
          <span className="w-6" aria-hidden="true" />
        </div>
      )}
      {targets.map((t, i) => (
        <div key={i} className="flex items-center gap-2 mb-2">
          <input
            type="text"
            placeholder="host or ip"
            required
            value={t.host}
            onChange={(e) => update(i, { host: e.target.value })}
            className={inputClass + ' font-mono flex-1 min-w-[160px]'}
          />
          <input
            type="number"
            min={1}
            max={65535}
            placeholder="port"
            required
            value={t.port || ''}
            onChange={(e) => update(i, { port: parseInt(e.target.value, 10) })}
            className={inputClass + ' font-mono w-24'}
          />
          <input
            type="number"
            min={1}
            max={256}
            value={t.weight ?? 1}
            onChange={(e) => update(i, { weight: parseInt(e.target.value, 10) })}
            className={inputClass + ' font-mono w-16'}
            title="weight"
          />
          <button
            type="button"
            onClick={() => remove(i)}
            className="text-xs px-2 py-1 rounded border border-slate-700 text-red-400 hover:bg-slate-800 w-6"
            title="remove target"
            aria-label="remove target"
          >
            x
          </button>
        </div>
      ))}
    </div>
  );
}

function Row({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div>
      <label className="block text-slate-300 mb-1">{label}</label>
      {children}
    </div>
  );
}

function NumberInput({
  value,
  onChange,
  min,
  max,
}: {
  value: number;
  onChange: (v: number) => void;
  min?: number;
  max?: number;
}) {
  function handle(e: ChangeEvent<HTMLInputElement>) {
    const n = parseInt(e.target.value, 10);
    if (!Number.isFinite(n)) return;
    onChange(n);
  }
  return (
    <input
      type="number"
      min={min}
      max={max}
      value={value}
      onChange={handle}
      className={inputClass + ' font-mono'}
    />
  );
}

const inputClass =
  'w-full px-3 py-2 rounded bg-slate-800 border border-slate-700 focus:outline-none focus:border-sky-500';
