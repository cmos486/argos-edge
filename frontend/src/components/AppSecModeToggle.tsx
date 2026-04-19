// AppSecModeToggle is the modal body for changing the WAF mode.
// Mirrors the TOTPDisable pattern: three radio options + a password
// gate so a temporarily-unattended session can't flip a high-blast-
// radius setting. Per the spec, the password check is done server-
// side only AFTER the mode mutation; we re-verify here by calling
// /api/auth/login with the current username, fail fast on bad
// creds, and only then issue the PATCH. This keeps the PATCH
// endpoint simple (no password field on /appsec/mode) at the cost
// of one extra round-trip.

import { FormEvent, useState } from 'react';
import { ShieldAlert, Shield, ShieldOff, AlertTriangle } from 'lucide-react';
import {
  ApiError,
  AppSecMode,
  api,
  isTOTPPending,
} from '../api/client';

interface Props {
  current: AppSecMode;
  username: string;
  onDone: (next: AppSecMode) => void;
  onCancel: () => void;
}

// MODE_META drives the radio list. Keeping it as data instead of
// three copy-pasted JSX blocks makes the "add another mode" change
// a one-liner and guarantees the blurb stays in sync with the icon.
const MODE_META: Array<{
  value: AppSecMode;
  label: string;
  icon: typeof Shield;
  color: string;
  blurb: string;
}> = [
  {
    value: 'detect',
    label: 'Detect',
    icon: Shield,
    color: 'text-emerald-400',
    blurb:
      'Rules evaluated; matches logged and counted in metrics but requests pass through. Safe to run long-term while tuning.',
  },
  {
    value: 'block',
    label: 'Block',
    icon: ShieldAlert,
    color: 'text-red-400',
    blurb:
      'Matching requests return 403 before reaching the backend. Expect some false positives; monitor /appsec for a day after enabling.',
  },
  {
    value: 'disabled',
    label: 'Disabled',
    icon: ShieldOff,
    color: 'text-slate-400',
    blurb:
      'AppSec round-trip is skipped entirely. Zero overhead per request, zero protection, zero metrics collected.',
  },
];

export default function AppSecModeToggle({
  current,
  username,
  onDone,
  onCancel,
}: Props) {
  const [selected, setSelected] = useState<AppSecMode>(current);
  const [password, setPassword] = useState('');
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  const dirty = selected !== current;

  async function onSubmit(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    if (!dirty) {
      onCancel();
      return;
    }
    setBusy(true);
    setErr(null);
    try {
      // Re-verify the password. We swallow the response: the session
      // we already have stays valid whether the verify succeeds or
      // not; a new cookie just lands on top. If the user has TOTP
      // enabled we refuse to proceed -- switching AppSec mode is not
      // worth routing through another challenge flow, and the
      // password-only re-auth is already strong enough.
      const res = await api.login(username, password);
      if (isTOTPPending(res)) {
        setErr('2FA is enabled; sign out and back in to flip AppSec mode');
        return;
      }
      await api.appsecSetMode(selected);
      onDone(selected);
    } catch (e2) {
      setErr(e2 instanceof ApiError ? e2.message : 'mode change failed');
    } finally {
      setBusy(false);
    }
  }

  return (
    <form onSubmit={onSubmit} className="space-y-4">
      <div className="flex items-start gap-2 bg-amber-950/40 border border-amber-900 rounded px-3 py-2 text-sm text-amber-200">
        <AlertTriangle className="w-5 h-5 mt-0.5 flex-shrink-0" />
        <span>
          Changing the WAF mode affects live traffic immediately. Caddy is
          reloaded via its admin API; no container restart.
        </span>
      </div>

      <div className="space-y-2">
        {MODE_META.map((m) => {
          const Icon = m.icon;
          const selectedRow = selected === m.value;
          return (
            <label
              key={m.value}
              className={`block rounded border px-3 py-2 cursor-pointer ${
                selectedRow
                  ? 'border-sky-500 bg-slate-800'
                  : 'border-slate-700 hover:bg-slate-800/50'
              }`}
            >
              <div className="flex items-center gap-2">
                <input
                  type="radio"
                  name="appsec-mode"
                  value={m.value}
                  checked={selectedRow}
                  onChange={() => setSelected(m.value)}
                  className="accent-sky-500"
                />
                <Icon className={`w-4 h-4 ${m.color}`} />
                <span className="font-medium">{m.label}</span>
                {current === m.value && (
                  <span className="ml-1 text-xs text-slate-400">(current)</span>
                )}
              </div>
              <div className="text-xs text-slate-400 mt-1 pl-6">{m.blurb}</div>
            </label>
          );
        })}
      </div>

      <label className="block text-sm text-slate-300">
        <span className="mb-1 block">Confirm with your password</span>
        <input
          type="password"
          autoComplete="current-password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          required
          className="w-full px-3 py-2 rounded bg-slate-800 border border-slate-700 focus:outline-none focus:border-sky-500"
        />
      </label>

      {err && (
        <div className="text-sm text-red-400 bg-red-950/40 border border-red-900 rounded px-3 py-2">
          {err}
        </div>
      )}

      <div className="flex gap-2 justify-end">
        <button
          type="button"
          onClick={onCancel}
          className="px-3 py-1.5 text-sm rounded border border-slate-700 hover:bg-slate-800"
        >
          Cancel
        </button>
        <button
          type="submit"
          disabled={busy || !dirty || !password}
          className="px-3 py-1.5 text-sm rounded bg-sky-600 hover:bg-sky-500 disabled:bg-slate-700 font-medium"
        >
          {busy ? 'applying...' : 'Change mode'}
        </button>
      </div>
    </form>
  );
}
