// TOTPDisable is the modal body for turning 2FA off from the System
// page. The backend requires both the current password and a code
// (TOTP 6-digit OR a recovery code in its place). The recovery path
// is offered as a fallback link so a user whose authenticator is
// lost can still disable without having to run the CLI break-glass.

import { FormEvent, useState } from 'react';
import { ShieldOff } from 'lucide-react';
import { ApiError, api } from '../api/client';

interface Props {
  onDone: () => void;   // disable succeeded
  onCancel: () => void; // user cancelled; close modal
}

export default function TOTPDisable({ onDone, onCancel }: Props) {
  const [password, setPassword] = useState('');
  const [code, setCode] = useState('');
  const [useRecovery, setUseRecovery] = useState(false);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  async function onSubmit(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    setBusy(true);
    setErr(null);
    try {
      await api.totpDisable(password, code);
      onDone();
    } catch (e2) {
      setErr(e2 instanceof ApiError ? e2.message : 'disable failed');
    } finally {
      setBusy(false);
    }
  }

  // Reset the code input and any stale error when the user toggles
  // between TOTP-code and recovery-code modes: the format + placeholder
  // differ, so preserving the half-typed value is more confusing than
  // helpful.
  function toggleRecovery() {
    setUseRecovery((v) => !v);
    setCode('');
    setErr(null);
  }

  const codeValid = useRecovery
    ? code.replace(/\s/g, '').length >= 8
    : /^\d{6}$/.test(code);

  return (
    <form onSubmit={onSubmit} className="space-y-3">
      <div className="flex items-start gap-2 bg-red-950/40 border border-red-900 rounded px-3 py-2 text-sm text-red-200">
        <ShieldOff className="w-5 h-5 mt-0.5 flex-shrink-0" />
        <span>
          Disabling 2FA removes both the TOTP secret and all recovery codes.
          You will only need your password to sign in until you re-enable it.
        </span>
      </div>

      <label className="block text-sm text-slate-300">
        <span className="mb-1 block">Password</span>
        <input
          type="password"
          autoComplete="current-password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          required
          className="w-full px-3 py-2 rounded bg-slate-800 border border-slate-700 focus:outline-none focus:border-sky-500"
        />
      </label>

      <label className="block text-sm text-slate-300">
        <span className="mb-1 block">
          {useRecovery ? 'Recovery code' : '6-digit code from your app'}
        </span>
        {useRecovery ? (
          <input
            type="text"
            autoComplete="off"
            value={code}
            onChange={(e) => setCode(e.target.value.toLowerCase())}
            placeholder="xxxx-xxxx"
            required
            className="w-full px-3 py-2 rounded bg-slate-800 border border-slate-700 font-mono focus:outline-none focus:border-sky-500"
          />
        ) : (
          <input
            type="text"
            inputMode="numeric"
            autoComplete="one-time-code"
            pattern="[0-9]{6}"
            maxLength={6}
            value={code}
            onChange={(e) => setCode(e.target.value.replace(/\D/g, ''))}
            placeholder="000000"
            required
            className="w-full px-3 py-2 rounded bg-slate-800 border border-slate-700 font-mono text-center tracking-[0.4em] focus:outline-none focus:border-sky-500"
          />
        )}
      </label>

      <button
        type="button"
        onClick={toggleRecovery}
        className="text-xs text-sky-400 hover:underline"
      >
        {useRecovery
          ? 'Use authenticator code instead'
          : 'Use recovery code instead'}
      </button>

      {err && (
        <div className="text-sm text-red-400 bg-red-950/40 border border-red-900 rounded px-3 py-2">
          {err}
        </div>
      )}

      <div className="flex gap-2 justify-end pt-1">
        <button
          type="button"
          onClick={onCancel}
          className="px-3 py-1.5 text-sm rounded border border-slate-700 hover:bg-slate-800"
        >
          Cancel
        </button>
        <button
          type="submit"
          disabled={busy || !password || !codeValid}
          className="px-3 py-1.5 text-sm rounded bg-red-600 hover:bg-red-500 disabled:bg-slate-700 font-medium"
        >
          {busy ? 'disabling...' : 'Disable 2FA'}
        </button>
      </div>
    </form>
  );
}
