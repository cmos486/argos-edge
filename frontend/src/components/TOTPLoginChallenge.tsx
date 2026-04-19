// TOTPLoginChallenge is the second step of login when the account has
// 2FA enabled: the password-only /auth/login response came back with
// {requires_totp: true, challenge_id}, and we now ask for a 6-digit
// code (or a recovery code on the fallback path).
//
// Auto-submit: the moment the user types 6 digits we fire /verify so
// they don't have to reach for Enter. Recovery codes are not
// auto-submitted because the length is user-facing ("xxxx-xxxx") and
// a paste-with-newline should not instantly commit it without review.
//
// Expiry timer: the backend's challenge TTL is 5 minutes. We run a
// local 1-second tick that mirrors it so the user sees when a code
// will be rejected as "challenge not found or expired".

import { FormEvent, useEffect, useRef, useState } from 'react';
import { ShieldCheck, KeyRound } from 'lucide-react';
import { ApiError, api } from '../api/client';

// CHALLENGE_TTL_SECONDS matches totp.DefaultChallengeTTL on the
// backend (5 min). If the backend ever lengthens it, this number
// becomes a lower-bound visualisation; the server still authoritative.
const CHALLENGE_TTL_SECONDS = 5 * 60;

interface Props {
  challengeId: string;
  onSuccess: () => void; // called after a successful verify/recovery
  onCancel: () => void;  // go back to the password form
}

export default function TOTPLoginChallenge({
  challengeId,
  onSuccess,
  onCancel,
}: Props) {
  const [code, setCode] = useState('');
  const [useRecovery, setUseRecovery] = useState(false);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  // Countdown: seconds left until the challenge expires client-side.
  // Refreshes every second; at zero we lock the form and invite the
  // user back to the password screen for a new challenge.
  const [remaining, setRemaining] = useState(CHALLENGE_TTL_SECONDS);
  useEffect(() => {
    const t = setInterval(() => {
      setRemaining((r) => (r > 0 ? r - 1 : 0));
    }, 1000);
    return () => clearInterval(t);
  }, [challengeId]);

  // submittedRef: guards against auto-submit firing twice when React
  // re-renders between the setState and the fetch landing (e.g. the
  // user pastes a code, auto-submit fires, then state churn would
  // try again before the await resolves).
  const submittedRef = useRef(false);

  async function submit(value: string) {
    if (submittedRef.current || busy) return;
    submittedRef.current = true;
    setBusy(true);
    setErr(null);
    try {
      if (useRecovery) {
        await api.totpRecovery(challengeId, value);
      } else {
        await api.totpVerify(challengeId, value);
      }
      onSuccess();
    } catch (e) {
      setErr(e instanceof ApiError ? e.message : 'verification failed');
      setCode('');
      submittedRef.current = false;
    } finally {
      setBusy(false);
    }
  }

  function onCodeChange(next: string) {
    if (useRecovery) {
      // Allow letters, digits, dashes, spaces. Lowercase to match the
      // canonical format the server normalises to. No auto-submit: see
      // header comment.
      setCode(next.toLowerCase().slice(0, 12));
      return;
    }
    const digits = next.replace(/\D/g, '').slice(0, 6);
    setCode(digits);
    if (digits.length === 6) {
      // Fire immediately when the 6th digit lands, without waiting for
      // the user to press Enter.
      void submit(digits);
    }
  }

  function onSubmitForm(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    void submit(code);
  }

  function toggleRecovery() {
    setUseRecovery((v) => !v);
    setCode('');
    setErr(null);
    submittedRef.current = false;
  }

  const expired = remaining <= 0;
  const mm = Math.floor(remaining / 60);
  const ss = remaining % 60;
  const timerText = `${mm}:${String(ss).padStart(2, '0')}`;

  return (
    <form onSubmit={onSubmitForm} className="space-y-4">
      <div className="flex items-center gap-2 text-sm text-slate-300">
        <ShieldCheck className="w-5 h-5 text-sky-400" />
        <span>
          Two-factor authentication enabled. Enter the code from your
          authenticator app.
        </span>
      </div>

      <label className="block text-sm text-slate-300">
        <span className="mb-1 block">
          {useRecovery ? 'Recovery code' : '6-digit code'}
        </span>
        {useRecovery ? (
          <input
            type="text"
            autoComplete="off"
            value={code}
            onChange={(e) => onCodeChange(e.target.value)}
            placeholder="xxxx-xxxx"
            required
            disabled={busy || expired}
            autoFocus
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
            onChange={(e) => onCodeChange(e.target.value)}
            placeholder="000000"
            required
            autoFocus
            disabled={busy || expired}
            className="w-full px-3 py-2 rounded bg-slate-800 border border-slate-700 font-mono text-center text-lg tracking-[0.4em] focus:outline-none focus:border-sky-500"
          />
        )}
      </label>

      <div className="flex items-center justify-between text-xs">
        <button
          type="button"
          onClick={toggleRecovery}
          disabled={busy}
          className="text-sky-400 hover:underline disabled:opacity-50"
        >
          {useRecovery
            ? 'Use authenticator code instead'
            : 'Use recovery code instead'}
        </button>
        <span className={expired ? 'text-red-400' : 'text-slate-400'}>
          {expired ? 'challenge expired' : `expires in ${timerText}`}
        </span>
      </div>

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
          Back
        </button>
        {/* Explicit submit button: useful when the user types a recovery
            code (no auto-submit) or after a rate-limit pause. */}
        <button
          type="submit"
          disabled={busy || expired || code.length === 0}
          className="flex items-center gap-1 px-3 py-1.5 text-sm rounded bg-sky-600 hover:bg-sky-500 disabled:bg-slate-700 font-medium"
        >
          <KeyRound className="w-3.5 h-3.5" />
          {busy ? 'verifying...' : 'Verify'}
        </button>
      </div>
    </form>
  );
}
