// TOTPSetup drives the enrollment flow in three steps:
//   1. scan QR / type secret into an authenticator app
//   2. enter first code -> /activate
//   3. reveal recovery codes, download as .txt, confirm save
//
// Step 3 is a hard gate: the codes are shown ONLY once and the server
// never returns them again. We block the user from closing with the
// "I've saved them" button until they explicitly acknowledge.

import { FormEvent, useState } from 'react';
import { KeyRound, Download, Copy, ShieldCheck, AlertTriangle } from 'lucide-react';
import { ApiError, TOTPSetupResponse, api } from '../api/client';

type Step = 'init' | 'scan' | 'verified' | 'error';

interface Props {
  onDone: () => void;   // called after "I've saved them"
  onCancel: () => void; // called from the cancel button in step 1/2
}

export default function TOTPSetup({ onDone, onCancel }: Props) {
  const [step, setStep] = useState<Step>('init');
  const [setup, setSetup] = useState<TOTPSetupResponse | null>(null);
  const [code, setCode] = useState('');
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  async function beginSetup() {
    setBusy(true);
    setErr(null);
    try {
      const s = await api.totpSetup();
      setSetup(s);
      setStep('scan');
    } catch (e) {
      setErr(e instanceof ApiError ? e.message : 'failed to start setup');
      setStep('error');
    } finally {
      setBusy(false);
    }
  }

  async function onActivate(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    setBusy(true);
    setErr(null);
    try {
      await api.totpActivate(code);
      setStep('verified');
    } catch (e2) {
      setErr(e2 instanceof ApiError ? e2.message : 'activation failed');
    } finally {
      setBusy(false);
    }
  }

  function copySecret() {
    if (!setup) return;
    navigator.clipboard?.writeText(setup.secret).catch(() => undefined);
  }

  function downloadCodes() {
    if (!setup) return;
    const body =
      'argos-edge recovery codes\n' +
      `generated: ${new Date().toISOString()}\n` +
      'each code can be used exactly once to sign in if you lose your authenticator.\n' +
      'keep them somewhere safe (password manager, printed + locked drawer).\n\n' +
      setup.recovery_codes.join('\n') +
      '\n';
    const blob = new Blob([body], { type: 'text/plain;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'argos-recovery-codes.txt';
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  }

  // ------------- render -------------

  if (step === 'init' || step === 'error') {
    return (
      <div className="space-y-4">
        <div className="flex items-start gap-2 text-sm text-slate-300">
          <ShieldCheck className="w-5 h-5 mt-0.5 text-sky-400" />
          <span>
            Protect your account with a one-time code from an authenticator app
            (Google Authenticator, Aegis, 1Password). You will be asked for the
            code every time you sign in.
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
            Cancel
          </button>
          <button
            type="button"
            onClick={beginSetup}
            disabled={busy}
            className="px-3 py-1.5 text-sm rounded bg-sky-600 hover:bg-sky-500 disabled:bg-slate-700 font-medium"
          >
            {busy ? 'starting...' : 'Start setup'}
          </button>
        </div>
      </div>
    );
  }

  if (step === 'scan' && setup) {
    return (
      <form onSubmit={onActivate} className="space-y-4">
        <ol className="text-sm text-slate-300 space-y-1 list-decimal pl-5">
          <li>Open your authenticator app.</li>
          <li>Scan the QR code (or type the secret by hand).</li>
          <li>Enter the 6-digit code the app shows to activate.</li>
        </ol>

        <div className="flex flex-col items-center gap-3">
          <img
            src={`data:image/png;base64,${setup.qr_png_base64}`}
            alt="2FA QR code"
            className="w-48 h-48 bg-white p-2 rounded"
          />
          <div className="w-full">
            <div className="text-xs text-slate-400 mb-1">
              Can&apos;t scan? Enter this secret manually:
            </div>
            <div className="flex items-center gap-2">
              <code className="flex-1 font-mono text-xs bg-slate-950 border border-slate-800 rounded px-2 py-1 break-all">
                {setup.secret}
              </code>
              <button
                type="button"
                onClick={copySecret}
                className="p-1.5 rounded border border-slate-700 hover:bg-slate-800"
                title="copy secret"
              >
                <Copy className="w-3.5 h-3.5" />
              </button>
            </div>
          </div>
        </div>

        <label className="block text-sm text-slate-300 mt-2">
          <span className="mb-1 block">6-digit code from your app</span>
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
            autoFocus
            className="w-full px-3 py-2 rounded bg-slate-800 border border-slate-700 font-mono text-center text-lg tracking-[0.4em] focus:outline-none focus:border-sky-500"
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
            disabled={busy || code.length !== 6}
            className="px-3 py-1.5 text-sm rounded bg-sky-600 hover:bg-sky-500 disabled:bg-slate-700 font-medium"
          >
            {busy ? 'activating...' : 'Activate'}
          </button>
        </div>
      </form>
    );
  }

  // step === 'verified'
  if (setup) {
    return (
      <div className="space-y-4">
        <div className="flex items-start gap-2 bg-emerald-950/40 border border-emerald-900 rounded px-3 py-2 text-sm text-emerald-200">
          <ShieldCheck className="w-5 h-5 mt-0.5" />
          <span>2FA is enabled. Save these recovery codes before closing.</span>
        </div>
        <div className="flex items-start gap-2 bg-amber-950/40 border border-amber-900 rounded px-3 py-2 text-sm text-amber-200">
          <AlertTriangle className="w-5 h-5 mt-0.5 flex-shrink-0" />
          <span>
            These codes are shown only once. Each can be used one time to sign
            in if you lose access to your authenticator. Store them in a
            password manager or somewhere safe before closing this dialog.
          </span>
        </div>

        <div className="grid grid-cols-2 gap-2 font-mono text-sm bg-slate-950 border border-slate-800 rounded p-3">
          {setup.recovery_codes.map((c) => (
            <code key={c} className="select-all">{c}</code>
          ))}
        </div>

        <div className="flex gap-2 justify-end">
          <button
            type="button"
            onClick={downloadCodes}
            className="flex items-center gap-1 px-3 py-1.5 text-sm rounded border border-slate-700 hover:bg-slate-800"
          >
            <Download className="w-3.5 h-3.5" /> Download .txt
          </button>
          <button
            type="button"
            onClick={onDone}
            className="flex items-center gap-1 px-3 py-1.5 text-sm rounded bg-sky-600 hover:bg-sky-500 font-medium"
          >
            <KeyRound className="w-3.5 h-3.5" /> I&apos;ve saved them
          </button>
        </div>
      </div>
    );
  }

  return null;
}
