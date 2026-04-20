// TOTPRegenerateModal is a two-step dialog:
//
//   step 1 "gate": password input + warning that the existing
//                  recovery codes are about to be invalidated.
//   step 2 "reveal": show the N new codes with Copy / Download /
//                    Done. ESC + Done both require confirmation so
//                    a stray keypress cannot dismiss the only
//                    chance to save them.
//
// Errors from /regenerate bubble inline:
//   - 401 invalid credentials → reset password + focus.
//   - 400 "not available for OIDC-only accounts" → distinct message;
//         the button shouldn't have been shown for SSO-only users
//         but we degrade gracefully.
//   - 409 2fa not enabled → race condition (disabled between the
//         list render and the modal open); close + surface in the
//         section the next time the user refreshes.

import { FormEvent, useEffect, useRef, useState } from 'react';
import {
  AlertTriangle,
  Check,
  Copy,
  Download,
  KeyRound,
  Loader2,
  RefreshCw,
} from 'lucide-react';
import Modal from './Modal';
import { ApiError, api } from '../api/client';

type Step = 'gate' | 'reveal';

interface Props {
  open: boolean;
  onClose: (result: 'cancelled' | 'regenerated') => void;
}

export default function TOTPRegenerateModal({ open, onClose }: Props) {
  const [step, setStep] = useState<Step>('gate');
  const [password, setPassword] = useState('');
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [codes, setCodes] = useState<string[]>([]);
  const [copied, setCopied] = useState(false);
  const pwdRef = useRef<HTMLInputElement | null>(null);

  // Reset internal state each time the modal opens so a prior
  // success does not leak into a re-open.
  useEffect(() => {
    if (open) {
      setStep('gate');
      setPassword('');
      setErr(null);
      setCodes([]);
      setCopied(false);
    }
  }, [open]);

  // On the reveal step the user MUST acknowledge. We don't have a
  // way to cancel the outer Modal's ESC handler entirely, so we
  // intercept ESC here and confirm() before letting the caller
  // close. Capture phase to beat Modal's own keydown listener.
  useEffect(() => {
    if (!open || step !== 'reveal') return;
    function onKey(e: KeyboardEvent) {
      if (e.key === 'Escape') {
        e.stopPropagation();
        e.preventDefault();
        confirmClose();
      }
    }
    window.addEventListener('keydown', onKey, true);
    return () => window.removeEventListener('keydown', onKey, true);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open, step]);

  function confirmClose() {
    if (window.confirm('Have you saved the new recovery codes? They will not be shown again.')) {
      onClose('regenerated');
    }
  }

  async function onSubmit(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    setBusy(true);
    setErr(null);
    try {
      const r = await api.totpRegenerateRecovery(password);
      setCodes(r.codes);
      setStep('reveal');
    } catch (e2) {
      if (e2 instanceof ApiError) {
        if (e2.status === 401) {
          setErr('Incorrect password. Try again.');
        } else if (e2.status === 400 && e2.message.includes('OIDC-only')) {
          setErr('Regenerate is not available for SSO accounts -- the identity provider manages 2FA.');
        } else if (e2.status === 409) {
          setErr('2FA is not enabled. Close this dialog and refresh the page.');
        } else {
          setErr(e2.message);
        }
      } else {
        setErr('Could not reach the server.');
      }
      setPassword('');
      setTimeout(() => pwdRef.current?.focus(), 0);
    } finally {
      setBusy(false);
    }
  }

  async function onCopy() {
    try {
      await navigator.clipboard.writeText(codes.join('\n'));
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch {
      setErr('Could not copy to clipboard.');
    }
  }

  function onDownload() {
    const body =
      'argos-edge recovery codes (regenerated)\n' +
      `generated: ${new Date().toISOString()}\n` +
      'each code can be used exactly once to sign in if you lose your authenticator.\n' +
      'any previous recovery codes for this account are now invalid.\n\n' +
      codes.join('\n') +
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

  // Modal close handler is wired different on each step: gate lets
  // ESC / X close freely, reveal demands confirmation.
  const handleModalClose = () => {
    if (step === 'reveal') {
      confirmClose();
    } else {
      onClose('cancelled');
    }
  };

  return (
    <Modal
      open={open}
      title={step === 'gate' ? 'Regenerate recovery codes' : 'Save your new recovery codes'}
      onClose={handleModalClose}
    >
      {step === 'gate' ? (
        <form onSubmit={onSubmit} className="space-y-3">
          <div className="flex items-start gap-2 bg-amber-950/40 border border-amber-900 rounded px-3 py-2 text-sm text-amber-200">
            <AlertTriangle className="w-5 h-5 mt-0.5 flex-shrink-0" />
            <span>
              Your current recovery codes will be invalidated immediately.
              Make sure to save the new codes -- they can only be shown once.
            </span>
          </div>

          <label className="block text-sm text-slate-300">
            <span className="mb-1 block">Confirm with your password</span>
            <input
              ref={pwdRef}
              type="password"
              autoComplete="current-password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              required
              autoFocus
              className="w-full px-3 py-2 rounded bg-slate-800 border border-slate-700 focus:outline-none focus:border-sky-500"
            />
          </label>

          {err && (
            <div className="text-sm text-red-400 bg-red-950/40 border border-red-900 rounded px-3 py-2">
              {err}
            </div>
          )}

          <div className="flex gap-2 justify-end pt-1">
            <button
              type="button"
              onClick={() => onClose('cancelled')}
              disabled={busy}
              className="px-3 py-1.5 text-sm rounded border border-slate-700 hover:bg-slate-800"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={busy || !password}
              className="inline-flex items-center gap-1 px-3 py-1.5 text-sm rounded bg-sky-600 hover:bg-sky-500 disabled:bg-slate-700 font-medium"
            >
              {busy ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <RefreshCw className="w-3.5 h-3.5" />}
              {busy ? 'regenerating...' : 'Regenerate'}
            </button>
          </div>
        </form>
      ) : (
        <div className="space-y-3">
          <div className="flex items-start gap-2 bg-amber-950/40 border border-amber-900 rounded px-3 py-2 text-sm text-amber-200">
            <AlertTriangle className="w-5 h-5 mt-0.5 flex-shrink-0" />
            <span>
              These codes are shown only once. Any previous recovery codes are
              now invalid. Save them in a password manager or printed and
              locked before closing this dialog.
            </span>
          </div>

          <div className="grid grid-cols-2 gap-2 font-mono text-sm bg-slate-950 border border-slate-800 rounded p-3">
            {codes.map((c) => (
              <code key={c} className="select-all">
                {c}
              </code>
            ))}
          </div>

          {err && (
            <div className="text-sm text-red-400 bg-red-950/40 border border-red-900 rounded px-3 py-2">
              {err}
            </div>
          )}

          <div className="flex gap-2 justify-end">
            <button
              type="button"
              onClick={onCopy}
              className="inline-flex items-center gap-1 px-3 py-1.5 text-sm rounded border border-slate-700 hover:bg-slate-800"
            >
              {copied ? (
                <Check className="w-3.5 h-3.5 text-emerald-400" />
              ) : (
                <Copy className="w-3.5 h-3.5" />
              )}
              {copied ? 'copied' : 'Copy to clipboard'}
            </button>
            <button
              type="button"
              onClick={onDownload}
              className="inline-flex items-center gap-1 px-3 py-1.5 text-sm rounded border border-slate-700 hover:bg-slate-800"
            >
              <Download className="w-3.5 h-3.5" /> Download .txt
            </button>
            <button
              type="button"
              onClick={confirmClose}
              className="inline-flex items-center gap-1 px-3 py-1.5 text-sm rounded bg-sky-600 hover:bg-sky-500 font-medium"
            >
              <KeyRound className="w-3.5 h-3.5" /> Done
            </button>
          </div>
        </div>
      )}
    </Modal>
  );
}
