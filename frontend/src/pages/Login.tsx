import { FormEvent, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { ShieldCheck } from 'lucide-react';
import { ApiError, api, isTOTPPending } from '../api/client';
import TOTPLoginChallenge from '../components/TOTPLoginChallenge';

// Login is a two-stage form when the account has 2FA enabled:
//  stage 1: username + password  -> /api/auth/login
//  stage 2: TOTP code (or recovery) -> /api/auth/totp/verify|recovery
// Stage 2 is rendered via TOTPLoginChallenge. On password-only accounts
// we skip straight to the post-login navigation.
export default function Login() {
  const navigate = useNavigate();
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [challengeId, setChallengeId] = useState<string | null>(null);

  async function onSubmit(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    setError(null);
    setSubmitting(true);
    try {
      const res = await api.login(username, password);
      if (isTOTPPending(res)) {
        setChallengeId(res.challenge_id);
      } else {
        navigate('/', { replace: true });
      }
    } catch (err) {
      const msg =
        err instanceof ApiError ? err.message : 'could not reach the server';
      setError(msg);
    } finally {
      setSubmitting(false);
    }
  }

  function onTOTPSuccess() {
    navigate('/', { replace: true });
  }

  function onTOTPCancel() {
    // Back to the password form. We don't attempt to explicitly
    // invalidate the challenge server-side: the 5-min TTL will sweep
    // it, and the user is free to restart the flow immediately.
    setChallengeId(null);
    setPassword('');
    setError(null);
  }

  return (
    <div className="min-h-screen flex items-center justify-center bg-slate-950 text-slate-100 px-4">
      <div className="w-full max-w-sm bg-slate-900 border border-slate-800 rounded-lg p-6 shadow-xl">
        <div className="flex items-center gap-2 mb-6">
          <ShieldCheck className="w-6 h-6 text-sky-400" />
          <h1 className="text-xl font-semibold tracking-tight">argos-edge</h1>
        </div>

        {challengeId ? (
          <TOTPLoginChallenge
            challengeId={challengeId}
            onSuccess={onTOTPSuccess}
            onCancel={onTOTPCancel}
          />
        ) : (
          <form onSubmit={onSubmit}>
            <label className="block text-sm text-slate-300 mb-1" htmlFor="username">
              Username
            </label>
            <input
              id="username"
              type="text"
              autoComplete="username"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              required
              className="w-full mb-4 px-3 py-2 rounded bg-slate-800 border border-slate-700 focus:outline-none focus:border-sky-500"
            />

            <label className="block text-sm text-slate-300 mb-1" htmlFor="password">
              Password
            </label>
            <input
              id="password"
              type="password"
              autoComplete="current-password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              required
              className="w-full mb-4 px-3 py-2 rounded bg-slate-800 border border-slate-700 focus:outline-none focus:border-sky-500"
            />

            {error && (
              <div className="mb-4 text-sm text-red-400 bg-red-950/40 border border-red-900 rounded px-3 py-2">
                {error}
              </div>
            )}

            <button
              type="submit"
              disabled={submitting}
              className="w-full py-2 rounded bg-sky-600 hover:bg-sky-500 disabled:bg-slate-700 disabled:cursor-not-allowed font-medium"
            >
              {submitting ? 'signing in...' : 'Sign in'}
            </button>
          </form>
        )}
      </div>
    </div>
  );
}
