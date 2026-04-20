import { FormEvent, useEffect, useState } from 'react';
import { useLocation, useNavigate } from 'react-router-dom';
import { KeyRound, ShieldCheck } from 'lucide-react';
import { ApiError, api, isTOTPPending } from '../api/client';
import TOTPLoginChallenge from '../components/TOTPLoginChallenge';

// Login is a two-stage form when the account has 2FA enabled:
//  stage 1: username + password  -> /api/auth/login
//  stage 2: TOTP code (or recovery) -> /api/auth/totp/verify|recovery
// Stage 2 is rendered via TOTPLoginChallenge. Password-only accounts
// skip straight to the post-login navigation.
//
// OIDC SSO, when /api/auth/oidc/available returns enabled=true, adds
// a "Sign in with SSO" button above the password form. Clicking it
// navigates the browser (full page, not fetch) to
// /api/auth/oidc/login?rd=<current-location>; the backend issues the
// 302 to the provider.
export default function Login() {
  const navigate = useNavigate();
  const location = useLocation();
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [challengeId, setChallengeId] = useState<string | null>(null);
  const [ssoEnabled, setSsoEnabled] = useState(false);

  // One-shot probe: is OIDC configured and ready? Cheap public
  // endpoint, no auth. Silent fail = hide the button.
  useEffect(() => {
    api
      .oidcAvailable()
      .then((r) => setSsoEnabled(r.enabled))
      .catch(() => setSsoEnabled(false));
  }, []);

  // The OIDC callback sends the browser to /login?oidc_error=<code>
  // when anything in the flow failed. Surface that as an inline
  // banner so the user knows WHY they landed back here.
  const ssoError = (() => {
    const p = new URLSearchParams(location.search);
    return p.get('oidc_error');
  })();

  async function onSubmit(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    setError(null);
    setSubmitting(true);
    try {
      const res = await api.login(username, password);
      if (isTOTPPending(res)) {
        setChallengeId(res.challenge_id);
      } else {
        await afterLoginRedirect();
      }
    } catch (err) {
      const msg =
        err instanceof ApiError ? err.message : 'could not reach the server';
      setError(msg);
    } finally {
      setSubmitting(false);
    }
  }

  // afterLoginRedirect honors the ?rd= query param when present.
  // Backend validator decides what is safe (same panel host or a
  // subdomain of oidc.cookie_parent_domain); an off-domain rd falls
  // back to "/". External targets need window.location (React Router
  // cannot cross origins); internal paths use navigate() so the SPA
  // state survives.
  async function afterLoginRedirect() {
    const rd = new URLSearchParams(location.search).get('rd') ?? '';
    if (!rd) {
      navigate('/', { replace: true });
      return;
    }
    try {
      const { url } = await api.safeRedirect(rd);
      if (url.startsWith('/')) {
        navigate(url, { replace: true });
      } else {
        window.location.href = url;
      }
    } catch {
      navigate('/', { replace: true });
    }
  }

  function onTOTPSuccess() {
    void afterLoginRedirect();
  }

  function onTOTPCancel() {
    // Back to the password form. We don't attempt to explicitly
    // invalidate the challenge server-side: the 5-min TTL will sweep
    // it, and the user is free to restart the flow immediately.
    setChallengeId(null);
    setPassword('');
    setError(null);
  }

  // Full-page nav (not fetch) so the browser follows the 302 that
  // /api/auth/oidc/login returns. rd= encodes where to land after
  // the round-trip; we re-use the current path so a user who
  // bookmarked "/dashboard" lands back there.
  function onSSO() {
    const rd = window.location.pathname + window.location.search;
    const target =
      '/api/auth/oidc/login?rd=' + encodeURIComponent(rd === '/login' ? '/' : rd);
    window.location.href = target;
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
          <>
            {ssoError && (
              <div className="mb-4 text-sm text-red-400 bg-red-950/40 border border-red-900 rounded px-3 py-2">
                Single sign-on failed: {humanizeOIDCError(ssoError)}
              </div>
            )}

            {ssoEnabled && (
              <>
                <button
                  type="button"
                  onClick={onSSO}
                  className="w-full mb-3 py-2 rounded bg-slate-800 hover:bg-slate-700 border border-slate-700 font-medium flex items-center justify-center gap-2"
                >
                  <KeyRound className="w-4 h-4" /> Sign in with SSO
                </button>
                <div className="relative mb-4 text-center text-xs text-slate-500">
                  <span className="bg-slate-900 px-2 relative z-10">or use local account</span>
                  <div className="absolute inset-x-0 top-1/2 border-t border-slate-800" />
                </div>
              </>
            )}

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
          </>
        )}
      </div>
    </div>
  );
}

// humanizeOIDCError maps the short reason codes the callback emits
// to user-facing strings. Keeping the vocabulary small and stable
// also stops us from accidentally leaking IdP internals in the URL.
function humanizeOIDCError(code: string): string {
  switch (code) {
    case 'idp_error':
      return 'the identity provider rejected the login';
    case 'state_not_found':
      return 'the login window expired; please try again';
    case 'not_allowed':
      return 'your account is not on the allowlist for this panel';
    case 'no_auto_provision':
      return 'your user is unknown and auto-provisioning is disabled';
    case 'email_unverified':
      return 'your identity provider has not verified your email address';
    case 'upsert':
      return 'could not create or update your user record';
    case 'callback':
      return 'callback verification failed';
    default:
      return code;
  }
}
