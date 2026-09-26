import { ReactNode, useEffect, useState } from 'react';
import { Navigate } from 'react-router-dom';
import { User, api, cachedUser } from '../api/client';

type AuthState =
  | { state: 'checking' }
  | { state: 'authed'; user: User }
  | { state: 'anon' };

interface Props {
  children: (user: User) => ReactNode;
}

// ProtectedRoute decides whether to render the children from the
// session identity. v1.3.38.5: /api/auth/me is asked once per session
// (api.me caches it in memory; the cache is dropped on logout and on
// any 401), so a route change on a known session renders at once
// instead of blanking the page for a round trip. Only the first mount
// of a session waits.
export default function ProtectedRoute({ children }: Props) {
  const [auth, setAuth] = useState<AuthState>(() => {
    const user = cachedUser();
    return user ? { state: 'authed', user } : { state: 'checking' };
  });

  useEffect(() => {
    if (auth.state !== 'checking') return;
    let cancelled = false;
    api
      .me()
      .then((user) => {
        if (!cancelled) setAuth({ state: 'authed', user });
      })
      .catch(() => {
        if (cancelled) return;
        // A 401 already redirected via the api client; anything else
        // (network) also sends the user to /login, where a fresh
        // attempt is one click away.
        setAuth({ state: 'anon' });
      });
    return () => {
      cancelled = true;
    };
  }, [auth.state]);

  if (auth.state === 'checking') {
    return (
      <div className="min-h-screen flex items-center justify-center text-slate-400">
        loading...
      </div>
    );
  }
  if (auth.state === 'anon') {
    return <Navigate to="/login" replace />;
  }
  return <>{children(auth.user)}</>;
}
