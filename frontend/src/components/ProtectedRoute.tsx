import { ReactNode, useEffect, useState } from 'react';
import { Navigate } from 'react-router-dom';
import { ApiError, User, api } from '../api/client';

type AuthState =
  | { state: 'checking' }
  | { state: 'authed'; user: User }
  | { state: 'anon' };

interface Props {
  children: (user: User) => ReactNode;
}

// ProtectedRoute hits /api/auth/me once on mount to decide whether to render
// the children. The api client already redirects on 401, so we mostly just
// render nothing during the network round-trip.
export default function ProtectedRoute({ children }: Props) {
  const [auth, setAuth] = useState<AuthState>({ state: 'checking' });

  useEffect(() => {
    let cancelled = false;
    api
      .me()
      .then((user) => {
        if (!cancelled) setAuth({ state: 'authed', user });
      })
      .catch((err) => {
        if (cancelled) return;
        if (err instanceof ApiError && err.status === 401) {
          setAuth({ state: 'anon' });
        } else {
          setAuth({ state: 'anon' });
        }
      });
    return () => {
      cancelled = true;
    };
  }, []);

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
