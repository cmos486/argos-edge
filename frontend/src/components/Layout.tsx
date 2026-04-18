import { ReactNode, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { LogOut, ShieldCheck } from 'lucide-react';
import { api } from '../api/client';

interface Props {
  username: string;
  children: ReactNode;
}

export default function Layout({ username, children }: Props) {
  const navigate = useNavigate();
  const [loggingOut, setLoggingOut] = useState(false);

  async function onLogout() {
    setLoggingOut(true);
    try {
      await api.logout();
    } catch {
      // The backend makes logout idempotent, so any network hiccup can be
      // ignored: we are about to bounce the user to /login regardless.
    }
    navigate('/login', { replace: true });
  }

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col">
      <header className="border-b border-slate-800 bg-slate-900">
        <div className="mx-auto max-w-6xl px-4 h-14 flex items-center justify-between">
          <div className="flex items-center gap-2 font-semibold tracking-tight">
            <ShieldCheck className="w-5 h-5 text-sky-400" />
            <span>argos-edge</span>
          </div>
          <div className="flex items-center gap-4 text-sm">
            <span className="text-slate-400">{username}</span>
            <button
              type="button"
              onClick={onLogout}
              disabled={loggingOut}
              className="flex items-center gap-1 px-2 py-1 rounded border border-slate-700 hover:bg-slate-800 disabled:opacity-50"
            >
              <LogOut className="w-4 h-4" />
              <span>logout</span>
            </button>
          </div>
        </div>
      </header>
      <main className="flex-1">{children}</main>
    </div>
  );
}
