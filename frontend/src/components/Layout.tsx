import { ReactNode, useEffect, useState } from 'react';
import { NavLink, useNavigate } from 'react-router-dom';
import { LogOut, ShieldCheck, TriangleAlert } from 'lucide-react';
import { api } from '../api/client';

interface Props {
  username: string;
  children: ReactNode;
}

const NAV_ITEMS: { to: string; label: string }[] = [
  { to: '/', label: 'Dashboard' },
  { to: '/hosts', label: 'Hosts' },
  { to: '/target-groups', label: 'Target Groups' },
  { to: '/security', label: 'Security' },
  { to: '/notifications', label: 'Notifications' },
  { to: '/certs', label: 'Certs' },
  { to: '/logs', label: 'Logs' },
  { to: '/backup', label: 'Backup' },
  { to: '/system', label: 'System' },
  { to: '/settings', label: 'Settings' },
];

export default function Layout({ username, children }: Props) {
  const navigate = useNavigate();
  const [loggingOut, setLoggingOut] = useState(false);
  const [panelMode, setPanelMode] = useState<'lan' | 'behind_caddy' | null>(null);

  useEffect(() => {
    // Cheap one-shot on mount; /api/system/health is admin-gated but
    // the user has already logged in by the time Layout renders.
    api
      .systemHealth()
      .then((h) => setPanelMode(h.panel_mode))
      .catch(() => {});
  }, []);

  const isLocalhost =
    typeof window !== 'undefined' &&
    (window.location.hostname === 'localhost' ||
      window.location.hostname === '127.0.0.1');
  const showLANBanner = panelMode === 'lan' && !isLocalhost;

  async function onLogout() {
    setLoggingOut(true);
    try {
      await api.logout();
    } catch {
      // Logout is idempotent on the backend; a failed network call here
      // is fine because we are about to bounce the user to /login anyway.
    }
    navigate('/login', { replace: true });
  }

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col">
      <header className="border-b border-slate-800 bg-slate-900">
        <div className="mx-auto max-w-6xl px-4 h-14 flex items-center justify-between">
          <div className="flex items-center gap-6">
            <div className="flex items-center gap-2 font-semibold tracking-tight">
              <ShieldCheck className="w-5 h-5 text-sky-400" />
              <span>argos-edge</span>
            </div>
            <nav className="flex items-center gap-1 text-sm">
              {NAV_ITEMS.map((item) => (
                <NavLink
                  key={item.to}
                  to={item.to}
                  end={item.to === '/'}
                  className={({ isActive }) =>
                    `px-3 py-1.5 rounded ${
                      isActive
                        ? 'bg-slate-800 text-slate-100'
                        : 'text-slate-400 hover:text-slate-100 hover:bg-slate-800/60'
                    }`
                  }
                >
                  {item.label}
                </NavLink>
              ))}
            </nav>
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
      {showLANBanner && (
        <div className="bg-amber-900/40 text-amber-200 border-y border-amber-800 text-xs">
          <div className="mx-auto max-w-6xl px-4 h-8 flex items-center gap-2">
            <TriangleAlert className="w-3.5 h-3.5 flex-shrink-0" />
            <span>
              LAN mode (HTTP) &mdash; Browser Push and HTTPS-only features are
              disabled. See{' '}
              <NavLink to="/system" className="underline hover:text-amber-100">
                /system
              </NavLink>{' '}
              for details.
            </span>
          </div>
        </div>
      )}
      <main className="flex-1">{children}</main>
    </div>
  );
}
