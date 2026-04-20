import { ReactNode, useEffect, useRef, useState } from 'react';
import { NavLink, useLocation, useNavigate } from 'react-router-dom';
import {
  LogOut,
  Menu,
  ShieldAlert,
  ShieldCheck,
  TriangleAlert,
  X,
} from 'lucide-react';
import { api, AppSecMode } from '../api/client';

interface Props {
  username: string;
  children: ReactNode;
}

const NAV_ITEMS: { to: string; label: string }[] = [
  { to: '/', label: 'Dashboard' },
  { to: '/hosts', label: 'Hosts' },
  { to: '/target-groups', label: 'Target Groups' },
  { to: '/security', label: 'Security' },
  { to: '/threats', label: 'Threats' },
  { to: '/appsec', label: 'AppSec' },
  { to: '/notifications', label: 'Notifications' },
  { to: '/certs', label: 'Certs' },
  { to: '/logs', label: 'Logs' },
  { to: '/backup', label: 'Backup' },
  { to: '/system', label: 'System' },
  { to: '/settings', label: 'Settings' },
];

export default function Layout({ username, children }: Props) {
  const navigate = useNavigate();
  const location = useLocation();
  const [loggingOut, setLoggingOut] = useState(false);
  const [panelMode, setPanelMode] = useState<'lan' | 'behind_caddy' | null>(null);
  const [appSecMode, setAppSecMode] = useState<AppSecMode | null>(null);

  // Mobile (< nav breakpoint = 1100px) nav state. The Tailwind `nav:`
  // responsive prefix hides the hamburger on >=1100px; the drawer is
  // never rendered there because mobileOpen stays false (nothing
  // opens it) and even if it did, the drawer's outer div carries
  // `nav:hidden`.
  const [mobileOpen, setMobileOpen] = useState(false);
  const drawerRef = useRef<HTMLDivElement | null>(null);

  useEffect(() => {
    // Cheap one-shot on mount; /api/system/health is admin-gated but
    // the user has already logged in by the time Layout renders.
    api
      .systemHealth()
      .then((h) => setPanelMode(h.panel_mode))
      .catch(() => {});
    // AppSec mode is polled on mount + every 30s so the "blocking
    // active" banner lands shortly after someone flips mode from
    // /appsec (or another tab). A Server-Sent Events push would be
    // nicer but we already poll status cards on a tight loop; a
    // dedicated stream is overkill for a three-state setting.
    const fetchMode = () =>
      api
        .appsecStatus()
        .then((s) => setAppSecMode(s.mode))
        .catch(() => {});
    fetchMode();
    const id = setInterval(fetchMode, 30_000);
    return () => clearInterval(id);
  }, []);

  // Close the drawer on route change. A user tapping a nav item
  // triggers this by virtue of NavLink changing location.pathname.
  useEffect(() => {
    setMobileOpen(false);
  }, [location.pathname]);

  // ESC closes the drawer; click-outside closes too (drawer is a card
  // anchored below the header, not a full-screen overlay, so a click
  // on main content should dismiss it).
  useEffect(() => {
    if (!mobileOpen) return;
    function onKey(e: KeyboardEvent) {
      if (e.key === 'Escape') setMobileOpen(false);
    }
    function onClick(e: MouseEvent) {
      if (!drawerRef.current) return;
      if (!drawerRef.current.contains(e.target as Node)) {
        setMobileOpen(false);
      }
    }
    window.addEventListener('keydown', onKey);
    // Use capture on the click listener so the hamburger button's own
    // onClick can re-open the drawer without racing a close from this.
    window.addEventListener('mousedown', onClick);
    return () => {
      window.removeEventListener('keydown', onKey);
      window.removeEventListener('mousedown', onClick);
    };
  }, [mobileOpen]);

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
      <header className="border-b border-slate-800 bg-slate-900 relative">
        <div className="mx-auto max-w-6xl px-4 h-14 flex items-center justify-between">
          <div className="flex items-center gap-6">
            <div className="flex items-center gap-2 font-semibold tracking-tight">
              <ShieldCheck className="w-5 h-5 text-sky-400" />
              <span>argos-edge</span>
            </div>
            {/* Desktop nav -- horizontal, shown at >=1100px. */}
            <nav className="hidden nav:flex items-center gap-1 text-sm">
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
            {/* Username + logout stay visible in both layouts so the
                break-glass "get out" action is never one more tap
                than necessary. */}
            <span className="hidden nav:inline text-slate-400">{username}</span>
            <button
              type="button"
              onClick={onLogout}
              disabled={loggingOut}
              className="hidden nav:flex items-center gap-1 px-2 py-1 rounded border border-slate-700 hover:bg-slate-800 disabled:opacity-50"
            >
              <LogOut className="w-4 h-4" />
              <span>logout</span>
            </button>
            {/* Mobile hamburger -- shown <1100px. */}
            <button
              type="button"
              onClick={() => setMobileOpen((v) => !v)}
              className="nav:hidden flex items-center gap-1 p-2 rounded border border-slate-700 hover:bg-slate-800"
              aria-label={mobileOpen ? 'Close menu' : 'Open menu'}
              aria-expanded={mobileOpen}
            >
              {mobileOpen ? (
                <X className="w-5 h-5" />
              ) : (
                <Menu className="w-5 h-5" />
              )}
            </button>
          </div>
        </div>

        {/* Mobile drawer -- anchored below the header bar. Uses the
            max-h transition pattern so the whole thing animates open
            (150ms) without needing JS-driven heights. */}
        <div
          ref={drawerRef}
          className={`nav:hidden overflow-hidden transition-all duration-150 ease-out border-t border-slate-800 bg-slate-900 ${
            mobileOpen ? 'max-h-[32rem]' : 'max-h-0'
          }`}
        >
          <nav className="mx-auto max-w-6xl px-4 py-3 flex flex-col gap-1 text-sm">
            {NAV_ITEMS.map((item) => (
              <NavLink
                key={item.to}
                to={item.to}
                end={item.to === '/'}
                className={({ isActive }) =>
                  `px-3 py-2 rounded ${
                    isActive
                      ? 'bg-slate-800 text-slate-100'
                      : 'text-slate-400 hover:text-slate-100 hover:bg-slate-800/60'
                  }`
                }
              >
                {item.label}
              </NavLink>
            ))}
            <div className="flex items-center justify-between border-t border-slate-800 mt-2 pt-2 text-slate-400">
              <span className="px-3">{username}</span>
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
          </nav>
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
      {appSecMode === 'block' && (
        <div className="bg-amber-900/40 text-amber-200 border-y border-amber-800 text-xs">
          <div className="mx-auto max-w-6xl px-4 h-8 flex items-center gap-2">
            <ShieldAlert className="w-3.5 h-3.5 flex-shrink-0" />
            <span>
              AppSec blocking active &mdash; matching requests return 403. Review
              hits at{' '}
              <NavLink to="/appsec" className="underline hover:text-amber-100">
                /appsec
              </NavLink>
              .
            </span>
          </div>
        </div>
      )}
      <main className="flex-1">{children}</main>
    </div>
  );
}
