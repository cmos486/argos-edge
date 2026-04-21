import { ReactNode, useEffect, useRef, useState } from 'react';
import { NavLink, useLocation, useNavigate } from 'react-router-dom';
import {
  LogOut,
  Menu,
  Shield,
  ShieldAlert,
  ShieldCheck,
  ShieldOff,
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
  { to: '/certificates', label: 'Certificates' },
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

  // Drawer-open state. Hamburger + drawer are visible at every
  // viewport -- the earlier responsive split at 1100px produced a
  // two-row wrap between 1100-1400px, so the twelve top-level nav
  // items now live inside the drawer unconditionally.
  const [drawerOpen, setDrawerOpen] = useState(false);
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
    setDrawerOpen(false);
  }, [location.pathname]);

  // ESC closes the drawer; click-outside closes too (drawer is a card
  // anchored below the header, not a full-screen overlay, so a click
  // on main content should dismiss it).
  useEffect(() => {
    if (!drawerOpen) return;
    function onKey(e: KeyboardEvent) {
      if (e.key === 'Escape') setDrawerOpen(false);
    }
    function onClick(e: MouseEvent) {
      if (!drawerRef.current) return;
      if (!drawerRef.current.contains(e.target as Node)) {
        setDrawerOpen(false);
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
  }, [drawerOpen]);

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
        <div className="mx-auto max-w-[1400px] px-4 h-14 flex items-center justify-between gap-3">
          <div className="flex items-center gap-3 min-w-0">
            {/* Logo bumped one step up in size so the brand reads
                clearly without the header growing taller -- the row
                is still h-14; items-center re-centres vertically. */}
            <div className="flex items-center gap-2.5 font-semibold tracking-tight text-base">
              <ShieldCheck className="w-6 h-6 text-sky-400" />
              <span>argos-edge</span>
            </div>
            {/* Status pills. What used to be a dedicated row below the
                header (LAN mode + AppSec blocking) is now inline here
                so the layout keeps one header instead of stacking
                alert bars. Each pill is a NavLink so clicking takes
                the operator to the settings page that controls the
                state the pill is complaining about; the `title` attr
                carries the long-form explanation for mouse users. */}
            {showLANBanner && (
              <NavLink
                to="/system"
                title="LAN mode (HTTP) -- Browser Push and HTTPS-only features are disabled. Click to review panel settings."
                className="hidden sm:inline-flex items-center gap-1 px-2 py-0.5 rounded border border-amber-700 bg-amber-900/40 text-amber-200 text-xs hover:bg-amber-900/60"
              >
                <TriangleAlert className="w-3.5 h-3.5 flex-shrink-0" />
                LAN mode
              </NavLink>
            )}
            {appSecMode && (
              <AppSecPill mode={appSecMode} />
            )}
          </div>
          <div className="flex items-center gap-4 text-sm">
            {/* Username + logout stay visible at every viewport so the
                break-glass "get out" action is always one tap away.
                Truncate caps the username on very narrow screens so a
                long name does not push logout / hamburger off-screen. */}
            <span className="text-slate-400 truncate max-w-[120px]">{username}</span>
            <button
              type="button"
              onClick={onLogout}
              disabled={loggingOut}
              className="flex items-center gap-1 px-2 py-1 rounded border border-slate-700 hover:bg-slate-800 disabled:opacity-50"
            >
              <LogOut className="w-4 h-4" />
              <span>logout</span>
            </button>
            {/* Hamburger. The twelve top-level routes live only inside
                the drawer now; trying to fit them on one line produced
                a two-row wrap between 1100-1400px that we gave up on. */}
            <button
              type="button"
              onClick={() => setDrawerOpen((v) => !v)}
              className="flex items-center gap-1 p-2 rounded border border-slate-700 hover:bg-slate-800"
              aria-label={drawerOpen ? 'Close menu' : 'Open menu'}
              aria-expanded={drawerOpen}
            >
              {drawerOpen ? (
                <X className="w-5 h-5" />
              ) : (
                <Menu className="w-5 h-5" />
              )}
            </button>
          </div>
        </div>

        {/* Drawer anchored below the header bar. Uses the max-h
            transition pattern so the whole thing animates open
            (150ms) without needing JS-driven heights. */}
        <div
          ref={drawerRef}
          className={`overflow-hidden transition-all duration-150 ease-out border-t border-slate-800 bg-slate-900 ${
            drawerOpen ? 'max-h-[32rem]' : 'max-h-0'
          }`}
        >
          <nav className="mx-auto max-w-[1400px] px-4 py-3 flex flex-col gap-1 text-sm">
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
          </nav>
        </div>
      </header>
      <main className="flex-1">{children}</main>
    </div>
  );
}

// AppSecPill renders the always-on WAF status indicator in the navbar.
// Three shapes keyed off the current AppSec runtime mode:
//
//   disabled -> slate/neutral, ShieldOff. The WAF is not filtering;
//               'off' is the message, not a problem.
//   detect   -> amber, ShieldAlert. The WAF is logging hits but not
//               blocking; worth noticing but not alarming.
//   block    -> red, Shield. The WAF is actively rejecting requests
//               at the edge; this is the strongest stance and the
//               operator should know it is on.
//
// Click routes to /appsec so the operator can change mode + review
// hits; the title attr carries the long-form explanation that used
// to live in the stripe banner.
function AppSecPill({ mode }: { mode: AppSecMode }) {
  let label: string;
  let tooltip: string;
  let Icon: typeof ShieldOff;
  let cls: string;
  switch (mode) {
    case 'disabled':
      label = 'AppSec off';
      tooltip = 'AppSec is disabled -- no request filtering. Click to configure.';
      Icon = ShieldOff;
      cls = 'border-slate-700 bg-slate-800/60 text-slate-300 hover:bg-slate-800';
      break;
    case 'block':
      label = 'AppSec block';
      tooltip = 'AppSec in block mode -- actively blocking malicious requests. Click for details.';
      Icon = Shield;
      cls = 'border-red-800 bg-red-950/50 text-red-200 hover:bg-red-900/60';
      break;
    case 'detect':
    default:
      label = 'AppSec detect';
      tooltip = 'AppSec in detect mode -- logging only, not blocking. Click for details.';
      Icon = ShieldAlert;
      cls = 'border-amber-700 bg-amber-900/40 text-amber-200 hover:bg-amber-900/60';
      break;
  }
  return (
    <NavLink
      to="/appsec"
      title={tooltip}
      className={`hidden sm:inline-flex items-center gap-1 px-2 py-0.5 rounded border text-xs ${cls}`}
    >
      <Icon className="w-3.5 h-3.5 flex-shrink-0" />
      {label}
    </NavLink>
  );
}
