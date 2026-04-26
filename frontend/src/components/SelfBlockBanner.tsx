import { useCallback, useEffect, useState } from 'react';
import { AlertTriangle, X } from 'lucide-react';
import {
  api,
  ApiError,
  SecurityBannedIPDetail,
  SecurityCheckSelfResponse,
  SecurityDecision,
} from '../api/client';
import { useToasts } from './toastsContext';

// SelfBlockBanner v2 (v1.3.23).
//
// v1.3.19 only saw the request's resolved client_ip. An operator
// hitting the panel from the LAN never noticed when their public
// IP was banned. v1.3.23's backend enumerates every IP the
// operator's session(s) might be tied to (current_session_ip +
// public_ip_self + active_session_ips) and probes LAPI for each;
// the banner now renders one row per banned IP with per-IP unban
// + whitelist actions.
//
// Backwards compatibility: when the backend returns the v1.3.19
// shape (no banned_ips field), the banner falls back to the
// single-IP rendering using the top-level decisions field. This
// covers mixed-version environments and the dev-panel case
// where /api/security/check-self is unwired.

const DISMISS_KEY = 'argos.selfblock.dismissed';
const POLL_MS = 60_000;

type BusyKey = string; // either 'unban:<ip>' / 'whitelist:<ip>' / null

const SOURCE_LABEL: Record<SecurityBannedIPDetail['source'], string> = {
  current_session: 'this session',
  public_ip: 'panel public IP',
  active_session: 'other active session',
};

export default function SelfBlockBanner() {
  const toasts = useToasts();
  const [state, setState] = useState<SecurityCheckSelfResponse | null>(null);
  const [busy, setBusy] = useState<BusyKey | null>(null);
  const [dismissed, setDismissed] = useState<boolean>(() => {
    try {
      return sessionStorage.getItem(DISMISS_KEY) === '1';
    } catch {
      return false;
    }
  });

  const probe = useCallback(async () => {
    try {
      const resp = await api.securityCheckSelf();
      setState(resp);
    } catch {
      // Silent: a transient probe failure should not paint a
      // scary error. Next 60s poll retries.
    }
  }, []);

  useEffect(() => {
    probe();
    const id = window.setInterval(probe, POLL_MS);
    return () => window.clearInterval(id);
  }, [probe]);

  if (dismissed || !state) return null;

  // Resolve the per-IP rows. Prefer v1.3.23's banned_ips array;
  // fall back to the v1.3.19 shape when absent or empty.
  const rows = resolveBannedRows(state);
  if (rows.length === 0) return null;

  async function unban(ip: string) {
    setBusy(`unban:${ip}`);
    try {
      const r = await api.securityUnbanIP(ip);
      toasts.push(`Unbanned ${ip} (${r.unbanned} decisions)`, 'success');
      // Optimistic remove of this IP from local state; next probe
      // confirms.
      setState(removeIPFromState(state!, ip));
    } catch (err) {
      toasts.push(
        err instanceof ApiError ? err.message : 'unban failed',
        'error',
      );
    } finally {
      setBusy(null);
    }
  }

  async function whitelist(ip: string) {
    setBusy(`whitelist:${ip}`);
    try {
      const resp = await api.securityWhitelistAdd(
        'ip',
        ip,
        'Self-rescue from panel banner',
      );
      await api.securityUnbanIP(ip);
      toasts.push(
        `Whitelisted ${ip}. Run \`${resp.reload_command}\` for the whitelist to take effect.`,
        'success',
      );
      setState(removeIPFromState(state!, ip));
    } catch (err) {
      // 409 from already-on-list is fine; still try the unban.
      if (err instanceof ApiError && err.status === 409) {
        try {
          await api.securityUnbanIP(ip);
          toasts.push(
            `${ip} was already whitelisted; unbanned anyway.`,
            'success',
          );
          setState(removeIPFromState(state!, ip));
        } catch (err2) {
          toasts.push(
            err2 instanceof ApiError ? err2.message : 'unban failed',
            'error',
          );
        }
      } else {
        toasts.push(
          err instanceof ApiError ? err.message : 'whitelist failed',
          'error',
        );
      }
    } finally {
      setBusy(null);
    }
  }

  function dismiss() {
    try {
      sessionStorage.setItem(DISMISS_KEY, '1');
    } catch {
      /* private mode etc. */
    }
    setDismissed(true);
  }

  const headline =
    rows.length === 1
      ? '1 of your IPs is currently banned.'
      : `${rows.length} of your IPs are currently banned.`;

  return (
    <div className="bg-amber-950/60 border-b border-amber-800 text-amber-100 px-4 py-3">
      <div className="max-w-6xl mx-auto flex items-start gap-3 text-sm">
        <AlertTriangle className="w-5 h-5 mt-0.5 flex-shrink-0 text-amber-400" />
        <div className="flex-1 min-w-0">
          <div className="flex items-center justify-between gap-3">
            <span className="font-semibold">{headline}</span>
            <button
              type="button"
              onClick={dismiss}
              disabled={busy !== null}
              className="inline-flex items-center gap-1 px-2 py-1 rounded text-amber-200 hover:bg-amber-900/40 text-xs"
              title="Dismiss for this browser session"
            >
              <X className="w-3 h-3" /> Dismiss
            </button>
          </div>
          <ul className="mt-2 space-y-2">
            {rows.map((row) => {
              const reasons = decisionReasons(row.decisions);
              const expiry = soonestExpiry(row.decisions);
              const unbanKey = `unban:${row.ip}`;
              const whitelistKey = `whitelist:${row.ip}`;
              return (
                <li
                  key={row.ip}
                  className="flex flex-wrap items-center gap-2 border-t border-amber-900 pt-2 first:border-t-0 first:pt-0"
                >
                  <div className="flex-1 min-w-[200px]">
                    <span className="font-mono text-amber-200">{row.ip}</span>
                    <span className="ml-2 text-xs text-amber-300">
                      ({SOURCE_LABEL[row.source]})
                    </span>
                    {reasons && (
                      <span className="ml-2 text-amber-200">— {reasons}</span>
                    )}
                    {expiry && (
                      <span className="ml-2 text-amber-200">
                        — expires {expiry}
                      </span>
                    )}
                  </div>
                  <button
                    type="button"
                    onClick={() => unban(row.ip)}
                    disabled={busy !== null}
                    className="px-3 py-1 rounded bg-amber-700 hover:bg-amber-600 disabled:bg-slate-700 text-white text-xs font-medium"
                  >
                    {busy === unbanKey ? 'unbanning…' : 'Unban'}
                  </button>
                  <button
                    type="button"
                    onClick={() => whitelist(row.ip)}
                    disabled={busy !== null}
                    className="px-3 py-1 rounded border border-amber-700 hover:bg-amber-900/40 disabled:opacity-50 text-amber-100 text-xs font-medium"
                  >
                    {busy === whitelistKey
                      ? 'whitelisting…'
                      : 'Whitelist permanently'}
                  </button>
                </li>
              );
            })}
          </ul>
        </div>
      </div>
    </div>
  );
}

// resolveBannedRows turns the multi-IP backend response into a
// flat list of per-IP rows. v1.3.23 backends populate
// `banned_ips`; older shapes fall back to `decisions` keyed on
// `client_ip`.
function resolveBannedRows(
  state: SecurityCheckSelfResponse,
): SecurityBannedIPDetail[] {
  if (state.banned_ips && state.banned_ips.length > 0) {
    return state.banned_ips;
  }
  // v1.3.19 shape fallback.
  if (state.banned && state.client_ip && state.decisions.length > 0) {
    return [
      {
        ip: state.client_ip,
        source: 'current_session',
        decisions: state.decisions,
      },
    ];
  }
  return [];
}

// removeIPFromState produces a new state object with the given
// IP cleared from banned_ips + decisions (when matching) so the
// optimistic UI doesn't flash the row before the next probe
// confirms.
function removeIPFromState(
  prev: SecurityCheckSelfResponse,
  ip: string,
): SecurityCheckSelfResponse {
  const next: SecurityCheckSelfResponse = { ...prev };
  if (next.banned_ips) {
    next.banned_ips = next.banned_ips.filter((r) => r.ip !== ip);
    next.banned_count = next.banned_ips.length;
    next.any_banned = next.banned_ips.length > 0;
  }
  if (next.client_ip === ip) {
    next.banned = false;
    next.decisions = [];
  }
  return next;
}

function decisionReasons(decisions: SecurityDecision[]): string {
  const seen = new Set<string>();
  const out: string[] = [];
  for (const d of decisions) {
    if (d.scenario && !seen.has(d.scenario)) {
      seen.add(d.scenario);
      out.push(d.scenario);
    }
  }
  return out.join(', ');
}

function soonestExpiry(decisions: SecurityDecision[]): string | null {
  let soonest: Date | null = null;
  for (const d of decisions) {
    if (!d.until) continue;
    const t = new Date(d.until);
    if (Number.isNaN(t.getTime())) continue;
    if (!soonest || t < soonest) soonest = t;
  }
  if (!soonest) return null;
  const ms = soonest.getTime() - Date.now();
  if (ms <= 0) return 'soon';
  const m = Math.round(ms / 60_000);
  if (m < 60) return `in ${m} min`;
  const h = Math.round(m / 60);
  if (h < 24) return `in ${h} h`;
  return `in ${Math.round(h / 24)} d`;
}
