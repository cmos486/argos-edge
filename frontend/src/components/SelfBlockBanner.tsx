import { useCallback, useEffect, useState } from 'react';
import { AlertTriangle, X } from 'lucide-react';
import {
  api,
  ApiError,
  SecurityCheckSelfResponse,
  SecurityDecision,
} from '../api/client';
import { useToasts } from './toastsContext';

// SelfBlockBanner — v1.3.19 escape hatch.
//
// Renders a yellow full-width banner above page content whenever
// the panel detects that the caller's resolved client IP is in
// CrowdSec's active decision list. The check fires once on mount
// and re-polls every 60s so a ban that lands mid-session surfaces
// without the operator having to refresh.
//
// Three actions:
//   * Unban my IP        -> POST /api/security/decisions/unban-ip
//                           with the resolved IP. LAPI takes effect
//                           on next bouncer poll (~15s) and on the
//                           next request to the bouncer. The banner
//                           hides immediately on success and the
//                           next probe in 60s confirms.
//   * Whitelist my IP    -> POST /api/security/whitelist  AND
//                           the unban above. Persists the IP so a
//                           future ban for the same IP will be
//                           filtered by CrowdSec's whitelist
//                           parser. Requires a manual
//                           setup-appsec.sh re-run for the
//                           whitelist file to be consumed -- the
//                           toast surfaces the exact command.
//   * Dismiss            -> sessionStorage flag. Banner stays
//                           hidden for the rest of this browser
//                           session even if a new poll detects
//                           the ban is still active.

const DISMISS_KEY = 'argos.selfblock.dismissed';
const POLL_MS = 60_000;

export default function SelfBlockBanner() {
  const toasts = useToasts();
  const [state, setState] = useState<SecurityCheckSelfResponse | null>(null);
  const [busy, setBusy] = useState<'unban' | 'whitelist' | null>(null);
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

  if (dismissed || !state || !state.banned || state.client_ip === '') {
    return null;
  }

  const reasons = decisionReasons(state.decisions);
  const expiry = soonestExpiry(state.decisions);

  async function onUnban() {
    if (!state) return;
    setBusy('unban');
    try {
      await api.securityUnbanIP(state.client_ip);
      toasts.push(`Unbanned ${state.client_ip}`, 'success');
      // Optimistically clear -- next probe will confirm.
      setState({ ...state, banned: false, decisions: [] });
    } catch (err) {
      toasts.push(
        err instanceof ApiError ? err.message : 'unban failed',
        'error',
      );
    } finally {
      setBusy(null);
    }
  }

  async function onWhitelist() {
    if (!state) return;
    setBusy('whitelist');
    try {
      // Whitelist first -- persist the entry before the unban
      // takes effect, so a second ban arriving in the gap is
      // filtered.
      const resp = await api.securityWhitelistAdd(
        'ip',
        state.client_ip,
        'Self-rescue from panel banner',
      );
      await api.securityUnbanIP(state.client_ip);
      toasts.push(
        `Whitelisted ${state.client_ip}. Run \`${resp.reload_command}\` for the whitelist to take effect.`,
        'success',
      );
      setState({ ...state, banned: false, decisions: [] });
    } catch (err) {
      // 409 from already-on-list is fine -- still try the unban
      // so the operator gets out.
      if (err instanceof ApiError && err.status === 409) {
        try {
          await api.securityUnbanIP(state.client_ip);
          toasts.push(
            `${state.client_ip} was already whitelisted; unbanned anyway.`,
            'success',
          );
          setState({ ...state, banned: false, decisions: [] });
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

  function onDismiss() {
    try {
      sessionStorage.setItem(DISMISS_KEY, '1');
    } catch {
      /* private mode etc. */
    }
    setDismissed(true);
  }

  return (
    <div className="bg-amber-950/60 border-b border-amber-800 text-amber-100 px-4 py-3">
      <div className="max-w-6xl mx-auto flex items-start gap-3 text-sm">
        <AlertTriangle className="w-5 h-5 mt-0.5 flex-shrink-0 text-amber-400" />
        <div className="flex-1 min-w-0">
          <div>
            <span className="font-semibold">Your IP is currently banned.</span>{' '}
            <span className="font-mono text-amber-200">{state.client_ip}</span>
            {reasons && (
              <>
                {' — '}
                <span className="text-amber-200">{reasons}</span>
              </>
            )}
            {expiry && (
              <>
                {' — '}
                <span className="text-amber-200">expires {expiry}</span>
              </>
            )}
            .
          </div>
          <div className="mt-2 flex flex-wrap gap-2">
            <button
              type="button"
              onClick={onUnban}
              disabled={busy !== null}
              className="px-3 py-1 rounded bg-amber-700 hover:bg-amber-600 disabled:bg-slate-700 text-white text-xs font-medium"
            >
              {busy === 'unban' ? 'unbanning…' : 'Unban my IP'}
            </button>
            <button
              type="button"
              onClick={onWhitelist}
              disabled={busy !== null}
              className="px-3 py-1 rounded border border-amber-700 hover:bg-amber-900/40 disabled:opacity-50 text-amber-100 text-xs font-medium"
            >
              {busy === 'whitelist'
                ? 'whitelisting…'
                : 'Whitelist my IP permanently'}
            </button>
            <button
              type="button"
              onClick={onDismiss}
              disabled={busy !== null}
              className="ml-auto inline-flex items-center gap-1 px-2 py-1 rounded text-amber-200 hover:bg-amber-900/40 text-xs"
              title="Dismiss for this browser session"
            >
              <X className="w-3 h-3" /> Dismiss
            </button>
          </div>
        </div>
      </div>
    </div>
  );
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
