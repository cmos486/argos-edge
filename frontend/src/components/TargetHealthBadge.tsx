import { Check, HelpCircle, X } from 'lucide-react';
import { TargetHealth } from '../api/client';

// v1.3.7 target-health badge. Shows a single-glance verdict plus a
// compact secondary hint: status code for HTTP-level failures, the
// truncated error string for network-level failures.
//
// The full timestamp + error live in the title attribute so hovering
// any badge reveals the same detail the operator would previously
// have had to open Logs to find.

const STATUS_CLASS: Record<TargetHealth['status'], string> = {
  healthy: 'bg-emerald-900 text-emerald-200 border-emerald-800',
  unhealthy: 'bg-red-900 text-red-200 border-red-800',
  unknown: 'bg-slate-800 text-slate-400 border-slate-700',
};

const STATUS_LABEL: Record<TargetHealth['status'], string> = {
  healthy: 'healthy',
  unhealthy: 'unhealthy',
  unknown: 'unknown',
};

// Truncate long error strings for the inline hint; the full error is
// in the tooltip. 32 chars keeps one-line rows readable on medium
// viewports without breaking the table layout.
function shortHint(h: TargetHealth): string {
  if (h.status === 'unhealthy') {
    if (h.last_status_code != null) return String(h.last_status_code);
    if (h.last_error) {
      return h.last_error.length > 32 ? h.last_error.slice(0, 32) + '...' : h.last_error;
    }
  }
  if (h.status === 'healthy' && h.num_requests > 0) {
    return `${h.num_requests} in-flight`;
  }
  return '';
}

function tooltip(h: TargetHealth): string {
  const parts: string[] = [];
  if (h.last_checked_at) {
    const d = new Date(h.last_checked_at);
    parts.push(`Last checked: ${d.toLocaleString()}`);
  } else {
    parts.push('No probe data yet');
  }
  if (h.last_status_code != null) parts.push(`Status: ${h.last_status_code}`);
  if (h.last_error) parts.push(`Error: ${h.last_error}`);
  if (h.num_requests > 0 || h.num_fails > 0) {
    parts.push(`In-flight: ${h.num_requests} / Fails: ${h.num_fails}`);
  }
  return parts.join('\n');
}

export function TargetHealthBadge({ health }: { health?: TargetHealth | null }) {
  // No data yet: render a placeholder identical to the unknown state
  // rather than a spinner. The row should not flicker between polls.
  if (!health) {
    return (
      <span
        className="inline-flex items-center gap-1 text-xs px-2 py-0.5 rounded border bg-slate-800 text-slate-400 border-slate-700"
        title="No data yet"
      >
        <HelpCircle className="w-3 h-3" /> unknown
      </span>
    );
  }
  const cls = STATUS_CLASS[health.status];
  const label = STATUS_LABEL[health.status];
  const hint = shortHint(health);
  const icon =
    health.status === 'healthy' ? (
      <Check className="w-3 h-3" />
    ) : health.status === 'unhealthy' ? (
      <X className="w-3 h-3" />
    ) : (
      <HelpCircle className="w-3 h-3" />
    );
  return (
    <span
      className={`inline-flex items-center gap-1 text-xs px-2 py-0.5 rounded border ${cls}`}
      title={tooltip(health)}
    >
      {icon}
      <span>{label}</span>
      {hint && <span className="opacity-70 font-mono ml-1">{hint}</span>}
    </span>
  );
}
