// RelativeTime renders a timestamp as a human-friendly distance
// ("2 hours ago", "yesterday", "3 days ago") with the full absolute
// timestamp surfaced via the HTML `title` attribute. Hover tooltip
// comes for free from the browser -- no JS popover library.
//
// Two modes:
//   * default: always relative.
//   * thresholdHours > 0: relative when the delta is within the
//     threshold; absolute (YYYY-MM-DD HH:MM:SS in local TZ) otherwise.
//     Used on log rows so recent events read naturally but older
//     entries keep forensic precision in the main text.
//
// The component re-renders at most once a minute so a page left open
// does not stick to a stale "a minute ago" label. Granularity matches
// formatDistanceToNow's smallest unit.
import { useEffect, useState } from 'react';
import { formatDistanceToNow } from 'date-fns';

interface Props {
  iso: string | null | undefined;
  // When set, a delta above this threshold renders the absolute
  // timestamp in the visible text. Tooltip still carries the
  // absolute value either way.
  thresholdHours?: number;
  // Fallback rendered when iso is empty / unparseable. Defaults to
  // an em dash so table cells keep a width.
  fallback?: string;
  className?: string;
}

function formatAbsolute(d: Date): string {
  // YYYY-MM-DD HH:MM:SS in the browser's local TZ. Matches what the
  // panel already uses in forensic contexts (Logs, audit drawer).
  const pad = (n: number) => n.toString().padStart(2, '0');
  return (
    d.getFullYear() +
    '-' +
    pad(d.getMonth() + 1) +
    '-' +
    pad(d.getDate()) +
    ' ' +
    pad(d.getHours()) +
    ':' +
    pad(d.getMinutes()) +
    ':' +
    pad(d.getSeconds())
  );
}

export default function RelativeTime({
  iso,
  thresholdHours,
  fallback = '—',
  className,
}: Props) {
  // Force a re-render every minute so "a minute ago" -> "2 minutes
  // ago" -> ... rolls on its own. Tick identity does not matter; we
  // just need React to notice.
  const [, setTick] = useState(0);
  useEffect(() => {
    if (!iso) return;
    const id = setInterval(() => setTick((t) => t + 1), 60_000);
    return () => clearInterval(id);
  }, [iso]);

  if (!iso) {
    return <span className={className}>{fallback}</span>;
  }
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) {
    return <span className={className}>{fallback}</span>;
  }

  const absolute = formatAbsolute(d);
  const deltaMs = Math.abs(Date.now() - d.getTime());
  const overThreshold =
    typeof thresholdHours === 'number' &&
    thresholdHours > 0 &&
    deltaMs > thresholdHours * 3600 * 1000;

  const visible = overThreshold
    ? absolute
    : formatDistanceToNow(d, { addSuffix: true });

  return (
    <time dateTime={d.toISOString()} title={absolute} className={className}>
      {visible}
    </time>
  );
}
