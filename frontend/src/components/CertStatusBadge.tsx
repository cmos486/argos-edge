import { Cert } from '../api/client';

// Shared badge used by both Active and Imported cert tables so the
// color thresholds stay identical on both surfaces.
export function CertStatusBadge({ status }: { status: Cert['status'] }) {
  const cls: Record<Cert['status'], string> = {
    ok: 'bg-emerald-900 text-emerald-200',
    warning: 'bg-amber-900 text-amber-200',
    critical: 'bg-red-900 text-red-200',
    expired: 'bg-red-950 text-red-300',
    unknown: 'bg-slate-800 text-slate-400',
  };
  return <span className={`text-xs px-2 py-0.5 rounded ${cls[status]}`}>{status}</span>;
}
