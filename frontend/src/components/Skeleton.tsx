// Skeleton placeholders (v1.3.38.5). Rendered only while a view has no
// data at all; a page that has a last-known value keeps showing it and
// refreshes behind it (see api/lastKnown.ts). Every skeleton carries
// data-skeleton so a capture or a smoke can tell "still empty" from
// "painted".

function Block({ className }: { className: string }) {
  return <div className={`animate-pulse rounded bg-slate-800 ${className}`} />;
}

export function SkeletonCards({ count = 4, cols }: { count?: number; cols?: string }) {
  const grid = cols ?? 'grid-cols-2 md:grid-cols-4';
  return (
    <div className={`grid ${grid} gap-3`} data-skeleton="cards" aria-busy="true" aria-hidden="true">
      {Array.from({ length: count }, (_, i) => (
        <div key={i} className="bg-slate-900 border border-slate-800 rounded-lg p-3 space-y-2">
          <Block className="h-3 w-1/2" />
          <Block className="h-6 w-2/3" />
        </div>
      ))}
    </div>
  );
}

export function SkeletonTable({ rows = 8, cols = 6 }: { rows?: number; cols?: number }) {
  return (
    <div className="space-y-2" data-skeleton="table" aria-busy="true" aria-hidden="true">
      <div className="flex gap-3 px-2 py-1">
        {Array.from({ length: cols }, (_, i) => (
          <Block key={i} className="h-3 flex-1" />
        ))}
      </div>
      {Array.from({ length: rows }, (_, r) => (
        <div key={r} className="flex gap-3 px-2 py-1.5 border-t border-slate-800">
          {Array.from({ length: cols }, (_, c) => (
            <Block key={c} className={`h-4 flex-1 ${c % 3 === 1 ? 'opacity-70' : ''}`} />
          ))}
        </div>
      ))}
    </div>
  );
}

export function SkeletonCharts({ count = 2, height = 200 }: { count?: number; height?: number }) {
  return (
    <div className="grid grid-cols-1 lg:grid-cols-2 gap-4" data-skeleton="charts" aria-busy="true" aria-hidden="true">
      {Array.from({ length: count }, (_, i) => (
        <div key={i} className="bg-slate-900 border border-slate-800 rounded-lg p-4 space-y-3">
          <Block className="h-4 w-1/3" />
          <Block className="w-full" />
          <div className="animate-pulse rounded bg-slate-800/60 w-full" style={{ height }} />
        </div>
      ))}
    </div>
  );
}
