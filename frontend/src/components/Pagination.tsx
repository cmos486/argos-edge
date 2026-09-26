// Page-based pagination control for server-paged lists (v1.3.38.5,
// first used by Threats). Renders nothing when everything fits on one
// page.
export default function Pagination({
  page,
  pages,
  total,
  perPage,
  onChange,
}: {
  page: number;
  pages: number;
  total: number;
  perPage: number;
  onChange: (page: number) => void;
}) {
  if (pages <= 1) return null;
  const first = (page - 1) * perPage + 1;
  const last = Math.min(total, page * perPage);
  return (
    <div className="mt-3 flex items-center gap-2 text-sm" data-pagination>
      <button
        type="button"
        onClick={() => onChange(page - 1)}
        disabled={page <= 1}
        className="px-3 py-1 rounded border border-slate-700 text-slate-300 hover:bg-slate-800 disabled:opacity-50"
      >
        Prev
      </button>
      <span className="text-xs text-slate-500">
        Page {page} of {pages} ({first}-{last} of {total.toLocaleString()})
      </span>
      <button
        type="button"
        onClick={() => onChange(page + 1)}
        disabled={page >= pages}
        className="px-3 py-1 rounded border border-slate-700 text-slate-300 hover:bg-slate-800 disabled:opacity-50"
      >
        Next
      </button>
    </div>
  );
}
