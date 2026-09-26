import type { ReactNode } from 'react';
import type { RangeKey } from '../lib/filters';

// FilterBar (v1.3.42.1): the one row of filter controls every list or
// aggregate page uses, in one order everywhere: range, host, enum
// selects, ip / country / scenario, free text, then whatever the page
// adds through `extra`. The page owns the values (useUrlFilters) and
// the bar only renders and calls back.

export interface RangeField {
  kind: 'range';
  key: string;
  presets: RangeKey[];
}
export interface SelectField {
  kind: 'select';
  key: string;
  label: string; // shown as the empty option ("all sources")
  options: { value: string; label: string }[];
}
export interface TextField {
  kind: 'text';
  key: string;
  placeholder: string;
  mono?: boolean;
  wide?: boolean;
}
export type Field = RangeField | SelectField | TextField;

export const inputCls = 'px-3 py-1.5 rounded bg-slate-800 border border-slate-700 text-sm';

export function FilterBar({
  fields,
  values,
  onChange,
  onReset,
  extra,
}: {
  fields: Field[];
  values: Record<string, string | number | boolean>;
  // push: true for range and selects (a new history entry), false for keystrokes
  onChange: (patch: Record<string, string | number | boolean>, push: boolean) => void;
  onReset?: () => void;
  extra?: ReactNode;
}) {
  const dirty = fields.some((f) => {
    const v = values[f.key];
    return f.kind === 'range' ? false : v !== '' && v !== undefined;
  });
  return (
    <div className="flex flex-wrap items-center gap-2 mb-3 text-sm" role="search">
      {fields.map((f) => {
        if (f.kind === 'range') {
          const cur = String(values[f.key] ?? '');
          return (
            <div key={f.key} className="flex items-center gap-1">
              <span className="text-slate-400 mr-1">Range:</span>
              {f.presets.map((k) => (
                <button
                  type="button"
                  key={k}
                  onClick={() => onChange({ [f.key]: k }, true)}
                  className={`px-2 py-0.5 rounded text-xs ${
                    cur === k ? 'bg-sky-900 text-sky-200' : 'border border-slate-700 hover:bg-slate-800'
                  }`}
                >
                  {k}
                </button>
              ))}
            </div>
          );
        }
        if (f.kind === 'select') {
          return (
            <select
              key={f.key}
              value={String(values[f.key] ?? '')}
              onChange={(e) => onChange({ [f.key]: e.target.value }, true)}
              className={inputCls}
              aria-label={f.label}
            >
              <option value="">{f.label}</option>
              {f.options.map((o) => (
                <option key={o.value} value={o.value}>
                  {o.label}
                </option>
              ))}
            </select>
          );
        }
        return (
          <input
            key={f.key}
            type="text"
            value={String(values[f.key] ?? '')}
            placeholder={f.placeholder}
            onChange={(e) => onChange({ [f.key]: e.target.value }, false)}
            className={`${inputCls} ${f.mono ? 'font-mono' : ''} ${f.wide ? 'min-w-[16rem]' : 'min-w-[9rem]'}`}
            aria-label={f.placeholder}
          />
        );
      })}
      {extra}
      {onReset && dirty && (
        <button type="button" onClick={onReset} className="text-xs text-slate-400 hover:text-slate-200 underline">
          clear
        </button>
      )}
    </div>
  );
}
