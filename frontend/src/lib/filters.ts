// Shared filter vocabulary (v1.3.42.1). Pure functions, no React and
// no DOM, so `npm run test:lib` can run them under node:test.
//
// One set of names is used in the URL of every page and in the API
// calls; where an endpoint still takes its own parameter (dashboard
// `range`, appsec `window`, logs/deliveries `from`/`to`) the
// translation lives here and nowhere else, so v1.3.42.2 removes it in
// one commit.

export type RangeKey = '15m' | '1h' | '6h' | '12h' | '24h' | '7d' | '30d';

export const ALL_RANGES: RangeKey[] = ['15m', '1h', '6h', '12h', '24h', '7d', '30d'];

const RANGE_MINUTES: Record<RangeKey, number> = {
  '15m': 15,
  '1h': 60,
  '6h': 360,
  '12h': 720,
  '24h': 1440,
  '7d': 10080,
  '30d': 43200,
};

export function isRangeKey(v: string | null | undefined): v is RangeKey {
  return !!v && (ALL_RANGES as string[]).includes(v);
}

export function rangeMinutes(r: RangeKey): number {
  return RANGE_MINUTES[r];
}

// rangeFrom: the `from` ISO timestamp for endpoints that take
// from/to (logs, deliveries). `now` is injectable for tests.
export function rangeFrom(r: RangeKey, now: Date = new Date()): string {
  return new Date(now.getTime() - RANGE_MINUTES[r] * 60_000).toISOString();
}

// rangeToDash maps to the dashboard's `range` param (1h/6h/24h/7d);
// values the dashboard does not have collapse to the nearest larger
// preset it serves.
export type DashRangeKey = '1h' | '6h' | '24h' | '7d';
export function rangeToDash(r: RangeKey): DashRangeKey {
  switch (r) {
    case '15m':
    case '1h':
      return '1h';
    case '6h':
      return '6h';
    case '12h':
    case '24h':
      return '24h';
    default:
      return '7d';
  }
}

// rangeToAppSecWindow maps to the AppSec metrics `window` (1h/6h/12h/24h).
export type AppSecWindowKey = '1h' | '6h' | '12h' | '24h';
export function rangeToAppSecWindow(r: RangeKey): AppSecWindowKey {
  switch (r) {
    case '15m':
    case '1h':
      return '1h';
    case '6h':
      return '6h';
    case '12h':
      return '12h';
    default:
      return '24h';
  }
}

// pickRange narrows an incoming value to the presets a page mounts,
// falling back to the page default.
export function pickRange(v: string | null | undefined, allowed: RangeKey[], fallback: RangeKey): RangeKey {
  if (isRangeKey(v) && allowed.includes(v)) return v;
  return fallback;
}

// --- URL schema ---------------------------------------------------------

export type FieldSpec =
  | { kind: 'range'; allowed: RangeKey[]; default: RangeKey }
  | { kind: 'text'; default?: string } // free text, debounced in the UI
  | { kind: 'enum'; values: string[]; default?: string } // select; unknown -> default
  | { kind: 'int'; default: number; min?: number; max?: number }
  | { kind: 'bool'; default?: boolean };

export type Schema = Record<string, FieldSpec>;

export type Values<S extends Schema> = {
  [K in keyof S]: S[K] extends { kind: 'range' }
    ? RangeKey
    : S[K] extends { kind: 'int' }
      ? number
      : S[K] extends { kind: 'bool' }
        ? boolean
        : string;
};

function fieldDefault(spec: FieldSpec): string | number | boolean {
  switch (spec.kind) {
    case 'range':
      return spec.default;
    case 'int':
      return spec.default;
    case 'bool':
      return spec.default ?? false;
    default:
      return spec.default ?? '';
  }
}

// parseValues reads a schema from URLSearchParams-like input (anything
// with get()). Unknown or invalid values fall back to the default.
export function parseValues<S extends Schema>(schema: S, params: { get(name: string): string | null }): Values<S> {
  const out: Record<string, string | number | boolean> = {};
  for (const [name, spec] of Object.entries(schema)) {
    const raw = params.get(name);
    switch (spec.kind) {
      case 'range':
        out[name] = pickRange(raw, spec.allowed, spec.default);
        break;
      case 'enum':
        out[name] = raw !== null && spec.values.includes(raw) ? raw : (spec.default ?? '');
        break;
      case 'int': {
        const n = raw === null ? NaN : parseInt(raw, 10);
        let v = Number.isFinite(n) ? n : spec.default;
        if (spec.min !== undefined && v < spec.min) v = spec.default;
        if (spec.max !== undefined && v > spec.max) v = spec.default;
        out[name] = v;
        break;
      }
      case 'bool':
        out[name] = raw === null ? (spec.default ?? false) : raw === '1' || raw === 'true';
        break;
      default:
        out[name] = raw ?? spec.default ?? '';
    }
  }
  return out as Values<S>;
}

// serializeValues writes only the fields that differ from their
// default, so a URL stays short and a bookmark of the default view is
// the bare route.
export function serializeValues<S extends Schema>(schema: S, values: Values<S>): [string, string][] {
  const out: [string, string][] = [];
  for (const [name, spec] of Object.entries(schema)) {
    const v = (values as Record<string, string | number | boolean>)[name];
    const d = fieldDefault(spec);
    if (v === d || v === '' || v === undefined) continue;
    if (spec.kind === 'bool') {
      if (v) out.push([name, '1']);
      continue;
    }
    out.push([name, String(v)]);
  }
  return out;
}

// --- global search classifier ----------------------------------------

export type SearchKind = 'ip' | 'domain' | 'scenario' | 'text';

const IPV4 = /^(\d{1,3}\.){3}\d{1,3}(\/\d{1,2})?$/;
const IPV6 = /^[0-9a-f:]+(\/\d{1,3})?$/i;
const HOSTNAME = /^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/i;
const SCENARIO = /^[a-z0-9_-]+\/[a-z0-9._-]+$/i;
const CRS_ID = /^\d{6}$/;

// classifySearch decides where a pasted value belongs. An IPv6 needs
// at least two colons so "a:b" style typos stay text.
export function classifySearch(raw: string): { kind: SearchKind; value: string } {
  const value = raw.trim();
  if (value === '') return { kind: 'text', value };
  if (IPV4.test(value)) return { kind: 'ip', value };
  if (value.includes('::') || (value.split(':').length >= 3 && IPV6.test(value))) return { kind: 'ip', value: value.toLowerCase() };
  if (SCENARIO.test(value) || CRS_ID.test(value)) return { kind: 'scenario', value };
  if (HOSTNAME.test(value)) return { kind: 'domain', value: value.toLowerCase() };
  return { kind: 'text', value };
}
