// WorldMap renders a world choropleth colored by per-country hit
// counts. Consumer of the Dashboard's security.by_country payload.
//
// Design notes:
//
//   - Topology is imported INLINE from world-atlas (110m resolution,
//     ~108 KiB raw). Inline beats a runtime fetch: no CDN
//     dependency at panel-startup, no CORS surprise, the file lives
//     next to the bundle in argos's embedded static FS.
//
//   - The backend emits ISO 3166-1 alpha-2 codes ("US", "ES"); the
//     topology keys features by numeric ISO ("840", "724"). We
//     bridge via iso3166.ts which is a static 2 KiB table.
//
//   - Color uses a LOG scale. Attack distributions are near-power-
//     law (one or two countries account for 80%+ of hits), and a
//     linear ramp washes everything but the top 1-2 into the base
//     color. Log stretches the middle of the distribution so the
//     map tells a useful story even on quiet days.
//
//   - No react-tooltip dep: a small absolutely-positioned div
//     tracks the hovered country + mouse coordinates. Works the
//     same in dark mode without extra CSS plumbing.
//
// Deliberately NOT implemented here (spec's FUERA DE SCOPE list):
// zoom/pan, drill-down-by-click, ASN overlays, temporal filters.

import { useMemo, useState, MouseEvent } from 'react';
import { ComposableMap, Geographies, Geography } from 'react-simple-maps';
import worldAtlas from 'world-atlas/countries-110m.json';
import { ISO2_TO_NUMERIC } from './iso3166';

interface Props {
  data: Record<string, number>;
  colorScale?: [string, string];
  onCountryClick?: (iso2: string) => void;
  height?: number;
}

// Default palette picked to match the panel's slate-950 background
// (dark blue, almost black) ramping up to the sky-500 accent used by
// every other dashboard highlight. Callers may override via prop.
const DEFAULT_SCALE: [string, string] = ['#1e293b', '#3b82f6'];

// Fill used for countries that HAVE geometry in the topology but NO
// entry in the data map. One step darker than the low end of the
// color ramp so the difference between "zero hits" and "lowest
// bucket of hits" stays legible.
const NO_DATA_FILL = '#0f172a';

// Stroke used on every country outline. Dark enough to be subtle
// against NO_DATA_FILL but visible against higher-intensity fills.
const STROKE = '#334155';

export default function WorldMap({
  data,
  colorScale = DEFAULT_SCALE,
  onCountryClick,
  height = 340,
}: Props) {
  // NUMERIC_TO_ISO2 is the inverse of the ISO2_TO_NUMERIC lookup we
  // already import. Built once per component instance because the
  // lookup runs per-feature on every render of Geographies.
  const numericToISO2 = useMemo(() => {
    const out: Record<string, string> = {};
    for (const [iso2, num] of Object.entries(ISO2_TO_NUMERIC)) {
      out[num] = iso2;
    }
    return out;
  }, []);

  // Precompute the data map keyed by numeric code so the Geography
  // loop below is a single dictionary lookup per feature.
  const byNumeric = useMemo(() => {
    const out: Record<string, number> = {};
    for (const [iso2, count] of Object.entries(data)) {
      const num = ISO2_TO_NUMERIC[iso2.toUpperCase()];
      if (num) out[num] = count;
    }
    return out;
  }, [data]);

  // Max hit count drives the top of the log scale.
  const maxHits = useMemo(() => {
    let m = 0;
    for (const v of Object.values(data)) if (v > m) m = v;
    return m;
  }, [data]);

  const [hover, setHover] = useState<{
    x: number;
    y: number;
    name: string;
    hits: number;
  } | null>(null);

  function fillFor(numericId: string | number | undefined): string {
    if (numericId === undefined) return NO_DATA_FILL;
    const key = String(numericId).padStart(3, '0');
    const hits = byNumeric[key];
    if (hits === undefined || hits <= 0 || maxHits <= 0) return NO_DATA_FILL;
    // log(x+1) / log(max+1) squashes one-big-spike distributions.
    const t = Math.log(hits + 1) / Math.log(maxHits + 1);
    return lerpColor(colorScale[0], colorScale[1], t);
  }

  function handleMove(e: MouseEvent<SVGPathElement>, name: string, hits: number) {
    // The tooltip is positioned relative to the wrapper div, not the
    // SVG, so use offsetX/Y. Native SVG mouse events expose layerX/Y
    // in most browsers but not consistently -- fallback to clientX/Y
    // minus the wrapper's bounding rect via a current-target ref.
    const rect = e.currentTarget.ownerSVGElement?.getBoundingClientRect();
    if (!rect) return;
    setHover({
      x: e.clientX - rect.left,
      y: e.clientY - rect.top,
      name,
      hits,
    });
  }

  return (
    <div className="relative w-full" style={{ height }}>
      <ComposableMap
        projection="geoEqualEarth"
        projectionConfig={{ scale: 155 }}
        width={900}
        height={height}
        style={{ width: '100%', height: '100%', background: 'transparent' }}
      >
        <Geographies geography={worldAtlas}>
          {({ geographies }) =>
            geographies.map((geo) => {
              const numeric = geo.id as string | number | undefined;
              const iso2 =
                numeric !== undefined
                  ? numericToISO2[String(numeric).padStart(3, '0')] ?? ''
                  : '';
              const name =
                (geo.properties as { name?: string }).name ?? iso2 ?? '?';
              const hits =
                iso2 && data[iso2] !== undefined ? data[iso2] : 0;
              return (
                <Geography
                  key={geo.rsmKey}
                  geography={geo}
                  fill={fillFor(numeric)}
                  stroke={STROKE}
                  strokeWidth={0.35}
                  style={{
                    default: { outline: 'none', transition: 'fill 120ms' },
                    hover: {
                      outline: 'none',
                      fill: hits > 0 ? '#60a5fa' : '#475569',
                    },
                    pressed: { outline: 'none' },
                  }}
                  onMouseMove={(e: MouseEvent<SVGPathElement>) =>
                    handleMove(e, name, hits)
                  }
                  onMouseLeave={() => setHover(null)}
                  onClick={
                    onCountryClick && iso2
                      ? () => onCountryClick(iso2)
                      : undefined
                  }
                />
              );
            })
          }
        </Geographies>
      </ComposableMap>

      {hover && (
        <div
          className="pointer-events-none absolute z-10 rounded border border-slate-700 bg-slate-900/95 px-2 py-1 text-xs text-slate-100 shadow-lg"
          style={{
            left: hover.x + 10,
            top: hover.y + 10,
          }}
        >
          <span className="font-medium">{hover.name}</span>
          <span className="mx-1 text-slate-500">·</span>
          <span className="font-mono">
            {hover.hits} {hover.hits === 1 ? 'hit' : 'hits'}
          </span>
        </div>
      )}
    </div>
  );
}

// lerpColor interpolates between two hex-RGB colors. 't' is clamped
// to [0, 1]. Stays inside this file because the rest of the panel
// uses Tailwind classes and never needed a runtime color helper.
function lerpColor(a: string, b: string, t: number): string {
  const tt = t < 0 ? 0 : t > 1 ? 1 : t;
  const [ar, ag, ab] = parseHex(a);
  const [br, bg, bb] = parseHex(b);
  const r = Math.round(ar + (br - ar) * tt);
  const g = Math.round(ag + (bg - ag) * tt);
  const bl = Math.round(ab + (bb - ab) * tt);
  return `rgb(${r}, ${g}, ${bl})`;
}

function parseHex(c: string): [number, number, number] {
  // Accept "#rrggbb" or "rrggbb" or "#rgb". Anything else falls back
  // to slate-800 so a typo on the caller side doesn't crash the map.
  const s = c.replace(/^#/, '').trim();
  if (s.length === 3) {
    const r = parseInt(s[0]! + s[0]!, 16);
    const g = parseInt(s[1]! + s[1]!, 16);
    const b = parseInt(s[2]! + s[2]!, 16);
    return [r, g, b];
  }
  if (s.length === 6) {
    return [
      parseInt(s.slice(0, 2), 16),
      parseInt(s.slice(2, 4), 16),
      parseInt(s.slice(4, 6), 16),
    ];
  }
  return [30, 41, 59]; // slate-800
}
