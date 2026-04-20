import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

// manualChunks groups node_modules paths into named vendor chunks.
// The goal is NOT per-dep chunks (that balloons request count); it's
// to isolate big, cold libs from the hot main+app bundle so:
//   - returning users hit cache for react-vendor across app releases
//   - the browser only downloads "charts" / "map" / "dnd" when a page
//     that uses them actually mounts
//   - the login-eager bundle stays small (no recharts, no map topology)
function vendorChunk(id: string): string | undefined {
  if (!id.includes('node_modules')) return undefined;
  // React core + router -- always loaded, always cached long-term.
  if (
    id.includes('node_modules/react/') ||
    id.includes('node_modules/react-dom/') ||
    id.includes('node_modules/react-router/') ||
    id.includes('node_modules/react-router-dom/') ||
    id.includes('node_modules/scheduler/')
  ) {
    return 'react-vendor';
  }
  // Charts: recharts + its d3-* peers. Used by /dashboard, /appsec,
  // /threats. Splitting the d3-geo subset off into the map chunk
  // keeps the per-page surface tighter.
  if (
    id.includes('node_modules/recharts') ||
    id.includes('node_modules/victory-') ||
    id.includes('node_modules/d3-scale') ||
    id.includes('node_modules/d3-shape') ||
    id.includes('node_modules/d3-array') ||
    id.includes('node_modules/d3-path') ||
    id.includes('node_modules/d3-time') ||
    id.includes('node_modules/d3-format') ||
    id.includes('node_modules/d3-interpolate') ||
    id.includes('node_modules/d3-color')
  ) {
    return 'charts';
  }
  // Map: world topology + rendering primitives. Only Dashboard imports
  // this; combined with React.lazy on WorldMap it ships only when the
  // dashboard's security card renders.
  if (
    id.includes('node_modules/react-simple-maps') ||
    id.includes('node_modules/d3-geo') ||
    id.includes('node_modules/d3-selection') ||
    id.includes('node_modules/topojson-client') ||
    id.includes('node_modules/world-atlas')
  ) {
    return 'map';
  }
  // lucide-react is tree-shaken but we still import ~40 icons across
  // the app -- pinning them in their own chunk pays cache mileage
  // even after a code change in pages/.
  if (id.includes('node_modules/lucide-react')) {
    return 'icons';
  }
  // @dnd-kit/* is only needed by /target-groups (target reorder) and
  // /hosts/:id/rules (rule reorder). Splitting it off keeps every
  // other route free of the drag-and-drop runtime.
  if (id.includes('node_modules/@dnd-kit/')) {
    return 'dnd';
  }
  // Anything else in node_modules stays with whichever chunk imports
  // it. We deliberately avoid a catch-all "vendor" chunk because
  // that re-creates the "one giant bundle" anti-pattern.
  return undefined;
}

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      '/api': {
        target: 'http://localhost:8080',
        changeOrigin: false,
      },
    },
  },
  build: {
    outDir: 'dist',
    sourcemap: false,
    emptyOutDir: true,
    // CSS code splitting is Vite's default; making it explicit so an
    // accidental false does not slip into a future change.
    cssCodeSplit: true,
    rollupOptions: {
      output: {
        manualChunks: vendorChunk,
      },
    },
  },
});
