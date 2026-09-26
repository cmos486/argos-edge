import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import { parseValues, serializeValues, type Schema, type Values } from '../lib/filters';

// useUrlFilters (v1.3.42.1) keeps a page's filter state in the URL so a
// link, a reload and the browser's back button reproduce the view.
//
// - `values` is what the URL says right now (validated by the schema,
//   defaults filled in). It follows the URL, so a second in-app link
//   to the same page with other params updates the page (the old
//   pages read the URL once in a useState initialiser and ignored it
//   afterwards).
// - `set(patch, { push })` writes the URL. Keystrokes use replace (no
//   history entry per character); range, tab, page and select changes
//   use push so back walks views.
// - `debounced` is `values` with the text fields held back 300 ms, for
//   the fetch effect; selects and ranges pass through at once.
// - `reset()` clears every field to its default.

const TEXT_DEBOUNCE_MS = 300;

export interface SetOptions {
  push?: boolean;
}

export function useUrlFilters<S extends Schema>(schema: S) {
  const [params, setParams] = useSearchParams();
  const values = useMemo(() => parseValues(schema, params), [schema, params]);

  // Two set() calls in one event handler must both land: patches are
  // accumulated until the URL change has rendered.
  const pending = useRef<Partial<Values<S>>>({});
  useEffect(() => {
    pending.current = {};
  }, [params]);

  const set = useCallback(
    (patch: Partial<Values<S>>, opts: SetOptions = {}) => {
      pending.current = { ...pending.current, ...patch };
      const next = { ...parseValues(schema, params), ...pending.current } as Values<S>;
      const pairs = serializeValues(schema, next);
      setParams(new URLSearchParams(pairs), { replace: !opts.push });
    },
    [schema, params, setParams],
  );

  const reset = useCallback(() => {
    setParams(new URLSearchParams(), { replace: false });
  }, [setParams]);

  // Text fields are debounced for fetching; everything else is
  // immediate. The debounced copy starts equal to the URL so the first
  // fetch of a deep link does not wait.
  const textKeys = useMemo(
    () => Object.entries(schema).filter(([, spec]) => spec.kind === 'text').map(([k]) => k),
    [schema],
  );
  const [debounced, setDebounced] = useState<Values<S>>(values);
  const timer = useRef<ReturnType<typeof setTimeout> | null>(null);
  useEffect(() => {
    const textChanged = textKeys.some(
      (k) => (values as Record<string, unknown>)[k] !== (debounced as Record<string, unknown>)[k],
    );
    const otherChanged = Object.keys(schema).some(
      (k) => !textKeys.includes(k) && (values as Record<string, unknown>)[k] !== (debounced as Record<string, unknown>)[k],
    );
    if (!textChanged && !otherChanged) return;
    if (timer.current) clearTimeout(timer.current);
    if (textChanged) {
      timer.current = setTimeout(() => setDebounced(values), TEXT_DEBOUNCE_MS);
    } else {
      setDebounced(values);
    }
    return () => {
      if (timer.current) clearTimeout(timer.current);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [values]);

  return { values, debounced, set, reset };
}
