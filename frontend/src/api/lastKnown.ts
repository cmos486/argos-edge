// In-memory last-known responses (v1.3.38.5).
//
// Pages seed their state from here on mount, keyed by their own
// endpoint + query string, so a revisit paints the previous data at
// once and refreshes behind it instead of showing a skeleton. Memory
// only: it lives as long as the tab and is dropped with the session
// (forgetSession in client.ts) so nothing from one login shows under
// the next.
const store = new Map<string, unknown>();

export function getLastKnown<T>(key: string): T | null {
  const v = store.get(key);
  return v === undefined ? null : (v as T);
}

export function setLastKnown<T>(key: string, value: T): void {
  store.set(key, value);
}

export function clearLastKnown(): void {
  store.clear();
}
