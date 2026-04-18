import { createContext, useContext } from 'react';

export type ToastKind = 'success' | 'error' | 'info';

export interface ToastsApi {
  push(message: string, kind?: ToastKind): void;
}

export const ToastsContext = createContext<ToastsApi | null>(null);

export function useToasts(): ToastsApi {
  const ctx = useContext(ToastsContext);
  if (!ctx) throw new Error('useToasts outside ToastsProvider');
  return ctx;
}
