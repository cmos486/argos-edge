import { ReactNode, useCallback, useState } from 'react';
import { ToastKind, ToastsContext } from './toastsContext';

interface Toast {
  id: number;
  kind: ToastKind;
  message: string;
}

export default function ToastsProvider({ children }: { children: ReactNode }) {
  const [items, setItems] = useState<Toast[]>([]);

  const push = useCallback((message: string, kind: ToastKind = 'info') => {
    const id = Date.now() + Math.random();
    setItems((prev) => [...prev, { id, kind, message }]);
    setTimeout(() => {
      setItems((prev) => prev.filter((t) => t.id !== id));
    }, 4000);
  }, []);

  return (
    <ToastsContext.Provider value={{ push }}>
      {children}
      <div className="fixed bottom-4 right-4 flex flex-col gap-2 z-50">
        {items.map((t) => (
          <div
            key={t.id}
            className={`px-4 py-2 rounded shadow-lg text-sm border ${toastClass(t.kind)}`}
          >
            {t.message}
          </div>
        ))}
      </div>
    </ToastsContext.Provider>
  );
}

function toastClass(kind: ToastKind): string {
  switch (kind) {
    case 'success':
      return 'bg-emerald-900 border-emerald-700 text-emerald-100';
    case 'error':
      return 'bg-red-900 border-red-700 text-red-100';
    default:
      return 'bg-slate-800 border-slate-600 text-slate-100';
  }
}
