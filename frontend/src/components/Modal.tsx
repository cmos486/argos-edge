import { ReactNode, useEffect } from 'react';
import { X } from 'lucide-react';

interface Props {
  open: boolean;
  title: string;
  onClose: () => void;
  children: ReactNode;
}

export default function Modal({ open, title, onClose, children }: Props) {
  useEffect(() => {
    if (!open) return;
    function onKey(e: KeyboardEvent) {
      if (e.key === 'Escape') onClose();
    }
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [open, onClose]);

  if (!open) return null;

  return (
    // Outer overlay: full viewport, centred content, dark scrim.
    // `py-4` adds breathing room at top/bottom so the clipped modal
    // doesn't kiss the viewport edges on small screens.
    <div className="fixed inset-0 z-40 flex items-center justify-center bg-black/70 px-4 py-4">
      {/*
        v1.3.6 scroll fix. Prior layout wrapped everything in a
        non-flex div with no max-height; forms with Advanced +
        inline target-group + DNS-provider dropdown expanded past
        viewport height and the overflowing bottom (including the
        Save button) fell off-screen with no way to scroll.

        New layout:
          - outer card is `flex flex-col` + `max-h-[calc(100vh-2rem)]`
            so the total can never exceed the viewport minus the
            py-4 padding on the overlay.
          - header is non-shrinking (flex-shrink-0) so it stays
            pinned at the top of the card.
          - body is `flex-1 overflow-y-auto` so overflowing content
            scrolls INSIDE the card while the header stays visible.
        Net: Save/Cancel at the bottom of any form are always
        reachable by scrolling the body.
      */}
      <div className="w-full max-w-lg bg-slate-900 border border-slate-700 rounded-lg shadow-xl flex flex-col max-h-[calc(100vh-2rem)]">
        <div className="flex items-center justify-between border-b border-slate-800 px-4 py-3 flex-shrink-0">
          <h2 className="text-base font-semibold">{title}</h2>
          <button
            type="button"
            onClick={onClose}
            className="p-1 rounded hover:bg-slate-800"
            aria-label="close"
          >
            <X className="w-4 h-4" />
          </button>
        </div>
        <div className="p-4 overflow-y-auto flex-1 min-h-0">{children}</div>
      </div>
    </div>
  );
}
