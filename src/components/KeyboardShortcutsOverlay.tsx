import { X, Keyboard } from 'lucide-react';
import { SHORTCUT_DEFINITIONS } from '../hooks/useKeyboardShortcuts';

interface Props {
  open: boolean;
  onClose: () => void;
}

export default function KeyboardShortcutsOverlay({ open, onClose }: Props) {
  if (!open) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 backdrop-blur-sm" onClick={onClose}>
      <div
        className="bg-navy-900 border border-border rounded-xl shadow-2xl w-full max-w-sm p-5"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="flex items-center justify-between mb-4">
          <div className="flex items-center gap-2 text-sm font-medium text-foreground">
            <Keyboard className="w-4 h-4 text-muted-foreground" />
            Keyboard Shortcuts
          </div>
          <button onClick={onClose} className="text-muted-foreground hover:text-foreground transition-colors">
            <X className="w-4 h-4" />
          </button>
        </div>

        <div className="space-y-2">
          {SHORTCUT_DEFINITIONS.map((s) => (
            <div key={s.keys} className="flex items-center justify-between text-xs">
              <span className="text-muted-foreground">{s.description}</span>
              <kbd className="px-1.5 py-0.5 rounded bg-navy-800 border border-border text-foreground font-mono text-[10px]">
                {s.keys}
              </kbd>
            </div>
          ))}
        </div>

        <p className="mt-4 text-[10px] text-muted-foreground text-center">
          Press <kbd className="px-1 py-0.5 rounded bg-navy-800 border border-border font-mono">?</kbd> to toggle this panel
        </p>
      </div>
    </div>
  );
}
