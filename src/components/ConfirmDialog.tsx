/**
 * ConfirmDialog — styled replacement for window.confirm().
 * Dark-theme modal matching the app's existing modal pattern.
 */
import { useEffect, useRef } from 'react';
import { AlertTriangle, HelpCircle } from 'lucide-react';
import { Button } from './ui/button';
import { cn } from '@/lib/utils';

interface ConfirmDialogProps {
  open: boolean;
  title: string;
  message: string;
  confirmLabel?: string;
  cancelLabel?: string;
  /** Renders the confirm button in red and shows a warning icon */
  danger?: boolean;
  onConfirm: () => void;
  onCancel: () => void;
}

export default function ConfirmDialog({
  open, title, message, confirmLabel = 'Confirm', cancelLabel = 'Cancel', danger = false, onConfirm, onCancel,
}: ConfirmDialogProps) {
  const confirmRef = useRef<HTMLButtonElement>(null);

  // Focus the confirm button and support Escape/Enter keys
  useEffect(() => {
    if (!open) return;
    confirmRef.current?.focus();
    const handler = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        e.preventDefault();
        onCancel();
      } else if (e.key === 'Enter') {
        e.preventDefault();
        onConfirm();
      }
    };
    document.addEventListener('keydown', handler);
    return () => document.removeEventListener('keydown', handler);
  }, [open, onConfirm, onCancel]);

  if (!open) return null;

  return (
    <div
      className="fixed inset-0 z-[120] flex items-center justify-center p-4 bg-black/70 backdrop-blur-sm"
      onClick={onCancel}
    >
      <div
        className="bg-navy-950 border border-border rounded-lg shadow-2xl w-full max-w-sm"
        onClick={(e) => e.stopPropagation()}
        role="alertdialog"
        aria-modal="true"
        aria-label={title}
      >
        <div className="px-5 py-4">
          <div className="flex items-start gap-3">
            <div className={cn(
              'w-8 h-8 rounded-full flex items-center justify-center flex-shrink-0',
              danger ? 'bg-red-500/15' : 'bg-cyan-500/15',
            )}>
              {danger
                ? <AlertTriangle className="w-4 h-4 text-red-400" />
                : <HelpCircle className="w-4 h-4 text-cyan-400" />}
            </div>
            <div className="flex-1 min-w-0">
              <h2 className="text-sm font-semibold text-foreground">{title}</h2>
              <p className="text-xs text-muted-foreground mt-1 whitespace-pre-line">{message}</p>
            </div>
          </div>
        </div>
        <div className="px-5 py-3 border-t border-border flex items-center justify-end gap-2">
          <Button variant="ghost" size="sm" onClick={onCancel} className="text-xs">
            {cancelLabel}
          </Button>
          <Button
            ref={confirmRef}
            size="sm"
            onClick={onConfirm}
            className={cn(
              'text-xs border',
              danger
                ? 'bg-red-500/20 text-red-300 hover:bg-red-500/30 border-red-500/30'
                : 'bg-cyan-500/20 text-cyan-300 hover:bg-cyan-500/30 border-cyan-500/30',
            )}
          >
            {confirmLabel}
          </Button>
        </div>
      </div>
    </div>
  );
}
