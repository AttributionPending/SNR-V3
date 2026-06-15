import { useEffect, useCallback } from 'react';

export interface ShortcutAction {
  key: string;
  ctrl?: boolean;
  shift?: boolean;
  alt?: boolean;
  description: string;
  action: () => void;
}

/**
 * Global keyboard shortcut handler.
 * Ignores events when the user is typing in inputs, textareas, or contenteditable elements.
 */
export function useKeyboardShortcuts(shortcuts: ShortcutAction[]) {
  const handler = useCallback(
    (e: KeyboardEvent) => {
      // Don't intercept when typing in inputs/textareas/contenteditable
      const target = e.target as HTMLElement;
      if (
        target.tagName === 'INPUT' ||
        target.tagName === 'TEXTAREA' ||
        target.tagName === 'SELECT' ||
        target.isContentEditable
      ) {
        return;
      }

      for (const shortcut of shortcuts) {
        const ctrlMatch = shortcut.ctrl ? e.ctrlKey || e.metaKey : !e.ctrlKey && !e.metaKey;
        const shiftMatch = shortcut.shift ? e.shiftKey : !e.shiftKey;
        const altMatch = shortcut.alt ? e.altKey : !e.altKey;

        if (e.key.toLowerCase() === shortcut.key.toLowerCase() && ctrlMatch && shiftMatch && altMatch) {
          e.preventDefault();
          shortcut.action();
          return;
        }
      }
    },
    [shortcuts],
  );

  useEffect(() => {
    window.addEventListener('keydown', handler);
    return () => window.removeEventListener('keydown', handler);
  }, [handler]);
}

/** All available shortcuts for the help overlay */
export const SHORTCUT_DEFINITIONS = [
  { keys: 'N', description: 'New session' },
  { keys: '⌘/Ctrl+K', description: 'Search intelligence' },
  { keys: '?', description: 'Toggle keyboard shortcuts help' },
  { keys: 'S', description: 'Toggle sidebar' },
  { keys: '1-9', description: 'Select session 1–9' },
  { keys: 'Esc', description: 'Close modals / clear selection' },
] as const;
