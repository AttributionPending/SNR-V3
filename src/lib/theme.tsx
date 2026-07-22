/**
 * Light/dark theme. The whole UI is driven by CSS variables (see index.css):
 * `:root` holds the light palette, `.dark` the dark palette, and the neutral
 * (n-scale) and accent (a-scale) flip with the class so even fixed navy and
 * cyan utility classes re-theme. This provider just toggles the `.dark` class
 * on the document element and persists the choice.
 */
import { createContext, useCallback, useContext, useEffect, useState, type ReactNode } from 'react';

type Theme = 'light' | 'dark';
const STORAGE_KEY = 'snr_theme';

interface ThemeCtx { theme: Theme; toggle: () => void; setTheme: (t: Theme) => void }
const ThemeContext = createContext<ThemeCtx | null>(null);

function readInitial(): Theme {
  try {
    const saved = localStorage.getItem(STORAGE_KEY);
    if (saved === 'light' || saved === 'dark') return saved;
  } catch { /* ignore */ }
  // Default matches the pre-set class on <html> (dark).
  return document.documentElement.classList.contains('dark') ? 'dark' : 'dark';
}

function apply(theme: Theme) {
  document.documentElement.classList.toggle('dark', theme === 'dark');
}

export function ThemeProvider({ children }: { children: ReactNode }) {
  const [theme, setThemeState] = useState<Theme>(readInitial);

  useEffect(() => {
    apply(theme);
    try { localStorage.setItem(STORAGE_KEY, theme); } catch { /* ignore */ }
  }, [theme]);

  const setTheme = useCallback((t: Theme) => setThemeState(t), []);
  const toggle = useCallback(() => setThemeState((t) => (t === 'dark' ? 'light' : 'dark')), []);

  return <ThemeContext.Provider value={{ theme, toggle, setTheme }}>{children}</ThemeContext.Provider>;
}

export function useTheme(): ThemeCtx {
  const ctx = useContext(ThemeContext);
  if (!ctx) throw new Error('useTheme must be used within ThemeProvider');
  return ctx;
}
