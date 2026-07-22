/**
 * Small analyst UI preferences persisted to localStorage. Kept separate from the
 * theme provider (which owns `snr_theme`) but follows the same read/write pattern.
 */

export type DefaultView = 'analysis' | 'intel';
const DEFAULT_VIEW_KEY = 'snr_default_view';

export function getDefaultView(): DefaultView {
  try {
    const saved = localStorage.getItem(DEFAULT_VIEW_KEY);
    if (saved === 'intel' || saved === 'analysis') return saved;
  } catch { /* ignore */ }
  return 'analysis';
}

export function setDefaultView(view: DefaultView): void {
  try { localStorage.setItem(DEFAULT_VIEW_KEY, view); } catch { /* ignore */ }
}
