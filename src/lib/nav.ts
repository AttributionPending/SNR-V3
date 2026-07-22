/**
 * In-app navigation model shared by App.tsx's browser-history layer. The app has
 * no react-router; instead each main view is pushed onto the browser history
 * stack (so Back/Forward work) and reflected in a URL hash (so a refresh or a
 * pasted link restores the view). Modals are tracked in history.state so Back
 * closes them, but are intentionally NOT encoded in the hash (they are transient).
 */

export type ViewKind = 'home' | 'session' | 'actor' | 'case' | 'search' | 'intel';
export type ModalKind = 'settings' | 'admin' | 'reports' | 'help' | 'changePassword';

export interface NavState {
  view: ViewKind;
  /** Entity id for session/actor/case views. */
  id?: string;
  /** Seed query for the search view. */
  seed?: string;
  /** Transient overlay open on top of the view (not encoded in the hash). */
  modal?: ModalKind;
}

/** The view-only part of a NavState (drops the transient modal). */
export function viewPart(nav: NavState): NavState {
  return { view: nav.view, id: nav.id, seed: nav.seed };
}

/** Build the URL hash for a nav view (modal is deliberately excluded). */
export function buildHash(nav: NavState): string {
  switch (nav.view) {
    case 'session': return nav.id ? `#/session/${encodeURIComponent(nav.id)}` : '#/';
    case 'actor':   return nav.id ? `#/actor/${encodeURIComponent(nav.id)}` : '#/';
    case 'case':    return nav.id ? `#/case/${encodeURIComponent(nav.id)}` : '#/';
    case 'intel':   return '#/intel';
    case 'search':  return nav.seed ? `#/search/${encodeURIComponent(nav.seed)}` : '#/search';
    case 'home':
    default:        return '#/';
  }
}

/** Parse a URL hash back into a nav view. Unknown/empty → home. */
export function parseHash(hash: string): NavState {
  const h = (hash || '').replace(/^#/, '').replace(/^\//, '');
  if (!h) return { view: 'home' };
  const [kind, ...rest] = h.split('/');
  const arg = rest.length ? decodeURIComponent(rest.join('/')) : '';
  switch (kind) {
    case 'session': return arg ? { view: 'session', id: arg } : { view: 'home' };
    case 'actor':   return arg ? { view: 'actor', id: arg } : { view: 'home' };
    case 'case':    return arg ? { view: 'case', id: arg } : { view: 'home' };
    case 'intel':   return { view: 'intel' };
    case 'search':  return arg ? { view: 'search', seed: arg } : { view: 'search' };
    default:        return { view: 'home' };
  }
}

/** True when two navs denote the same underlying view (ignoring modal). */
export function sameView(a: NavState | null, b: NavState): boolean {
  return !!a && a.view === b.view && (a.id ?? '') === (b.id ?? '') && (a.seed ?? '') === (b.seed ?? '');
}
