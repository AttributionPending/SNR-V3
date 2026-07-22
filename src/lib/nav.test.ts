import { describe, it, expect } from 'vitest';
import { buildHash, parseHash, viewPart, sameView, type NavState } from './nav';

describe('nav hash mapping', () => {
  const cases: Array<[NavState, string]> = [
    [{ view: 'home' }, '#/'],
    [{ view: 'intel' }, '#/intel'],
    [{ view: 'search' }, '#/search'],
    [{ view: 'search', seed: '1.2.3.4' }, '#/search/1.2.3.4'],
    [{ view: 'session', id: 'abc-123' }, '#/session/abc-123'],
    [{ view: 'actor', id: 'a1' }, '#/actor/a1'],
    [{ view: 'case', id: 'c9' }, '#/case/c9'],
  ];

  it('builds the expected hash for each view', () => {
    for (const [nav, hash] of cases) expect(buildHash(nav)).toBe(hash);
  });

  it('round-trips build → parse for the view part', () => {
    for (const [nav] of cases) expect(parseHash(buildHash(nav))).toEqual(viewPart(nav));
  });

  it('encodes/decodes ids and seeds with special characters', () => {
    const nav: NavState = { view: 'search', seed: 'evil corp/beacon?x=1' };
    expect(parseHash(buildHash(nav))).toEqual(nav);
  });

  it('drops the modal from the hash (transient)', () => {
    expect(buildHash({ view: 'case', id: 'c9', modal: 'settings' })).toBe('#/case/c9');
  });

  it('treats unknown or empty hashes as home', () => {
    expect(parseHash('')).toEqual({ view: 'home' });
    expect(parseHash('#/')).toEqual({ view: 'home' });
    expect(parseHash('#/bogus/thing')).toEqual({ view: 'home' });
    expect(parseHash('#/session')).toEqual({ view: 'home' }); // missing id
  });

  it('viewPart strips the modal; sameView ignores it', () => {
    expect(viewPart({ view: 'case', id: 'c9', modal: 'help' })).toEqual({ view: 'case', id: 'c9', seed: undefined });
    expect(sameView({ view: 'case', id: 'c9' }, { view: 'case', id: 'c9', modal: 'help' })).toBe(true);
    expect(sameView({ view: 'case', id: 'c9' }, { view: 'case', id: 'c8' })).toBe(false);
    expect(sameView(null, { view: 'home' })).toBe(false);
  });
});
