import { describe, it, expect } from 'vitest';
import { normalizeTechniqueId, ruleHash, coverageStatus } from './detection-index';

describe('normalizeTechniqueId', () => {
  it('accepts the ids the model is prompted to emit', () => {
    expect(normalizeTechniqueId('T1059.001')).toBe('T1059.001');
    expect(normalizeTechniqueId('T1566')).toBe('T1566');
  });

  it('normalizes case and pulls the id out of surrounding text', () => {
    expect(normalizeTechniqueId('t1059.001')).toBe('T1059.001');
    expect(normalizeTechniqueId('T1566 - Phishing')).toBe('T1566');
    expect(normalizeTechniqueId('ATT&CK T1071.001 (App Layer Protocol)')).toBe('T1071.001');
  });

  it('returns null for an unmapped rule rather than inventing an id', () => {
    expect(normalizeTechniqueId(null)).toBeNull();
    expect(normalizeTechniqueId(undefined)).toBeNull();
    expect(normalizeTechniqueId('')).toBeNull();
    expect(normalizeTechniqueId('n/a')).toBeNull();
    expect(normalizeTechniqueId('TA0001')).toBeNull();   // a tactic, not a technique
    expect(normalizeTechniqueId('T99')).toBeNull();      // too short to be an id
  });
});

describe('ruleHash', () => {
  it('ignores whitespace-only differences so a regenerated rule counts once', () => {
    expect(ruleHash('title: x\n  detection:  a')).toBe(ruleHash('title: x\ndetection: a'));
    expect(ruleHash(' a b ')).toBe(ruleHash('a  b'));
  });

  it('separates genuinely different rules', () => {
    expect(ruleHash('rule a')).not.toBe(ruleHash('rule b'));
  });

  it('handles a missing body without throwing', () => {
    expect(ruleHash(undefined)).toBe(ruleHash(''));
  });
});

describe('coverageStatus', () => {
  it('is covered when rules exist and nothing reported a gap', () => {
    expect(coverageStatus(3, 0, 2)).toBe('covered');
    expect(coverageStatus(1, 0, 0)).toBe('covered');
  });

  it('is partial when rules exist but a gap is still reported — the disagreement case', () => {
    expect(coverageStatus(3, 1, 2)).toBe('partial');
  });

  it('is a gap when no rule covers a technique analysis flagged', () => {
    expect(coverageStatus(0, 5, 0)).toBe('gap');
  });

  it('falls back to the verdict when no rules exist', () => {
    expect(coverageStatus(0, 0, 4)).toBe('covered');   // controls believed sufficient
    expect(coverageStatus(0, 0, 0)).toBe('unknown');
  });
});
