import { describe, it, expect } from 'vitest';
import { normalizeIocValue, iocIndexKey, reindexSessionIocs, parseFalsePositiveKeys } from '../server/lib/ioc-index.js';

// The UI's identity key (src/components/IOCTable.tsx:iocKey) for a plain value.
const uiKey = (type: string, value: string) => `${type}::${value.toLowerCase().trim()}`;

describe('normalizeIocValue', () => {
  it('matches the UI iocKey value half for plain (non-defanged) values', () => {
    for (const [t, v] of [['ipv4', '1.2.3.4'], ['domain', 'Evil.COM'], ['sha256', 'AbCdEf']] as const) {
      expect(`${t}::${normalizeIocValue(t, v)}`).toBe(uiKey(t, v));
    }
  });

  it('collapses defanged variants of the same indicator', () => {
    expect(normalizeIocValue('domain', 'evil[.]com')).toBe('evil.com');
    expect(normalizeIocValue('url', 'hxxps://evil[.]com/a')).toBe('https://evil.com/a');
    expect(normalizeIocValue('ipv4', '1[.]2[.]3[.]4')).toBe('1.2.3.4');
    // defanged and refanged forms produce the same key
    expect(normalizeIocValue('domain', 'evil[.]com')).toBe(normalizeIocValue('domain', 'evil.com'));
  });

  it('iocIndexKey composes type + normalized value', () => {
    expect(iocIndexKey('domain', 'Evil[.]Com')).toBe('domain::evil.com');
  });
});

describe('parseFalsePositiveKeys', () => {
  it('reads the JSON-string array under ioc_false_positives', () => {
    const overrides = JSON.stringify({ ioc_false_positives: JSON.stringify(['ipv4::1.2.3.4']) });
    expect(parseFalsePositiveKeys(overrides)).toEqual(['ipv4::1.2.3.4']);
  });
  it('tolerates a raw array and returns [] for junk', () => {
    expect(parseFalsePositiveKeys(JSON.stringify({ ioc_false_positives: ['a::b'] }))).toEqual(['a::b']);
    expect(parseFalsePositiveKeys('not json')).toEqual([]);
    expect(parseFalsePositiveKeys(null)).toEqual([]);
  });
});

// Minimal fake DB matching the getDb().prepare(sql).run(...) shape used server-side.
function fakeDb() {
  const inserts: Record<string, unknown>[] = [];
  let deleted = 0;
  const db = {
    prepare(sql: string) {
      return {
        async run(...args: unknown[]) {
          if (/^\s*DELETE/i.test(sql)) { deleted++; return; }
          if (/INSERT INTO ioc_observations/i.test(sql)) {
            // columns: id, team_id, session_id, ioc_type, ioc_value, ioc_value_norm, context, confidence, is_false_positive, created_at
            inserts.push({
              team_id: args[1], session_id: args[2], ioc_type: args[3], ioc_value: args[4],
              ioc_value_norm: args[5], context: args[6], confidence: args[7], is_false_positive: args[8],
            });
          }
        },
      };
    },
    _inserts: inserts,
    _deleted: () => deleted,
  };
  return db;
}

describe('reindexSessionIocs', () => {
  it('inserts one row per distinct (type, normalized value) after clearing the session', async () => {
    const db = fakeDb();
    const result = {
      iocs: [
        { type: 'domain', value: 'evil.com', context: 'c2', confidence: 'High' },
        { type: 'domain', value: 'evil[.]com', context: 'dup defanged', confidence: 'Low' }, // dup of above
        { type: 'ipv4', value: '1.2.3.4', context: 'beacon', confidence: 'Medium' },
        { type: 'ipv4', value: '  ', context: 'blank', confidence: 'Low' }, // skipped
      ],
    };
    await reindexSessionIocs(db, 'sess-1', 'team-1', result, []);
    expect(db._deleted()).toBe(1);
    expect(db._inserts).toHaveLength(2);
    const norms = db._inserts.map((r) => r.ioc_value_norm).sort();
    expect(norms).toEqual(['1.2.3.4', 'evil.com']);
    expect(db._inserts.every((r) => r.is_false_positive === 0)).toBe(true);
  });

  it('honors false-positive keys (plain UI form)', async () => {
    const db = fakeDb();
    const result = { iocs: [{ type: 'ipv4', value: '1.2.3.4', context: '', confidence: 'High' }] };
    await reindexSessionIocs(db, 's', 't', result, ['ipv4::1.2.3.4']);
    expect(db._inserts[0].is_false_positive).toBe(1);
  });

  it('clears rows and inserts nothing when there are no IOCs', async () => {
    const db = fakeDb();
    await reindexSessionIocs(db, 's', 't', { iocs: [] }, []);
    expect(db._deleted()).toBe(1);
    expect(db._inserts).toHaveLength(0);
  });
});
