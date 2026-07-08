import { describe, it, expect } from 'vitest';
import { extractReferences, NO_REFERENCES } from '../server/lib/references.js';

describe('extractReferences', () => {
  it('keeps a vendor citation URL', () => {
    const out = extractReferences('See https://unit42.paloaltonetworks.com/cl-sta-1062-tinyrct-backdoor/ for details');
    expect(out).toBe('https://unit42.paloaltonetworks.com/cl-sta-1062-tinyrct-backdoor/');
  });

  it('excludes a URL that is also an extracted IOC (by full value)', () => {
    const input = 'Beacon to https://evil-c2.example/gate.php observed.';
    const out = extractReferences(input, ['https://evil-c2.example/gate.php']);
    expect(out).toBe(NO_REFERENCES);
  });

  it('excludes a URL whose host matches an IOC domain', () => {
    const input = 'C2: https://evil-c2.example/path?a=1 and report https://unit42.paloaltonetworks.com/x/';
    const out = extractReferences(input, ['evil-c2.example']);
    expect(out).toContain('https://unit42.paloaltonetworks.com/x/');
    expect(out).not.toContain('evil-c2.example');
  });

  it('ignores defanged indicators (hxxp / [.])', () => {
    const out = extractReferences('IOC: hxxp://evil[.]com/payload and 1.2.3[.]4');
    expect(out).toBe(NO_REFERENCES);
  });

  it('captures CVE identifiers (uppercased)', () => {
    const out = extractReferences('Exploits cve-2024-1234 in the wild');
    expect(out).toContain('CVE-2024-1234');
  });

  it('captures explicit Reference:/Source: lines', () => {
    const out = extractReferences('Reference: Unit42 TinyRCT report\nSource: internal IR ticket 4421');
    expect(out).toContain('Unit42 TinyRCT report');
    expect(out).toContain('internal IR ticket 4421');
  });

  it('returns the placeholder when nothing is provided', () => {
    expect(extractReferences('just some prose with no links')).toBe(NO_REFERENCES);
    expect(extractReferences('')).toBe(NO_REFERENCES);
  });

  it('dedupes repeated URLs and CVEs', () => {
    const input = 'https://a.example/x https://a.example/x/ CVE-2024-0001 cve-2024-0001';
    const out = extractReferences(input);
    const lines = out.split('\n');
    expect(lines.filter((l) => l.includes('a.example')).length).toBe(1);
    expect(lines.filter((l) => l === 'CVE-2024-0001').length).toBe(1);
  });

  it('emits bare URLs, never markdown links', () => {
    const out = extractReferences('https://example.com/report');
    expect(out).not.toContain('](');
    expect(out).toBe('https://example.com/report');
  });

  it('orders reference lines, then URLs, then CVEs', () => {
    const out = extractReferences('Reference: My Report\nhttps://example.com/x\nCVE-2024-9999');
    expect(out).toBe('My Report\nhttps://example.com/x\nCVE-2024-9999');
  });

  it('does not repeat a URL/CVE already contained in a Reference: line', () => {
    const out = extractReferences('Reference: https://blog.example/writeup and CVE-2024-1234');
    expect(out).toBe('https://blog.example/writeup and CVE-2024-1234');
    expect(out.split('\n')).toHaveLength(1);
  });
});
