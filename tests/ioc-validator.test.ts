import { describe, it, expect } from 'vitest';
import { validateAndDeduplicateIOCs } from '../server/lib/ioc-validator.js';

type IOC = Parameters<typeof validateAndDeduplicateIOCs>[0][number];
const ioc = (type: string, value: string, confidence: 'High' | 'Medium' | 'Low' = 'Medium', context = ''): IOC =>
  ({ type, value, context, confidence } as IOC);

describe('validateAndDeduplicateIOCs', () => {
  it('dedupes by type + normalized value (case-insensitive)', () => {
    const out = validateAndDeduplicateIOCs([ioc('domain', 'Evil.com'), ioc('domain', 'evil.com')]);
    expect(out).toHaveLength(1);
  });

  it('keeps the highest confidence and merges distinct contexts', () => {
    const out = validateAndDeduplicateIOCs([
      ioc('domain', 'evil.com', 'Low', 'seen in email'),
      ioc('domain', 'evil.com', 'High', 'seen in proxy'),
    ]);
    expect(out).toHaveLength(1);
    expect(out[0].confidence).toBe('High');
    expect(out[0].context).toContain('seen in email');
    expect(out[0].context).toContain('seen in proxy');
  });

  it('does not merge across different types', () => {
    const out = validateAndDeduplicateIOCs([ioc('domain', 'x.com'), ioc('url', 'x.com')]);
    expect(out).toHaveLength(2);
  });

  it('flags an invalid IPv4 (octet out of range)', () => {
    const out = validateAndDeduplicateIOCs([ioc('ipv4', '300.1.2.3')]);
    expect(out[0].validation?.valid).toBe(false);
  });

  it('marks a well-formed public IPv4 as valid', () => {
    const out = validateAndDeduplicateIOCs([ioc('ipv4', '45.32.113.172')]);
    expect(out[0].validation?.valid).toBe(true);
  });

  it('refangs a defanged domain and marks it valid (canonical value stored)', () => {
    const out = validateAndDeduplicateIOCs([ioc('domain', 'browseraccess4.pages[.]dev')]);
    expect(out).toHaveLength(1);
    expect(out[0].value).toBe('browseraccess4.pages.dev');
    expect(out[0].validation?.valid).toBe(true);
  });

  it('refangs defanged urls, emails, and ipv4', () => {
    const url = validateAndDeduplicateIOCs([ioc('url', 'hxxps://evil[.]com/gate[.]php')]);
    expect(url[0].value).toBe('https://evil.com/gate.php');
    expect(url[0].validation?.valid).toBe(true);

    const email = validateAndDeduplicateIOCs([ioc('email', 'user[@]evil[.]com')]);
    expect(email[0].value).toBe('user@evil.com');
    expect(email[0].validation?.valid).toBe(true);

    const ip = validateAndDeduplicateIOCs([ioc('ipv4', '45[.]32[.]113[.]172')]);
    expect(ip[0].value).toBe('45.32.113.172');
    expect(ip[0].validation?.valid).toBe(true);
  });

  it('merges a defanged and fanged form of the same indicator', () => {
    const out = validateAndDeduplicateIOCs([ioc('domain', 'evil[.]com'), ioc('domain', 'evil.com')]);
    expect(out).toHaveLength(1);
    expect(out[0].value).toBe('evil.com');
  });

  it('does not refang non-network types (a filename keeping [.] literally)', () => {
    const out = validateAndDeduplicateIOCs([ioc('filename', 'weird[.]name.exe')]);
    expect(out[0].value).toBe('weird[.]name.exe');
  });
});
