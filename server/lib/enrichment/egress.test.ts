import { describe, it, expect } from 'vitest';
import {
  assertSafeUrl, isBlockedIPv4, isBlockedIPv6, isBlockedAddress,
  classifyAddress, EgressBlockedError,
} from './egress';

describe('egress SSRF guard', () => {
  it('blocks non-public IPv4 ranges', () => {
    for (const ip of ['10.0.0.5', '127.0.0.1', '192.168.1.1', '172.16.0.1', '172.31.255.255',
                      '169.254.169.254', '100.64.0.1', '0.0.0.0', '224.0.0.1', '255.255.255.255']) {
      expect(isBlockedIPv4(ip), ip).toBe(true);
    }
  });

  it('allows public IPv4', () => {
    for (const ip of ['8.8.8.8', '1.1.1.1', '104.16.0.1', '172.32.0.1', '192.167.1.1']) {
      expect(isBlockedIPv4(ip), ip).toBe(false);
    }
  });

  it('blocks non-public IPv6 (incl. IPv4-mapped private)', () => {
    for (const ip of ['::1', '::', 'fe80::1', 'fc00::1', 'fd12:3456::1', 'ff02::1', '::ffff:10.0.0.1']) {
      expect(isBlockedIPv6(ip), ip).toBe(true);
    }
  });

  it('allows public IPv6', () => {
    expect(isBlockedIPv6('2606:4700:4700::1111')).toBe(false);
    expect(isBlockedIPv6('::ffff:8.8.8.8')).toBe(false);
  });

  it('refuses anything that is not an IP literal', () => {
    expect(isBlockedAddress('not-an-ip')).toBe(true);
  });

  it('requires https', () => {
    expect(() => assertSafeUrl('http://example.com/x')).toThrow(EgressBlockedError);
    expect(() => assertSafeUrl('ftp://example.com')).toThrow(EgressBlockedError);
    expect(() => assertSafeUrl('not a url')).toThrow(EgressBlockedError);
  });

  it('rejects https URLs pointing straight at internal IP literals', () => {
    expect(() => assertSafeUrl('https://127.0.0.1/admin')).toThrow(EgressBlockedError);
    expect(() => assertSafeUrl('https://169.254.169.254/latest/meta-data/')).toThrow(EgressBlockedError);
    expect(() => assertSafeUrl('https://10.0.0.5:8080/')).toThrow(EgressBlockedError);
  });

  it('accepts a normal public https URL', () => {
    expect(assertSafeUrl('https://www.virustotal.com/api/v3/ip_addresses/8.8.8.8').hostname)
      .toBe('www.virustotal.com');
  });
});

describe('internal opt-in (self-hosted feeds)', () => {
  it('separates always-blocked addresses from opt-in private ranges', () => {
    // Never reachable, even with the opt-in.
    for (const ip of ['127.0.0.1', '169.254.169.254', '0.0.0.0', '224.0.0.1', '::1', 'fe80::1']) {
      expect(classifyAddress(ip), ip).toBe('blocked');
    }
    // Reachable only when a feed opts in.
    for (const ip of ['10.0.0.5', '192.168.1.10', '172.16.0.1', '100.64.0.1', 'fd12::1']) {
      expect(classifyAddress(ip), ip).toBe('private');
    }
    expect(classifyAddress('8.8.8.8')).toBe('public');
  });

  it('allows private ranges only when allowInternal is set', () => {
    expect(isBlockedAddress('10.0.0.5')).toBe(true);
    expect(isBlockedAddress('10.0.0.5', true)).toBe(false);
    expect(isBlockedAddress('192.168.1.10', true)).toBe(false);
    expect(isBlockedAddress('fd12::1', true)).toBe(false);
  });

  it('still refuses loopback and cloud metadata with allowInternal set', () => {
    expect(isBlockedAddress('127.0.0.1', true)).toBe(true);
    expect(isBlockedAddress('169.254.169.254', true)).toBe(true);
    expect(isBlockedAddress('::1', true)).toBe(true);
  });

  it('permits http and a private literal host only for internal feeds', () => {
    expect(() => assertSafeUrl('http://misp.corp.local/events')).toThrow(EgressBlockedError);
    expect(assertSafeUrl('http://misp.corp.local/events', true).protocol).toBe('http:');
    expect(() => assertSafeUrl('https://10.0.0.5/misp')).toThrow(EgressBlockedError);
    expect(assertSafeUrl('https://10.0.0.5/misp', true).hostname).toBe('10.0.0.5');
    // …but the always-blocked set stays blocked even for internal feeds.
    expect(() => assertSafeUrl('http://169.254.169.254/latest/meta-data/', true)).toThrow(EgressBlockedError);
    expect(() => assertSafeUrl('http://127.0.0.1:8080/', true)).toThrow(EgressBlockedError);
  });
});
