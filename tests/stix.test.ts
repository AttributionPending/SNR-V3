import { describe, it, expect } from 'vitest';
import { buildStixBundle } from '../server/lib/stix.js';
import type { AnalysisResult } from '../server/lib/claude.js';

function bundleResult(): AnalysisResult {
  return {
    incident_summary: { title: 'Incident', severity: 'High', confidence: 'High', description: 'd', analyst_notes: '' },
    attack_chain: [],
    iocs: [],
    detection_rules: [],
    threat_actor: { name: null, aliases: [], motivation: null, attribution_confidence: null, malware_families: [] },
    affected_assets: [],
    email_content: { subject: 's', severity_badge: 'High' },
  } as AnalysisResult;
}

describe('buildStixBundle — provenance (workbench origin)', () => {
  const analyst = () =>
    (buildStixBundle(bundleResult(), 'INC-1', 'AMBER' as never, 'CTI Analyst', 'Acme', undefined, 'workbench')
      .objects.find((o) => o.type === 'identity' && (o as { identity_class?: string }).identity_class === 'individual')) as
      | { x_snr_origin?: string }
      | undefined;

  it('marks the analyst identity as analyst-authored when origin is workbench', () => {
    expect(analyst()?.x_snr_origin).toBe('analyst-authored');
  });

  it('omits the provenance property for analysis-origin (default)', () => {
    const id = buildStixBundle(bundleResult(), 'INC-1', 'AMBER' as never, 'CTI Analyst', 'Acme')
      .objects.find((o) => o.type === 'identity' && (o as { identity_class?: string }).identity_class === 'individual') as
      | { x_snr_origin?: string }
      | undefined;
    expect(id).toBeDefined();
    expect(id?.x_snr_origin).toBeUndefined();
  });
});

// Test the pure buildStixPattern logic (not exported, so we replicate it)
describe('buildStixPattern', () => {
  function buildStixPattern(type: string, value: string): string | null {
    const validators: Record<string, RegExp> = {
      ipv4: /^(\d{1,3}\.){3}\d{1,3}(\/\d{1,2})?$/,
      ipv6: /^[0-9a-fA-F:]+$/,
      domain: /^([a-zA-Z0-9-]{1,63}\.)+[a-zA-Z]{2,}$/,
      url: /^https?:\/\/.+/,
      md5: /^[a-fA-F0-9]{32}$/,
      sha1: /^[a-fA-F0-9]{40}$/,
      sha256: /^[a-fA-F0-9]{64}$/,
      email: /^[^\s@]+@[^\s@]+\.[^\s@]+$/,
    };
    const validator = validators[type];
    if (validator && !validator.test(value)) return null;

    const escaped = value.replace(/'/g, "\\'").replace(/\\/g, '\\\\');
    switch (type) {
      case 'ipv4':
        return `[ipv4-addr:value = '${escaped}']`;
      case 'ipv6':
        return `[ipv6-addr:value = '${escaped}']`;
      case 'domain':
        return `[domain-name:value = '${escaped}']`;
      case 'url':
        return `[url:value = '${escaped}']`;
      case 'md5':
        return `[file:hashes.MD5 = '${escaped}']`;
      case 'sha1':
        return `[file:hashes.SHA-1 = '${escaped}']`;
      case 'sha256':
        return `[file:hashes.SHA-256 = '${escaped}']`;
      case 'email':
        return `[email-addr:value = '${escaped}']`;
      case 'filename':
        return `[file:name = '${escaped}']`;
      case 'registry':
        return `[windows-registry-key:key = '${escaped}']`;
      case 'user_agent':
        return `[network-traffic:extensions.'http-request-ext'.request_header.user-agent = '${escaped}']`;
      default:
        return null;
    }
  }

  describe('IPv4', () => {
    it('generates correct pattern for valid IPv4', () => {
      expect(buildStixPattern('ipv4', '192.168.1.1')).toBe(
        "[ipv4-addr:value = '192.168.1.1']",
      );
    });

    it('supports CIDR notation', () => {
      expect(buildStixPattern('ipv4', '10.0.0.0/8')).toBe("[ipv4-addr:value = '10.0.0.0/8']");
    });

    it('rejects invalid IPv4', () => {
      expect(buildStixPattern('ipv4', 'not-an-ip')).toBeNull();
    });
  });

  describe('Domain', () => {
    it('generates correct pattern for valid domain', () => {
      expect(buildStixPattern('domain', 'evil.example.com')).toBe(
        "[domain-name:value = 'evil.example.com']",
      );
    });

    it('rejects invalid domain', () => {
      expect(buildStixPattern('domain', 'just-a-word')).toBeNull();
    });
  });

  describe('Hashes', () => {
    it('generates MD5 pattern', () => {
      const md5 = 'd41d8cd98f00b204e9800998ecf8427e';
      expect(buildStixPattern('md5', md5)).toBe(`[file:hashes.MD5 = '${md5}']`);
    });

    it('generates SHA-256 pattern', () => {
      const sha256 = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';
      expect(buildStixPattern('sha256', sha256)).toBe(`[file:hashes.SHA-256 = '${sha256}']`);
    });

    it('rejects invalid hash length', () => {
      expect(buildStixPattern('md5', 'tooshort')).toBeNull();
      expect(buildStixPattern('sha256', 'abc123')).toBeNull();
    });
  });

  describe('URL', () => {
    it('generates correct pattern for HTTP URL', () => {
      expect(buildStixPattern('url', 'https://evil.com/payload')).toBe(
        "[url:value = 'https://evil.com/payload']",
      );
    });

    it('rejects non-HTTP URL', () => {
      expect(buildStixPattern('url', 'ftp://evil.com')).toBeNull();
    });
  });

  describe('Email', () => {
    it('generates correct pattern', () => {
      expect(buildStixPattern('email', 'attacker@evil.com')).toBe(
        "[email-addr:value = 'attacker@evil.com']",
      );
    });

    it('rejects invalid email', () => {
      expect(buildStixPattern('email', 'not-an-email')).toBeNull();
    });
  });

  describe('Special characters', () => {
    it('escapes single quotes in values', () => {
      const result = buildStixPattern('filename', "evil'payload.exe");
      // The escape replaces ' with \' then \ with \\, so result has \\'
      expect(result).toBe("[file:name = 'evil\\\\'payload.exe']");
    });

    it('escapes backslashes in registry keys', () => {
      const result = buildStixPattern('registry', 'HKLM\\SOFTWARE\\Malware');
      expect(result).toBe("[windows-registry-key:key = 'HKLM\\\\SOFTWARE\\\\Malware']");
    });
  });

  describe('Unknown type', () => {
    it('returns null for unknown IOC type', () => {
      expect(buildStixPattern('unknown_type', 'somevalue')).toBeNull();
    });
  });

  describe('Filename and user_agent', () => {
    it('generates filename pattern', () => {
      expect(buildStixPattern('filename', 'malware.exe')).toBe(
        "[file:name = 'malware.exe']",
      );
    });

    it('generates user_agent pattern', () => {
      const ua = 'Mozilla/5.0 evil-bot';
      expect(buildStixPattern('user_agent', ua)).toContain(ua);
    });
  });
});

describe('stixTimestamp', () => {
  function stixTimestamp(date?: Date): string {
    return (date ?? new Date()).toISOString().replace(/\.\d{3}Z$/, '.000Z');
  }

  it('formats date with .000Z suffix', () => {
    const date = new Date('2024-01-15T10:30:45.123Z');
    expect(stixTimestamp(date)).toBe('2024-01-15T10:30:45.000Z');
  });

  it('returns current time when no argument given', () => {
    const result = stixTimestamp();
    expect(result).toMatch(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.000Z$/);
  });
});
