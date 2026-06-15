/**
 * IOC validation and deduplication.
 * Validates format per type, flags warnings, and merges duplicates.
 */

interface IOC {
  type: string;
  value: string;
  context: string;
  confidence: 'High' | 'Medium' | 'Low';
  validation?: { valid: boolean; warnings: string[] };
  duplicateCount?: number;
}

// ── Validation regexes ───────────────────────────────────────────────────────

const IPV4_RE = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;
const IPV6_RE = /^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$/;
const DOMAIN_RE = /^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}$/;
const MD5_RE = /^[0-9a-fA-F]{32}$/;
const SHA1_RE = /^[0-9a-fA-F]{40}$/;
const SHA256_RE = /^[0-9a-fA-F]{64}$/;
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

// RFC 1918 private ranges
function isPrivateIPv4(ip: string): boolean {
  const parts = ip.split('.').map(Number);
  if (parts[0] === 10) return true;
  if (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) return true;
  if (parts[0] === 192 && parts[1] === 168) return true;
  return false;
}

function isReservedIPv4(ip: string): boolean {
  const parts = ip.split('.').map(Number);
  if (parts[0] === 0) return true;          // 0.0.0.0/8
  if (parts[0] === 127) return true;        // loopback
  if (parts[0] === 169 && parts[1] === 254) return true; // link-local
  if (parts[0] >= 224 && parts[0] <= 239) return true;   // multicast
  if (parts[0] >= 240) return true;         // reserved
  return false;
}

// ── Per-type validators ──────────────────────────────────────────────────────

type Validator = (value: string) => { valid: boolean; warnings: string[] };

const validators: Record<string, Validator> = {
  ipv4(value) {
    const warnings: string[] = [];
    const m = IPV4_RE.exec(value.trim());
    if (!m) return { valid: false, warnings: ['Invalid IPv4 format'] };
    const octets = [Number(m[1]), Number(m[2]), Number(m[3]), Number(m[4])];
    if (octets.some(o => o > 255)) return { valid: false, warnings: ['IPv4 octet out of range (0-255)'] };
    if (isReservedIPv4(value.trim())) warnings.push('Reserved/loopback address');
    else if (isPrivateIPv4(value.trim())) warnings.push('Private (RFC 1918) address');
    return { valid: true, warnings };
  },

  ipv6(value) {
    const v = value.trim();
    // Allow :: shorthand and mapped IPv4
    if (IPV6_RE.test(v) || /^::ffff:\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/i.test(v) || v === '::' || v === '::1') {
      const warnings: string[] = [];
      if (v === '::1' || v === '::') warnings.push('Loopback/unspecified address');
      return { valid: true, warnings };
    }
    return { valid: false, warnings: ['Invalid IPv6 format'] };
  },

  domain(value) {
    const v = value.trim().toLowerCase();
    const warnings: string[] = [];
    if (!DOMAIN_RE.test(v)) return { valid: false, warnings: ['Invalid domain format'] };
    if (v.length > 253) return { valid: false, warnings: ['Domain exceeds 253 characters'] };
    // Warn on suspicious TLDs
    if (/\.(test|example|invalid|localhost)$/i.test(v)) warnings.push('Non-routable TLD');
    return { valid: true, warnings };
  },

  url(value) {
    const v = value.trim();
    try {
      const u = new URL(v.replace(/^hxxp/i, 'http').replace(/\[\.\]/g, '.').replace(/\[:\]/g, ':'));
      const warnings: string[] = [];
      if (!['http:', 'https:', 'ftp:'].includes(u.protocol)) warnings.push(`Unusual protocol: ${u.protocol}`);
      return { valid: true, warnings };
    } catch {
      return { valid: false, warnings: ['Invalid URL — cannot be parsed'] };
    }
  },

  md5(value) {
    const v = value.trim();
    if (MD5_RE.test(v)) return { valid: true, warnings: [] };
    if (/^[0-9a-fA-F]+$/.test(v)) {
      return { valid: false, warnings: [`Hash is ${v.length} hex chars — MD5 requires exactly 32`] };
    }
    return { valid: false, warnings: ['Contains non-hex characters'] };
  },

  sha1(value) {
    const v = value.trim();
    if (SHA1_RE.test(v)) return { valid: true, warnings: [] };
    if (/^[0-9a-fA-F]+$/.test(v)) {
      return { valid: false, warnings: [`Hash is ${v.length} hex chars — SHA-1 requires exactly 40`] };
    }
    return { valid: false, warnings: ['Contains non-hex characters'] };
  },

  sha256(value) {
    const v = value.trim();
    if (SHA256_RE.test(v)) return { valid: true, warnings: [] };
    if (/^[0-9a-fA-F]+$/.test(v)) {
      return { valid: false, warnings: [`Hash is ${v.length} hex chars — SHA-256 requires exactly 64`] };
    }
    return { valid: false, warnings: ['Contains non-hex characters'] };
  },

  email(value) {
    const v = value.trim();
    if (EMAIL_RE.test(v)) return { valid: true, warnings: [] };
    return { valid: false, warnings: ['Invalid email format'] };
  },

  filename(value) {
    const v = value.trim();
    const warnings: string[] = [];
    if (!v) return { valid: false, warnings: ['Empty filename'] };
    if (v.includes('..')) warnings.push('Contains path traversal (..)');
    if (v.length > 255) return { valid: false, warnings: ['Filename exceeds 255 characters'] };
    return { valid: true, warnings };
  },

  registry(value) {
    const v = value.trim();
    if (/^(HKEY_|HK[A-Z]{2})/i.test(v)) return { valid: true, warnings: [] };
    return { valid: false, warnings: ['Does not start with a valid registry hive (HKEY_ or HKLM/HKCU/...)'] };
  },

  user_agent(value) {
    const v = value.trim();
    if (!v) return { valid: false, warnings: ['Empty user agent'] };
    return { valid: true, warnings: [] };
  },
};

// ── Public functions ─────────────────────────────────────────────────────────

/**
 * Validate a single IOC and attach validation metadata.
 */
function validateIOC(ioc: IOC): IOC {
  const validator = validators[ioc.type];
  if (!validator) {
    return { ...ioc, validation: { valid: true, warnings: [`Unknown IOC type: ${ioc.type}`] } };
  }
  const result = validator(ioc.value);
  return { ...ioc, validation: result };
}

/** Confidence rank for merging — keep the highest. */
const CONFIDENCE_RANK: Record<string, number> = { High: 3, Medium: 2, Low: 1 };

/**
 * Validate all IOCs and deduplicate by type + normalized value.
 * Duplicates are merged: highest confidence kept, contexts concatenated.
 */
export function validateAndDeduplicateIOCs(iocs: IOC[]): IOC[] {
  // Validate each IOC
  const validated = iocs.map(validateIOC);

  // Deduplicate by type + normalized value
  const seen = new Map<string, IOC>();

  for (const ioc of validated) {
    const key = `${ioc.type}::${ioc.value.trim().toLowerCase()}`;
    const existing = seen.get(key);

    if (!existing) {
      seen.set(key, { ...ioc, duplicateCount: 1 });
    } else {
      // Merge: keep highest confidence
      const existingRank = CONFIDENCE_RANK[existing.confidence] ?? 0;
      const newRank = CONFIDENCE_RANK[ioc.confidence] ?? 0;
      if (newRank > existingRank) {
        existing.confidence = ioc.confidence;
      }
      // Append context if different
      if (ioc.context && !existing.context.includes(ioc.context)) {
        existing.context = `${existing.context} | ${ioc.context}`;
        // Trim merged context to a reasonable length
        if (existing.context.length > 200) {
          existing.context = existing.context.slice(0, 197) + '...';
        }
      }
      // Merge warnings
      if (ioc.validation && existing.validation) {
        const warnSet = new Set([...existing.validation.warnings, ...ioc.validation.warnings]);
        existing.validation.warnings = Array.from(warnSet);
        existing.validation.valid = existing.validation.valid && ioc.validation.valid;
      }
      existing.duplicateCount = (existing.duplicateCount ?? 1) + 1;
    }
  }

  return Array.from(seen.values());
}
