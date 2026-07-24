/**
 * Guarded outbound HTTP for admin-supplied URLs (enrichment providers and
 * threat feeds).
 *
 * Those URLs are operator-controlled, so a naive fetch is an SSRF path into the
 * internal network (cloud metadata, container services, databases). Guarantees:
 *   - https only, unless a caller explicitly opts into an internal destination
 *   - the destination IP is classified, not just the hostname
 *   - the check runs at CONNECT time via a custom agent `lookup`, so a hostname
 *     that resolves public-then-private (DNS rebinding) still cannot connect
 *   - redirects are not followed automatically; each hop is re-validated
 *   - request timeout and response byte cap
 *
 * Two tiers of address:
 *   'blocked' — loopback, link-local (incl. 169.254.169.254 cloud metadata),
 *               unspecified and multicast/reserved. Refused ALWAYS, even for
 *               callers that opt into internal hosts.
 *   'private' — RFC1918, CGNAT and IPv6 unique-local. Refused by default;
 *               permitted only when the caller passes `allowInternal` (used by
 *               feeds explicitly marked as self-hosted MISP/TAXII servers).
 *
 * Exported predicates are pure so they can be unit-tested without network.
 */
import https from 'node:https';
import http from 'node:http';
import dns from 'node:dns';
import net from 'node:net';

export class EgressBlockedError extends Error {
  constructor(message: string) { super(message); this.name = 'EgressBlockedError'; }
}

const USER_AGENT = 'SNR-Enrichment/1.0';
const DEFAULT_TIMEOUT_MS = 10_000;
const DEFAULT_MAX_BYTES = 512 * 1024;
const MAX_REDIRECTS = 3;

export type AddressClass = 'public' | 'private' | 'blocked';

export function classifyIPv4(ip: string): AddressClass {
  const p = ip.split('.').map(Number);
  if (p.length !== 4 || p.some((n) => !Number.isInteger(n) || n < 0 || n > 255)) return 'blocked';
  const [a, b] = p as [number, number, number, number];
  if (a === 0) return 'blocked';                          // unspecified / "this" network
  if (a === 127) return 'blocked';                        // loopback
  if (a === 169 && b === 254) return 'blocked';           // link-local + cloud metadata
  if (a >= 224) return 'blocked';                         // multicast, reserved, broadcast
  if (a === 192 && b === 0) return 'blocked';             // IETF protocol assignments
  if (a === 10) return 'private';                         // RFC1918
  if (a === 172 && b >= 16 && b <= 31) return 'private';  // RFC1918
  if (a === 192 && b === 168) return 'private';           // RFC1918
  if (a === 100 && b >= 64 && b <= 127) return 'private'; // CGNAT (RFC6598)
  return 'public';
}

export function classifyIPv6(ip: string): AddressClass {
  const v = ip.toLowerCase().split('%')[0]!;              // strip zone id
  if (v === '::' || v === '::1') return 'blocked';        // unspecified / loopback
  // IPv4-mapped (::ffff:10.0.0.1) — judge by the embedded v4 address.
  const mapped = v.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/);
  if (mapped) return classifyIPv4(mapped[1]!);
  if (/^fe[89ab]/.test(v)) return 'blocked';              // link-local fe80::/10
  if (v.startsWith('ff')) return 'blocked';               // multicast
  if (/^f[cd]/.test(v)) return 'private';                 // unique-local fc00::/7
  return 'public';
}

export function classifyAddress(ip: string): AddressClass {
  const fam = net.isIP(ip);
  if (fam === 4) return classifyIPv4(ip);
  if (fam === 6) return classifyIPv6(ip);
  return 'blocked';   // not an IP literal → refuse rather than guess
}

/** Strict (public-only) predicates — the default policy. */
export function isBlockedIPv4(ip: string): boolean { return classifyIPv4(ip) !== 'public'; }
export function isBlockedIPv6(ip: string): boolean { return classifyIPv6(ip) !== 'public'; }

export function isBlockedAddress(ip: string, allowInternal = false): boolean {
  const c = classifyAddress(ip);
  if (c === 'blocked') return true;                       // never permitted
  if (c === 'private') return !allowInternal;             // opt-in only
  return false;
}

export interface EgressOptions {
  method?: 'GET' | 'POST';
  headers?: Record<string, string>;
  body?: string;
  timeoutMs?: number;
  maxBytes?: number;
  /**
   * Permit RFC1918 / CGNAT / unique-local destinations and plain http — an
   * explicit per-feed opt-in for self-hosted MISP/TAXII. Loopback and cloud
   * metadata remain blocked.
   */
  allowInternal?: boolean;
}

/** Validate the URL shape. Throws EgressBlockedError. */
export function assertSafeUrl(raw: string, allowInternal = false): URL {
  let u: URL;
  try { u = new URL(raw); } catch { throw new EgressBlockedError('Invalid URL'); }
  if (u.protocol !== 'https:' && !(allowInternal && u.protocol === 'http:')) {
    throw new EgressBlockedError('Only https:// URLs are allowed');
  }
  // A bare IP literal host is checked here too; hostnames are checked at connect.
  if (net.isIP(u.hostname) && isBlockedAddress(u.hostname, allowInternal)) {
    throw new EgressBlockedError(`Destination ${u.hostname} is not an allowed address`);
  }
  return u;
}

/**
 * Agent whose DNS lookup refuses disallowed results. Node calls this
 * immediately before connecting, so a rebinding answer is caught here rather
 * than in a separate earlier resolve.
 */
function guardedAgent(secure: boolean, allowInternal: boolean): https.Agent | http.Agent {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const lookup = (hostname: string, options: any, callback: any) => {
    dns.lookup(hostname, { ...options, all: true }, (err, addresses) => {
      if (err) return callback(err);
      const list = (Array.isArray(addresses) ? addresses : [addresses]) as Array<{ address: string; family: number }>;
      const bad = list.find((a) => isBlockedAddress(a.address, allowInternal));
      if (bad) {
        return callback(new EgressBlockedError(`${hostname} resolves to a disallowed address (${bad.address})`));
      }
      const first = list[0]!;
      return options?.all ? callback(null, list) : callback(null, first.address, first.family);
    });
  };
  return secure ? new https.Agent({ lookup }) : new http.Agent({ lookup });
}

export interface SafeResponse {
  status: number;
  /** Raw response text (XML for RSS, JSON for TAXII/MISP/enrichment). */
  body: string;
  /** Parsed JSON, or null when the body is empty / not JSON. */
  json(): unknown;
}

interface RawResponse { status: number; location: string | undefined; body: string }

/**
 * One request via node:http(s). We deliberately do NOT use global fetch: it is
 * undici-backed and ignores the `agent` option, which would silently bypass the
 * connect-time address guard.
 */
function requestOnce(url: URL, opts: EgressOptions): Promise<RawResponse> {
  const secure = url.protocol === 'https:';
  const maxBytes = opts.maxBytes ?? DEFAULT_MAX_BYTES;
  return new Promise<RawResponse>((resolve, reject) => {
    const agent = guardedAgent(secure, !!opts.allowInternal);
    const mod = secure ? https : http;
    const req = mod.request(
      url,
      {
        method: opts.method ?? 'GET',
        headers: { accept: 'application/json', 'user-agent': USER_AGENT, ...(opts.headers ?? {}) },
        agent,
        timeout: opts.timeoutMs ?? DEFAULT_TIMEOUT_MS,
      },
      (res) => {
        let size = 0;
        const chunks: Buffer[] = [];
        res.on('data', (c: Buffer) => {
          size += c.length;
          if (size > maxBytes) { req.destroy(new Error('Response too large')); return; }
          chunks.push(c);
        });
        res.on('end', () => {
          agent.destroy();
          resolve({ status: res.statusCode ?? 0, location: res.headers.location, body: Buffer.concat(chunks).toString('utf8') });
        });
      },
    );
    req.on('timeout', () => req.destroy(new Error('Request timed out')));
    req.on('error', (e) => { agent.destroy(); reject(e); });
    if (opts.body) req.write(opts.body);
    req.end();
  });
}

/**
 * Guarded request returning the raw body. Redirects are re-validated per hop.
 * Throws EgressBlockedError on policy violations; other failures throw Errors.
 * Does NOT throw on non-2xx — inspect `status`.
 */
export async function safeRequest(rawUrl: string, opts: EgressOptions = {}): Promise<SafeResponse> {
  let url = assertSafeUrl(rawUrl, opts.allowInternal);

  for (let hop = 0; hop <= MAX_REDIRECTS; hop++) {
    const res = await requestOnce(url, opts);

    if (res.status >= 300 && res.status < 400) {
      if (!res.location) throw new Error(`Redirect ${res.status} without Location`);
      url = assertSafeUrl(new URL(res.location, url).toString(), opts.allowInternal);  // re-validate every hop
      continue;
    }

    return {
      status: res.status,
      body: res.body,
      json: () => { try { return res.body.trim() ? JSON.parse(res.body) : null; } catch { return null; } },
    };
  }
  throw new Error('Too many redirects');
}

/** JSON convenience used by enrichment providers (public https, GET). */
export async function safeFetch(
  rawUrl: string,
  init: { headers?: Record<string, string>; timeoutMs?: number } = {},
): Promise<{ status: number; json: unknown }> {
  const res = await safeRequest(rawUrl, init);
  return { status: res.status, json: res.json() };
}
