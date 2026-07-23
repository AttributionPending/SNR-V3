/**
 * Guarded outbound HTTP for enrichment providers.
 *
 * Provider URLs are supplied by admins, so a naive fetch would be an SSRF path
 * into the internal network (cloud metadata, container services, databases).
 * `safeFetch` enforces:
 *   - https only
 *   - the destination IP must be public — private / loopback / link-local /
 *     unique-local / CGNAT / metadata ranges are refused, for IPv4 and IPv6
 *   - the check runs at CONNECT time via a custom agent `lookup`, so a hostname
 *     that resolves public-then-private (DNS rebinding) still cannot connect
 *   - redirects are not followed automatically; each hop is re-validated
 *   - a request timeout and a response byte cap
 *
 * Exported predicates are pure so they can be unit-tested without network.
 */
import https from 'node:https';
import dns from 'node:dns';
import net from 'node:net';

export class EgressBlockedError extends Error {
  constructor(message: string) { super(message); this.name = 'EgressBlockedError'; }
}

const USER_AGENT = 'SNR-Enrichment/1.0';
const DEFAULT_TIMEOUT_MS = 10_000;
const MAX_BYTES = 512 * 1024;      // enrichment payloads are small; cap hard
const MAX_REDIRECTS = 3;

/** True when an IPv4 literal is outside the publicly routable space. */
export function isBlockedIPv4(ip: string): boolean {
  const p = ip.split('.').map(Number);
  if (p.length !== 4 || p.some((n) => !Number.isInteger(n) || n < 0 || n > 255)) return true;
  const [a, b] = p as [number, number, number, number];
  if (a === 0) return true;                              // "this" network
  if (a === 10) return true;                             // RFC1918
  if (a === 127) return true;                            // loopback
  if (a === 169 && b === 254) return true;               // link-local + AWS/GCP metadata
  if (a === 172 && b >= 16 && b <= 31) return true;      // RFC1918
  if (a === 192 && b === 168) return true;               // RFC1918
  if (a === 100 && b >= 64 && b <= 127) return true;     // CGNAT (RFC6598)
  if (a === 192 && b === 0) return true;                 // IETF protocol assignments
  if (a >= 224) return true;                             // multicast + reserved + broadcast
  return false;
}

/** True when an IPv6 literal is outside the publicly routable space. */
export function isBlockedIPv6(ip: string): boolean {
  const v = ip.toLowerCase().split('%')[0]!;             // strip zone id
  if (v === '::' || v === '::1') return true;            // unspecified / loopback
  // IPv4-mapped (::ffff:10.0.0.1) — judge by the embedded v4 address.
  const mapped = v.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/);
  if (mapped) return isBlockedIPv4(mapped[1]!);
  if (v.startsWith('fe80') || v.startsWith('fe9') || v.startsWith('fea') || v.startsWith('feb')) return true; // link-local
  if (/^f[cd]/.test(v)) return true;                     // unique-local fc00::/7
  if (v.startsWith('ff')) return true;                   // multicast
  return false;
}

export function isBlockedAddress(ip: string): boolean {
  const fam = net.isIP(ip);
  if (fam === 4) return isBlockedIPv4(ip);
  if (fam === 6) return isBlockedIPv6(ip);
  return true; // not an IP literal → refuse rather than guess
}

/** Validate the URL shape (https, sane port). Throws EgressBlockedError. */
export function assertSafeUrl(raw: string): URL {
  let u: URL;
  try { u = new URL(raw); } catch { throw new EgressBlockedError('Invalid URL'); }
  if (u.protocol !== 'https:') throw new EgressBlockedError('Only https:// URLs are allowed');
  // A bare IP literal host is checked here too; hostnames are checked at connect.
  if (net.isIP(u.hostname) && isBlockedAddress(u.hostname)) {
    throw new EgressBlockedError(`Destination ${u.hostname} is not a public address`);
  }
  return u;
}

/**
 * https.Agent whose DNS lookup refuses non-public results. Because Node calls
 * this immediately before connecting, a rebinding answer is caught here rather
 * than in a separate earlier resolve.
 */
function guardedAgent(): https.Agent {
  return new https.Agent({
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    lookup: (hostname: string, options: any, callback: any) => {
      dns.lookup(hostname, { ...options, all: true }, (err, addresses) => {
        if (err) return callback(err);
        const list = (Array.isArray(addresses) ? addresses : [addresses]) as Array<{ address: string; family: number }>;
        const blocked = list.find((a) => isBlockedAddress(a.address));
        if (blocked) {
          return callback(new EgressBlockedError(`${hostname} resolves to a non-public address (${blocked.address})`));
        }
        const first = list[0]!;
        return options?.all ? callback(null, list) : callback(null, first.address, first.family);
      });
    },
  });
}

export interface SafeFetchResult {
  status: number;
  /** Parsed JSON body, or null when the body was empty / not JSON. */
  json: unknown;
}

interface RawResponse { status: number; location: string | undefined; body: string }

/**
 * One request via node:https. We deliberately do NOT use global fetch here:
 * fetch is undici-backed and ignores the `agent` option, which would silently
 * bypass the connect-time address guard. https.request honours agent.lookup.
 */
function requestOnce(url: URL, headers: Record<string, string>, timeoutMs: number): Promise<RawResponse> {
  return new Promise<RawResponse>((resolve, reject) => {
    const agent = guardedAgent();
    const req = https.request(
      url,
      {
        method: 'GET',
        // Several public APIs (GitHub among them) reject requests with no
        // User-Agent; providers can still override either default.
        headers: { accept: 'application/json', 'user-agent': USER_AGENT, ...headers },
        agent,
        timeout: timeoutMs,
      },
      (res) => {
        let size = 0;
        const chunks: Buffer[] = [];
        res.on('data', (c: Buffer) => {
          size += c.length;
          if (size > MAX_BYTES) { req.destroy(new Error('Response too large')); return; }
          chunks.push(c);
        });
        res.on('end', () => {
          agent.destroy();
          resolve({
            status: res.statusCode ?? 0,
            location: res.headers.location,
            body: Buffer.concat(chunks).toString('utf8'),
          });
        });
      },
    );
    req.on('timeout', () => req.destroy(new Error('Request timed out')));
    req.on('error', (e) => { agent.destroy(); reject(e); });
    req.end();
  });
}

/**
 * Fetch a public https JSON endpoint with SSRF, timeout and size guards.
 * Redirects are re-validated per hop. Throws EgressBlockedError on policy
 * violations; other network failures throw plain Errors.
 */
export async function safeFetch(
  rawUrl: string,
  init: { headers?: Record<string, string>; timeoutMs?: number } = {},
): Promise<SafeFetchResult> {
  let url = assertSafeUrl(rawUrl);
  const timeoutMs = init.timeoutMs ?? DEFAULT_TIMEOUT_MS;

  for (let hop = 0; hop <= MAX_REDIRECTS; hop++) {
    const res = await requestOnce(url, init.headers ?? {}, timeoutMs);

    if (res.status >= 300 && res.status < 400) {
      if (!res.location) throw new Error(`Redirect ${res.status} without Location`);
      url = assertSafeUrl(new URL(res.location, url).toString());  // re-validate every hop
      continue;
    }

    let json: unknown = null;
    if (res.body.trim()) { try { json = JSON.parse(res.body); } catch { json = null; } }
    return { status: res.status, json };
  }
  throw new Error('Too many redirects');
}
