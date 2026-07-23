/**
 * Generic HTTP enrichment executor.
 *
 * Turns a stored provider row (catalog preset OR custom) into an
 * `EnrichmentProvider`. One implementation serves every vendor: the row's
 * `config` supplies the URL, headers, and the response→display mapping.
 *
 * Deliberately small: dot-path extraction and `{token}` substitution rather than
 * a JSONPath/expression engine, which would be a needless attack surface for
 * admin-authored config.
 */
import { vtPathFor, type FactSpec, type HttpProviderConfig } from './catalog.js';
import { safeFetch, EgressBlockedError } from './egress.js';
import type { EnrichmentProvider, EnrichmentRequest, EnrichmentResult } from './types.js';

export interface ProviderRow {
  id: string;
  name: string;
  kind: string;
  api_key: string | null;
  config: string;   // JSON HttpProviderConfig
}

/** Read `a.b.0.c` out of a parsed JSON body. Returns undefined when absent. */
export function getPath(obj: unknown, path: string): unknown {
  return path.split('.').reduce<unknown>((acc, key) => {
    if (acc == null) return undefined;
    if (Array.isArray(acc)) {
      const i = Number(key);
      return Number.isInteger(i) ? acc[i] : undefined;
    }
    if (typeof acc === 'object') return (acc as Record<string, unknown>)[key];
    return undefined;
  }, obj);
}

function display(v: unknown): string {
  if (v == null) return '—';
  if (Array.isArray(v)) return v.slice(0, 12).join(', ');
  if (typeof v === 'object') return JSON.stringify(v).slice(0, 120);
  return String(v);
}

export function parseConfig(raw: string): HttpProviderConfig {
  try {
    const c = JSON.parse(raw) as Partial<HttpProviderConfig>;
    return {
      supports: Array.isArray(c.supports) ? c.supports : [],
      url: typeof c.url === 'string' ? c.url : '',
      headers: c.headers ?? {},
      summary: c.summary,
      facts: Array.isArray(c.facts) ? c.facts : [],
      link: c.link,
      notFound: Array.isArray(c.notFound) ? c.notFound : [404],
    };
  } catch {
    return { supports: [], url: '', headers: {}, facts: [], notFound: [404] };
  }
}

/** Substitute {value}, {api_key}, {vt_path} … and any {dot.path} from `body`. */
export function render(
  template: string,
  ctx: { value: string; apiKey: string; type: string },
  body?: unknown,
): string {
  return template.replace(/\{([^}]+)\}/g, (_m, token: string) => {
    switch (token) {
      case 'value': return ctx.value;
      case 'value_enc': return encodeURIComponent(ctx.value);
      case 'value_b64url': return Buffer.from(ctx.value).toString('base64url');
      case 'api_key': return ctx.apiKey;
      case 'vt_path': return vtPathFor(ctx.type);
      case 'type': return ctx.type;
      default: return body !== undefined ? display(getPath(body, token)) : '';
    }
  });
}

function mapFacts(specs: FactSpec[], body: unknown): EnrichmentResult['facts'] {
  return specs
    .map((f) => ({ label: f.label, value: display(getPath(body, f.path)), tone: f.tone }))
    .filter((f) => f.value !== '—');
}

/**
 * Build an EnrichmentProvider from a stored row. `cache` lets the caller supply
 * DB-backed read/write so repeat card opens don't re-bill the vendor API.
 */
export function providerFromRow(
  row: ProviderRow,
  cache?: {
    read: (providerId: string, type: string, value: string) => Promise<EnrichmentResult | null>;
    write: (providerId: string, type: string, value: string, result: EnrichmentResult) => Promise<void>;
  },
): EnrichmentProvider {
  const cfg = parseConfig(row.config);
  const base = { providerId: row.id, providerName: row.name };

  return {
    id: row.id,
    name: row.name,
    requiredSettings: ['API key'],
    supports: (type) => cfg.supports.includes(type),
    // A key is only required when the config actually references one.
    isConfigured: () => {
      const needsKey = /\{api_key\}/.test(cfg.url) || Object.values(cfg.headers ?? {}).some((h) => /\{api_key\}/.test(h));
      return !needsKey || !!row.api_key;
    },

    async enrich({ type, value }: EnrichmentRequest): Promise<EnrichmentResult> {
      const cached = cache ? await cache.read(row.id, type, value) : null;
      if (cached) return cached;

      const ctx = { value, apiKey: row.api_key ?? '', type };
      if (!cfg.url) return { ...base, status: 'error', message: 'Provider has no URL configured.' };

      let result: EnrichmentResult;
      try {
        const { status, json } = await safeFetch(render(cfg.url, ctx), {
          headers: Object.fromEntries(Object.entries(cfg.headers ?? {}).map(([k, v]) => [k, render(v, ctx)])),
        });

        if ((cfg.notFound ?? [404]).includes(status)) {
          result = { ...base, status: 'not_found', fetchedAt: Date.now() };
        } else if (status < 200 || status >= 300) {
          // Surface the vendor's status — 401/403 (bad key) and 429 (quota) are
          // the two an operator actually needs to see.
          return { ...base, status: 'error', message: `Provider returned HTTP ${status}.` };
        } else {
          result = {
            ...base,
            status: 'ok',
            summary: cfg.summary ? render(cfg.summary, ctx, json) : undefined,
            facts: mapFacts(cfg.facts ?? [], json),
            link: cfg.link ? render(cfg.link, ctx) : undefined,
            fetchedAt: Date.now(),
          };
        }
      } catch (err) {
        const msg = err instanceof EgressBlockedError
          ? `Blocked: ${err.message}`
          : `Lookup failed: ${(err as Error).message}`;
        return { ...base, status: 'error', message: msg };
      }

      if (cache) await cache.write(row.id, type, value, result);
      return result;
    },
  };
}
