/**
 * Enrichment provider registry — DB-backed.
 *
 * Providers are rows in `enrichment_providers`, added per team from the Admin
 * panel (catalog preset or Custom HTTP). Every row is executed by the same
 * generic HTTP executor (./http-provider.ts) behind the SSRF guard (./egress.ts).
 *
 * With no rows configured, `enrichIndicator` returns [] and no indicator value
 * leaves the network.
 */
import logger from '../logger.js';
import { getDb } from '../../db/database.js';
import { providerFromRow, type ProviderRow } from './http-provider.js';
import type { EnrichmentProvider, EnrichmentRequest, EnrichmentResult, IocType } from './types.js';

/** Cached provider responses expire after this long. */
const CACHE_TTL_MS = 60 * 60 * 1000; // 1 hour

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type Db = any;

/** `skipRead` powers the card's Refresh button: re-query the vendor, then
 *  overwrite the cached copy. Writes always happen so the next open is cheap. */
const cacheIo = (db: Db, skipRead = false) => ({
  async read(providerId: string, type: string, value: string): Promise<EnrichmentResult | null> {
    if (skipRead) return null;
    const row = (await db.prepare(
      'SELECT payload, fetched_at FROM enrichment_cache WHERE provider_id = ? AND ioc_type = ? AND ioc_value_norm = ?',
    ).get(providerId, type, value)) as { payload: string; fetched_at: number } | undefined;
    if (!row) return null;
    if (Date.now() - Number(row.fetched_at) > CACHE_TTL_MS) return null;
    try { return JSON.parse(row.payload) as EnrichmentResult; } catch { return null; }
  },
  async write(providerId: string, type: string, value: string, result: EnrichmentResult): Promise<void> {
    await db.prepare(`
      INSERT INTO enrichment_cache (provider_id, ioc_type, ioc_value_norm, payload, fetched_at)
      VALUES (?,?,?,?,?)
      ON CONFLICT (provider_id, ioc_type, ioc_value_norm)
      DO UPDATE SET payload = EXCLUDED.payload, fetched_at = EXCLUDED.fetched_at
    `).run(providerId, type, value, JSON.stringify(result), Date.now());
  },
});

/** Enabled providers for a team, as executable EnrichmentProviders. */
export async function loadProviders(
  teamId: string,
  opts: { includeDisabled?: boolean; noCache?: boolean } = {},
): Promise<EnrichmentProvider[]> {
  if (!teamId) return [];
  const db = getDb();
  const rows = (await db.prepare(
    `SELECT id, name, kind, api_key, config FROM enrichment_providers
     WHERE team_id = ? ${opts.includeDisabled ? '' : 'AND enabled = 1'}
     ORDER BY created_at ASC`,
  ).all(teamId)) as ProviderRow[];
  const io = cacheIo(db, opts.noCache);
  return rows.map((r) => providerFromRow(r, io));
}

/** Providers for a team that handle this indicator type. */
export async function providersFor(teamId: string, type: IocType): Promise<EnrichmentProvider[]> {
  return (await loadProviders(teamId)).filter((p) => p.supports(type));
}

/**
 * Run every enabled provider that supports this indicator type. Unconfigured
 * providers are reported (so the UI can prompt) rather than silently skipped.
 * Runs in parallel and never rejects — one bad provider cannot break the card.
 */
export async function enrichIndicator(
  req: EnrichmentRequest,
  opts: { noCache?: boolean } = {},
): Promise<EnrichmentResult[]> {
  const applicable = (await loadProviders(req.teamId, { noCache: opts.noCache }))
    .filter((p) => p.supports(req.type));
  if (applicable.length === 0) return [];

  return Promise.all(applicable.map(async (p): Promise<EnrichmentResult> => {
    if (!p.isConfigured(req.settings)) {
      return {
        providerId: p.id,
        providerName: p.name,
        status: 'unconfigured',
        message: `Add an API key for ${p.name} in Admin → Enrichment.`,
      };
    }
    try {
      return await p.enrich(req);
    } catch (err) {
      logger.warn({ provider: p.id, err: (err as Error).message }, 'Enrichment provider failed');
      return {
        providerId: p.id,
        providerName: p.name,
        status: 'error',
        message: 'Lookup failed. Check the provider configuration and try again.',
      };
    }
  }));
}

/** Drop cached responses for a provider (called when its config/key changes). */
export async function invalidateProviderCache(providerId: string): Promise<void> {
  await getDb().prepare('DELETE FROM enrichment_cache WHERE provider_id = ?').run(providerId);
}

export type { EnrichmentProvider, EnrichmentRequest, EnrichmentResult } from './types.js';
