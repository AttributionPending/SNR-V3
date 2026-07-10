/**
 * Cross-session IOC index (server/db `ioc_observations`).
 *
 * The index is DERIVED STATE — analysis_results.result_json is the source of
 * truth. `reindexSessionIocs` rebuilds a session's rows idempotently from its
 * result, so the table can be dropped and repopulated at any time (and the
 * 008 migration backfills it the same way).
 *
 * Correlation groups indicators by (type, normalized value). The normalized
 * value refangs (hxxp→http, [.]→., [:]→:), trims, and lowercases — a superset
 * of the UI's iocKey (`${type}::${lower(trim(value))}`) so defanged variants of
 * the same indicator collapse to one.
 */
import crypto from 'crypto';
import logger from './logger.js';

interface IocLike {
  type: string;
  value: string;
  context?: string;
  confidence?: string;
}

interface ResultLike {
  iocs?: IocLike[];
}

/**
 * Normalize an IOC value into its correlation key (value only, no type prefix).
 * For a value with no defanging this is exactly `value.trim().toLowerCase()`,
 * matching the value half of the UI's `iocKey` so counts line up.
 */
export function normalizeIocValue(_type: string, value: string): string {
  return value
    .replace(/hxxp/gi, 'http')
    .replace(/\[\.\]/g, '.')
    .replace(/\[:\]/g, ':')
    .trim()
    .toLowerCase();
}

/** The UI/dedupe identity key for an IOC: `${type}::${normalized value}`. */
export function iocIndexKey(type: string, value: string): string {
  return `${type}::${normalizeIocValue(type, value)}`;
}

/**
 * Rebuild the ioc_observations rows for one session from its result. Deletes the
 * session's existing rows first, then inserts one row per distinct (type, norm).
 * `falsePositiveKeys` are `${type}::${lower(trim(value))}` strings from
 * analyst_overrides.ioc_false_positives. Best-effort — the caller wraps this in
 * try/catch so an index failure never breaks analysis or authoring.
 */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
export async function reindexSessionIocs(
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  db: any,
  sessionId: string,
  teamId: string,
  result: ResultLike,
  falsePositiveKeys: string[] = [],
): Promise<void> {
  const fpSet = new Set(falsePositiveKeys.map((k) => k.toLowerCase()));
  const now = Date.now();

  await db.prepare('DELETE FROM ioc_observations WHERE session_id = ?').run(sessionId);

  const iocs = Array.isArray(result.iocs) ? result.iocs : [];
  if (iocs.length === 0) return;

  // Dedupe within the session by (type, norm) — the UNIQUE constraint would
  // reject the second row anyway; doing it here keeps the insert clean.
  const seen = new Set<string>();
  for (const ioc of iocs) {
    if (!ioc?.type || !ioc?.value || !ioc.value.trim()) continue;
    const norm = normalizeIocValue(ioc.type, ioc.value);
    const dedupeKey = `${ioc.type}::${norm}`;
    if (seen.has(dedupeKey)) continue;
    seen.add(dedupeKey);

    // FP keys are stored in the UI's plain form (`type::lower(trim(value))`).
    const fpKey = `${ioc.type}::${ioc.value.trim().toLowerCase()}`;
    const isFp = fpSet.has(fpKey.toLowerCase()) || fpSet.has(dedupeKey.toLowerCase());

    await db
      .prepare(
        `INSERT INTO ioc_observations
           (id, team_id, session_id, ioc_type, ioc_value, ioc_value_norm, context, confidence, is_false_positive, created_at)
         VALUES (?,?,?,?,?,?,?,?,?,?)
         ON CONFLICT (session_id, ioc_type, ioc_value_norm) DO NOTHING`,
      )
      .run(
        crypto.randomUUID(),
        teamId,
        sessionId,
        ioc.type,
        ioc.value,
        norm,
        ioc.context ?? '',
        ioc.confidence ?? null,
        isFp ? 1 : 0,
        now,
      );
  }

  logger.debug({ sessionId, count: seen.size }, 'Reindexed session IOCs');
}

/** Parse analyst_overrides.ioc_false_positives (a JSON array of key strings). */
export function parseFalsePositiveKeys(overridesJson: string | null | undefined): string[] {
  if (!overridesJson) return [];
  try {
    const overrides = JSON.parse(overridesJson) as Record<string, unknown>;
    const raw = overrides['ioc_false_positives'];
    const arr = typeof raw === 'string' ? JSON.parse(raw) : raw;
    return Array.isArray(arr) ? arr.filter((x): x is string => typeof x === 'string') : [];
  } catch {
    return [];
  }
}
