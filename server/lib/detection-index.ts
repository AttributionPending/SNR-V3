/**
 * Cross-session detection-rule index (server/db `detection_rule_observations`).
 *
 * The index is DERIVED STATE — analysis_results.result_json is the source of
 * truth. `reindexSessionDetectionRules` rebuilds a session's rows idempotently
 * from its result, so the table can be dropped and repopulated at any time (and
 * the 016 migration backfills it the same way). Mirrors ./ioc-index.ts.
 *
 * Coverage groups rules by the ATT&CK technique they detect. `related_technique`
 * is prompted as a bare id but arrives in mixed shapes, so it is normalized to a
 * canonical `T####[.###]` (or null for an unmapped rule).
 */
import crypto from 'crypto';
import logger from './logger.js';

interface RuleLike {
  rule_type?: string;
  rule_name?: string;
  rule_content?: string;
  description?: string;
  source?: string;
  confidence?: string;
  related_technique?: string | null;
}

interface ResultLike {
  detection_rules?: RuleLike[];
}

/**
 * Parse an ATT&CK technique id out of a rule's `related_technique`.
 * Accepts `T1059.001`, `t1059`, `T1566 - Phishing`, `ATT&CK T1071.001`, …
 * Returns the uppercased id, or null when there is nothing usable.
 */
export function normalizeTechniqueId(raw: string | null | undefined): string | null {
  if (!raw) return null;
  const m = /T\d{4}(?:\.\d{3})?/i.exec(raw);
  return m ? m[0].toUpperCase() : null;
}

/**
 * Stable identity for a rule body, so the same rule recurring across sessions
 * collapses to one "distinct" rule. Whitespace-normalized before hashing —
 * regenerated rules often differ only in indentation.
 */
export function ruleHash(content: string | undefined): string {
  return crypto.createHash('sha256').update((content ?? '').replace(/\s+/g, ' ').trim()).digest('hex');
}

/** How a technique's two coverage signals combine into one status. */
export type CoverageStatus = 'covered' | 'partial' | 'gap' | 'unknown';

/**
 * Derive a technique's coverage from BOTH signals:
 *  - ruleCount: detection rules we have written that map to it
 *  - gapVotes:  analyses that judged it a Detection Gap
 * `partial` is the interesting disagreement — rules exist, yet analysis still
 * reports the technique as a gap.
 */
export function coverageStatus(ruleCount: number, gapVotes: number, detectedVotes: number): CoverageStatus {
  if (ruleCount > 0) return gapVotes > 0 ? 'partial' : 'covered';
  if (gapVotes > 0) return 'gap';
  return detectedVotes > 0 ? 'covered' : 'unknown';
}

/**
 * Rebuild the detection_rule_observations rows for one session from its result.
 * Deletes the session's existing rows first, then inserts one row per distinct
 * (rule_type, rule_name, rule_hash). Best-effort — the caller wraps this in
 * try/catch so an index failure never breaks analysis or authoring.
 */
export async function reindexSessionDetectionRules(
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  db: any,
  sessionId: string,
  teamId: string,
  result: ResultLike,
): Promise<void> {
  const now = Date.now();

  await db.prepare('DELETE FROM detection_rule_observations WHERE session_id = ?').run(sessionId);

  const rules = Array.isArray(result.detection_rules) ? result.detection_rules : [];
  if (rules.length === 0) return;

  // Dedupe within the session — the UNIQUE constraint would reject the second
  // row anyway; doing it here keeps the insert clean.
  const seen = new Set<string>();
  let inserted = 0;
  for (const rule of rules) {
    const type = (rule?.rule_type ?? '').trim().toLowerCase();
    const name = (rule?.rule_name ?? '').trim();
    if (!type || !name) continue;
    const hash = ruleHash(rule.rule_content);
    const dedupeKey = `${type}::${name}::${hash}`;
    if (seen.has(dedupeKey)) continue;
    seen.add(dedupeKey);

    await db
      .prepare(
        `INSERT INTO detection_rule_observations
           (id, team_id, session_id, rule_type, rule_name, rule_hash, rule_content, description, source, confidence, technique_id, created_at)
         VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
         ON CONFLICT (session_id, rule_type, rule_name, rule_hash) DO NOTHING`,
      )
      .run(
        crypto.randomUUID(),
        teamId,
        sessionId,
        type,
        name,
        hash,
        rule.rule_content ?? '',
        rule.description ?? '',
        rule.source ?? 'generated',
        rule.confidence ?? null,
        normalizeTechniqueId(rule.related_technique),
        now,
      );
    inserted++;
  }

  logger.debug({ sessionId, count: inserted }, 'Reindexed session detection rules');
}
