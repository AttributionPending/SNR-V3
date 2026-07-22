/**
 * Shared SQL for the merged indicator view: report-derived observations
 * (ioc_observations, live sessions only) UNIONed with analyst-curated manual
 * indicators (manual_iocs) AND indicators pinned directly to a case (case_iocs),
 * collapsed by (type, normalized value). Used by the IOC browse list and the
 * Intelligence overview/holdings so a curated indicator and a later report
 * observation of the same value appear as one row, flagged `is_manual` with an
 * incident `session_count` (0 for curated-only). Case indicators carry the case
 * name as their `source`.
 *
 * The returned `cte` is a leading WITH clause; append your own
 * `SELECT ... FROM combined ...`. `params` are the placeholder values the CTE
 * consumes and must be bound FIRST (before any outer-query params). Pass a
 * falsy teamId for an org-wide (admin, no active team) view.
 */
export function combinedIndicatorsCte(teamId: string | undefined): { cte: string; params: unknown[] } {
  const oTeam = teamId ? 'AND o.team_id = ?' : '';
  const mWhere = teamId ? 'WHERE m.team_id = ?' : '';
  const cWhere = teamId ? 'WHERE c.team_id = ?' : '';
  const cte = `
    WITH combined AS (
      SELECT o.ioc_type AS type, o.ioc_value_norm AS norm, o.ioc_value AS value,
             o.session_id AS session_id, o.created_at AS created_at,
             0 AS is_manual, CAST(NULL AS TEXT) AS source
      FROM ioc_observations o
      JOIN sessions s ON s.id = o.session_id
      WHERE s.deleted_at IS NULL AND s.status = 'complete' ${oTeam}
      UNION ALL
      SELECT m.ioc_type, m.ioc_value_norm, m.ioc_value,
             CAST(NULL AS TEXT), m.created_at, 1, m.source
      FROM manual_iocs m ${mWhere}
      UNION ALL
      SELECT ci.ioc_type, ci.ioc_value_norm, ci.ioc_value,
             CAST(NULL AS TEXT), ci.added_at, 1, c.name
      FROM case_iocs ci
      JOIN cases c ON c.id = ci.case_id ${cWhere}
    )`;
  const params: unknown[] = [];
  if (teamId) { params.push(teamId); params.push(teamId); params.push(teamId); }
  return { cte, params };
}

/** The aggregated column list for a merged-indicator row (over `combined`). */
export const COMBINED_SELECT = `
  type,
  MIN(value)               AS ioc_value,
  norm                     AS ioc_value_norm,
  COUNT(DISTINCT session_id) AS session_count,
  MAX(created_at)          AS last_seen,
  MAX(is_manual)           AS is_manual,
  MAX(source)              AS source`;

// eslint-disable-next-line @typescript-eslint/no-explicit-any
export function mapMergedIndicator(r: any) {
  return {
    type: r.type as string,
    value: r.ioc_value as string,
    norm: r.ioc_value_norm as string,
    sessionCount: Number(r.session_count),
    lastSeen: Number(r.last_seen),
    manual: Number(r.is_manual) > 0,
    source: (r.source as string) || null,
  };
}
