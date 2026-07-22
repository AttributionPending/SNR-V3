/**
 * Intelligence holdings overview — one round-trip that powers the Intelligence
 * dashboard and the Search browse-state: counts plus top/recent lists across the
 * team's indicators, actors, techniques, and incidents. Read-only; team-scoped
 * via authReq.teamId (admins with no active team get an org-wide view, matching
 * the other list routes). Reuses the ioc_observations index, session_threat_actors,
 * and the attack_chain fold used by analytics.
 */
import { Router } from 'express';
import { getDb } from '../db/database.js';
import { combinedIndicatorsCte, COMBINED_SELECT, mapMergedIndicator } from '../lib/ioc-holdings.js';
import type { Request, Response } from 'express';
import type { AuthenticatedRequest } from '../middleware/auth.js';

const router = Router();
const N = 10;

router.get('/overview', async (req: Request, res: Response) => {
  const authReq = req as AuthenticatedRequest;
  const teamId = authReq.teamId;
  const db = getDb();

  // Team filter fragments keyed by the alias each query uses for `sessions`/entity.
  const sTeam = teamId ? 'AND s.team_id = ?' : '';
  const sTeamP = teamId ? [teamId] : [];
  const oTeam = teamId ? 'AND o.team_id = ?' : '';
  const live = "s.deleted_at IS NULL AND s.status = 'complete'";

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const scalar = async (sql: string, params: any[]): Promise<number> => {
    const r = (await db.prepare(sql).get(...params)) as { c: number } | undefined;
    return Number(r?.c ?? 0);
  };

  // Merged indicators (report-derived + manual), collapsed by (type, norm).
  const merged = combinedIndicatorsCte(teamId);
  const iocSelect = (orderBy: string) => `${merged.cte}
    SELECT ${COMBINED_SELECT}
    FROM combined
    GROUP BY type, norm
    ORDER BY ${orderBy}
    LIMIT ${N}`;
  const mapIocs = (rows: Array<Record<string, unknown>>) => rows.map(mapMergedIndicator);
  // Distinct-indicator count across both sources.
  const indicatorsCountSql = `SELECT COUNT(*) AS c FROM (
      SELECT o.ioc_type, o.ioc_value_norm FROM ioc_observations o JOIN sessions s ON s.id = o.session_id WHERE ${live} ${oTeam}
      UNION
      SELECT m.ioc_type, m.ioc_value_norm FROM manual_iocs m ${teamId ? 'WHERE m.team_id = ?' : ''}
      UNION
      SELECT ci.ioc_type, ci.ioc_value_norm FROM case_iocs ci JOIN cases c ON c.id = ci.case_id ${teamId ? 'WHERE c.team_id = ?' : ''}
    ) x`;
  const indicatorsCountP = teamId ? [teamId, teamId, teamId] : [];

  const [
    indicators, actors, techniques, incidents, cases,
    topIocRows, recentIocRows, actorRows, techRows, recentSessionRows,
  ] = await Promise.all([
    scalar(indicatorsCountSql, indicatorsCountP),
    scalar(`SELECT COUNT(*) AS c FROM threat_actors ta WHERE ta.name <> 'Unattributed' ${teamId ? 'AND ta.team_id = ?' : ''}`, teamId ? [teamId] : []),
    scalar(`SELECT COUNT(*) AS c FROM (SELECT DISTINCT tech.value ->> 'technique_id' AS tid FROM analysis_results ar JOIN sessions s ON s.id = ar.session_id, snr_json_array(ar.result_json, 'attack_chain') AS tech(value) WHERE ${live} ${sTeam} AND tech.value ->> 'technique_id' IS NOT NULL) x`, sTeamP),
    scalar(`SELECT COUNT(*) AS c FROM sessions s WHERE ${live} ${sTeam}`, sTeamP),
    scalar(`SELECT COUNT(*) AS c FROM cases c ${teamId ? 'WHERE c.team_id = ?' : ''}`, teamId ? [teamId] : []),

    db.prepare(iocSelect('session_count DESC, last_seen DESC')).all(...merged.params),
    db.prepare(iocSelect('last_seen DESC')).all(...merged.params),

    db.prepare(`
      SELECT ta.id, ta.name, ta.attribution_confidence,
             COUNT(sta.session_id) AS session_count, MAX(sta.linked_at) AS latest
      FROM threat_actors ta
      LEFT JOIN session_threat_actors sta ON sta.threat_actor_id = ta.id
      WHERE ta.name <> 'Unattributed' ${teamId ? 'AND ta.team_id = ?' : ''}
      GROUP BY ta.id
      ORDER BY session_count DESC, latest DESC NULLS LAST
      LIMIT ${N}
    `).all(...(teamId ? [teamId] : [])),

    db.prepare(`
      SELECT technique_id, MAX(technique_name) AS technique_name, MAX(tactic) AS tactic,
             COUNT(DISTINCT session_id) AS session_count
      FROM (
        SELECT tech.value ->> 'technique_id' AS technique_id,
               tech.value ->> 'technique_name' AS technique_name,
               tech.value ->> 'tactic' AS tactic, ar.session_id
        FROM analysis_results ar JOIN sessions s ON s.id = ar.session_id,
             snr_json_array(ar.result_json, 'attack_chain') AS tech(value)
        WHERE ${live} ${sTeam} AND tech.value ->> 'technique_id' IS NOT NULL
      ) t
      GROUP BY technique_id
      ORDER BY session_count DESC
      LIMIT ${N}
    `).all(...sTeamP),

    db.prepare(`SELECT s.id, s.name, s.severity, s.created_at FROM sessions s WHERE ${live} ${sTeam} ORDER BY s.created_at DESC LIMIT ${N}`).all(...sTeamP),
  ]);

  res.json({
    counts: { indicators, actors, techniques, incidents, cases },
    top_iocs: mapIocs(topIocRows as Array<Record<string, unknown>>),
    recent_iocs: mapIocs(recentIocRows as Array<Record<string, unknown>>),
    top_actors: (actorRows as Array<Record<string, unknown>>).map((a) => ({
      id: a.id as string, name: a.name as string,
      session_count: Number(a.session_count), attribution_confidence: (a.attribution_confidence as string) ?? null,
    })),
    top_techniques: (techRows as Array<Record<string, unknown>>).map((t) => ({
      technique_id: t.technique_id as string, technique_name: (t.technique_name as string) ?? 'Unknown',
      tactic: (t.tactic as string) ?? 'Unknown', session_count: Number(t.session_count),
    })),
    recent_sessions: (recentSessionRows as Array<Record<string, unknown>>).map((s) => ({
      id: s.id as string, name: s.name as string, severity: (s.severity as string) ?? null, created_at: Number(s.created_at),
    })),
  });
});

/**
 * Paginated, sortable holdings for a single panel — powers "scroll beyond the
 * top N" and the per-box sort control on the Intelligence dashboard.
 *   GET /api/intel/holdings?kind=indicators|actors|techniques|sessions
 *                          &order=<per-kind>&limit=&offset=
 * Returns { items, hasMore }. Team-scoped, live sessions only, like /overview.
 */
router.get('/holdings', async (req: Request, res: Response) => {
  const authReq = req as AuthenticatedRequest;
  const teamId = authReq.teamId;
  const db = getDb();

  const kind = String(req.query['kind'] ?? '');
  const order = String(req.query['order'] ?? '');
  const limit = Math.min(Math.max(parseInt(req.query['limit'] as string) || 20, 1), 100);
  const offset = Math.max(parseInt(req.query['offset'] as string) || 0, 0);

  const sTeam = teamId ? 'AND s.team_id = ?' : '';
  const sTeamP = teamId ? [teamId] : [];
  const taTeam = teamId ? 'AND ta.team_id = ?' : '';
  const taTeamP = teamId ? [teamId] : [];
  const live = "s.deleted_at IS NULL AND s.status = 'complete'";
  const sevRank = "CASE s.severity WHEN 'Critical' THEN 5 WHEN 'High' THEN 4 WHEN 'Medium' THEN 3 WHEN 'Low' THEN 2 WHEN 'Informational' THEN 1 ELSE 0 END";

  // Per-kind: [SQL builder, params (before limit/offset), row→item mapper, allowed orders].
  let sql = ''; let params: unknown[] = []; let map: (r: Record<string, unknown>) => unknown;

  if (kind === 'indicators') {
    const orderBy = order === 'recent' ? 'last_seen DESC' : 'session_count DESC, last_seen DESC';
    const merged = combinedIndicatorsCte(teamId);
    sql = `${merged.cte}
           SELECT ${COMBINED_SELECT}
           FROM combined
           GROUP BY type, norm
           ORDER BY ${orderBy} LIMIT ? OFFSET ?`;
    params = [...merged.params];
    map = (r) => mapMergedIndicator(r);
  } else if (kind === 'actors') {
    const orderBy = order === 'recent' ? 'latest DESC NULLS LAST, session_count DESC' : 'session_count DESC, latest DESC NULLS LAST';
    sql = `SELECT ta.id, ta.name, ta.attribution_confidence,
                  COUNT(sta.session_id) AS session_count, MAX(sta.linked_at) AS latest
           FROM threat_actors ta
           LEFT JOIN session_threat_actors sta ON sta.threat_actor_id = ta.id
           WHERE ta.name <> 'Unattributed' ${taTeam}
           GROUP BY ta.id
           ORDER BY ${orderBy} LIMIT ? OFFSET ?`;
    params = [...taTeamP];
    map = (a) => ({ id: a.id as string, name: a.name as string, session_count: Number(a.session_count), attribution_confidence: (a.attribution_confidence as string) ?? null });
  } else if (kind === 'techniques') {
    const orderBy = order === 'recent' ? 'last_seen DESC' : 'session_count DESC';
    sql = `SELECT technique_id, MAX(technique_name) AS technique_name, MAX(tactic) AS tactic,
                  COUNT(DISTINCT session_id) AS session_count, MAX(created_at) AS last_seen
           FROM (
             SELECT tech.value ->> 'technique_id' AS technique_id,
                    tech.value ->> 'technique_name' AS technique_name,
                    tech.value ->> 'tactic' AS tactic, ar.session_id, s.created_at
             FROM analysis_results ar JOIN sessions s ON s.id = ar.session_id,
                  snr_json_array(ar.result_json, 'attack_chain') AS tech(value)
             WHERE ${live} ${sTeam} AND tech.value ->> 'technique_id' IS NOT NULL
           ) t
           GROUP BY technique_id
           ORDER BY ${orderBy} LIMIT ? OFFSET ?`;
    params = [...sTeamP];
    map = (t) => ({ technique_id: t.technique_id as string, technique_name: (t.technique_name as string) ?? 'Unknown', tactic: (t.tactic as string) ?? 'Unknown', session_count: Number(t.session_count) });
  } else if (kind === 'sessions') {
    const orderBy = order === 'severity' ? `${sevRank} DESC, s.created_at DESC` : 's.created_at DESC';
    sql = `SELECT s.id, s.name, s.severity, s.created_at
           FROM sessions s WHERE ${live} ${sTeam}
           ORDER BY ${orderBy} LIMIT ? OFFSET ?`;
    params = [...sTeamP];
    map = (s) => ({ id: s.id as string, name: s.name as string, severity: (s.severity as string) ?? null, created_at: Number(s.created_at) });
  } else {
    res.status(400).json({ error: 'unknown kind' });
    return;
  }

  // Fetch one extra row to detect whether more pages remain.
  const rows = (await db.prepare(sql).all(...params, limit + 1, offset)) as Array<Record<string, unknown>>;
  const hasMore = rows.length > limit;
  res.json({ items: rows.slice(0, limit).map(map), hasMore });
});

export default router;
