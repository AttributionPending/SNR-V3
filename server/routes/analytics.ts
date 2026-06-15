import { Router } from 'express';
import { getDb } from '../db/database.js';
import type { Request, Response } from 'express';
import type { AuthenticatedRequest } from '../middleware/auth.js';
import logger from '../lib/logger.js';

interface TechniqueRow {
  technique_id: string | null;
  technique_name: string | null;
  tactic: string | null;
  session_id: string;
  session_name: string;
  session_severity: string | null;
  session_created_at: number;
}

type TechniqueEntry = {
  technique_id: string;
  technique_name: string;
  tactic: string;
  sessions: { id: string; name: string; severity: string | null; created_at: number }[];
};

const router = Router();

// GET /api/analytics?days=7|30|90|0&all=true
router.get('/', (req: Request, res: Response) => {
  const authReq = req as AuthenticatedRequest;
  const db = getDb();
  const days = parseInt((req.query.days as string) ?? '30', 10);
  const cutoff = days > 0 ? Date.now() - days * 24 * 60 * 60 * 1000 : null;

  // Admin can pass ?all=true to see org-wide analytics (skip team filter)
  const showAll = authReq.user.role === 'admin' && req.query.all === 'true';
  const teamId = authReq.teamId;
  const applyTeamFilter = !showAll && !!teamId;

  // Build reusable team filter fragments
  const teamWhere = applyTeamFilter ? ' AND s.team_id = ?' : '';
  const teamParams: unknown[] = applyTeamFilter ? [teamId] : [];

  // 1. Sessions over time (daily buckets)
  const sessionsOverTime = cutoff !== null
    ? db.prepare(`
        SELECT strftime('%Y-%m-%d', datetime(s.created_at / 1000, 'unixepoch')) AS date,
               COUNT(*) AS count
        FROM sessions s
        WHERE s.status = 'complete' AND s.deleted_at IS NULL AND s.created_at >= ?${teamWhere}
        GROUP BY date ORDER BY date ASC
      `).all(cutoff, ...teamParams)
    : db.prepare(`
        SELECT strftime('%Y-%m-%d', datetime(s.created_at / 1000, 'unixepoch')) AS date,
               COUNT(*) AS count
        FROM sessions s
        WHERE s.status = 'complete' AND s.deleted_at IS NULL${teamWhere}
        GROUP BY date ORDER BY date ASC
      `).all(...teamParams);

  // 2. Severity distribution
  const severityDistribution = db.prepare(`
    SELECT COALESCE(s.severity, 'Unknown') AS severity, COUNT(*) AS count
    FROM sessions s WHERE s.status = 'complete' AND s.deleted_at IS NULL${teamWhere}
    GROUP BY severity
    ORDER BY CASE severity
      WHEN 'Critical' THEN 1 WHEN 'High' THEN 2 WHEN 'Medium' THEN 3
      WHEN 'Low' THEN 4 WHEN 'Informational' THEN 5 ELSE 6 END
  `).all(...teamParams);

  // 3. Audience breakdown
  const audienceBreakdown = db.prepare(`
    SELECT COALESCE(s.audience, 'unknown') AS audience, COUNT(*) AS count
    FROM sessions s WHERE s.status = 'complete' AND s.deleted_at IS NULL${teamWhere}
    GROUP BY audience ORDER BY count DESC
  `).all(...teamParams);

  // 4. Export activity (from audit_log, scoped to team sessions)
  const exportActivity = applyTeamFilter
    ? db.prepare(`
        SELECT replace(al.action, 'export_', '') AS export_type, COUNT(*) AS count
        FROM audit_log al
        JOIN sessions s ON al.session_id = s.id
        WHERE al.action LIKE 'export_%' AND s.team_id = ? AND s.deleted_at IS NULL
        GROUP BY al.action ORDER BY count DESC
      `).all(teamId)
    : db.prepare(`
        SELECT replace(action, 'export_', '') AS export_type, COUNT(*) AS count
        FROM audit_log WHERE action LIKE 'export_%'
        GROUP BY action ORDER BY count DESC
      `).all();

  // 5. IOC type distribution (parse result_json via json_each)
  const iocDistribution = applyTeamFilter
    ? db.prepare(`
        SELECT json_extract(ioc.value, '$.type') AS ioc_type, COUNT(*) AS count
        FROM analysis_results ar
        JOIN sessions s ON ar.session_id = s.id,
        json_each(ar.result_json, '$.iocs') AS ioc
        WHERE json_extract(ioc.value, '$.type') IS NOT NULL AND s.team_id = ? AND s.deleted_at IS NULL
        GROUP BY ioc_type ORDER BY count DESC LIMIT 500
      `).all(teamId)
    : db.prepare(`
        SELECT json_extract(ioc.value, '$.type') AS ioc_type, COUNT(*) AS count
        FROM analysis_results ar
        JOIN sessions s ON ar.session_id = s.id,
        json_each(ar.result_json, '$.iocs') AS ioc
        WHERE json_extract(ioc.value, '$.type') IS NOT NULL AND s.deleted_at IS NULL
        GROUP BY ioc_type ORDER BY count DESC LIMIT 500
      `).all();

  // 6. ATT&CK technique -> sessions mapping
  const rawTechniques = applyTeamFilter
    ? db.prepare(`
        SELECT
          json_extract(tech.value, '$.technique_id')   AS technique_id,
          json_extract(tech.value, '$.technique_name') AS technique_name,
          json_extract(tech.value, '$.tactic')         AS tactic,
          ar.session_id,
          s.name        AS session_name,
          s.severity    AS session_severity,
          s.created_at  AS session_created_at
        FROM analysis_results ar
        JOIN sessions s ON ar.session_id = s.id,
        json_each(ar.result_json, '$.attack_chain') AS tech
        WHERE s.team_id = ? AND s.deleted_at IS NULL
        GROUP BY json_extract(tech.value, '$.technique_id'), ar.session_id
        ORDER BY json_extract(tech.value, '$.technique_id')
        LIMIT 5000
      `).all(teamId) as TechniqueRow[]
    : db.prepare(`
        SELECT
          json_extract(tech.value, '$.technique_id')   AS technique_id,
          json_extract(tech.value, '$.technique_name') AS technique_name,
          json_extract(tech.value, '$.tactic')         AS tactic,
          ar.session_id,
          s.name        AS session_name,
          s.severity    AS session_severity,
          s.created_at  AS session_created_at
        FROM analysis_results ar
        JOIN sessions s ON ar.session_id = s.id,
        json_each(ar.result_json, '$.attack_chain') AS tech
        WHERE s.deleted_at IS NULL
        GROUP BY json_extract(tech.value, '$.technique_id'), ar.session_id
        ORDER BY json_extract(tech.value, '$.technique_id')
        LIMIT 5000
      `).all() as TechniqueRow[];

  // Server-side aggregation: group rows by technique_id, collect sessions array
  const techniqueMapIndex = new Map<string, TechniqueEntry>();
  for (const row of rawTechniques) {
    if (!row.technique_id) continue;
    const sessionEntry = {
      id: row.session_id,
      name: row.session_name,
      severity: row.session_severity,
      created_at: row.session_created_at,
    };
    const existing = techniqueMapIndex.get(row.technique_id);
    if (existing) {
      if (!existing.sessions.find((s) => s.id === row.session_id)) {
        existing.sessions.push(sessionEntry);
      }
    } else {
      techniqueMapIndex.set(row.technique_id, {
        technique_id: row.technique_id,
        technique_name: row.technique_name ?? 'Unknown',
        tactic: row.tactic ?? 'Unknown',
        sessions: [sessionEntry],
      });
    }
  }

  res.json({
    sessionsOverTime,
    severityDistribution,
    audienceBreakdown,
    exportActivity,
    iocDistribution,
    techniqueMap: Array.from(techniqueMapIndex.values()),
  });
});

export default router;
