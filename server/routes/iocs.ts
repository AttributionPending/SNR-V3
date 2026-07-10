/**
 * Cross-session IOC browse + pivot, backed by the ioc_observations index.
 *
 * GET /api/iocs?q=&type=&limit=        — distinct indicators for the team with
 *                                         a count of the incidents they appear in.
 * GET /api/iocs/occurrences?type=&value= — every incident (and attributed actor)
 *                                         that shares one indicator.
 *
 * All queries are team-scoped and exclude soft-deleted / non-complete sessions,
 * so restore re-includes an incident and hard delete cascades via FK.
 */
import { Router } from 'express';
import { getDb } from '../db/database.js';
import { normalizeIocValue } from '../lib/ioc-index.js';
import type { Request, Response } from 'express';
import type { AuthenticatedRequest } from '../middleware/auth.js';

const router = Router();

// GET /api/iocs — distinct indicators with incident counts.
router.get('/', async (req: Request, res: Response) => {
  const authReq = req as AuthenticatedRequest;
  const teamId = authReq.teamId;
  const q = ((req.query['q'] as string) || '').trim().toLowerCase();
  const type = ((req.query['type'] as string) || '').trim();
  const limit = Math.min(parseInt(req.query['limit'] as string) || 50, 200);

  const db = getDb();
  const clauses = ["s.deleted_at IS NULL", "s.status = 'complete'", 'o.team_id = ?'];
  const params: unknown[] = [teamId];
  if (type) { clauses.push('o.ioc_type = ?'); params.push(type); }
  if (q) { clauses.push('o.ioc_value_norm LIKE ?'); params.push(`%${q}%`); }
  params.push(limit);

  const rows = (await db.prepare(`
    SELECT o.ioc_type,
           MIN(o.ioc_value)          AS ioc_value,
           o.ioc_value_norm,
           COUNT(DISTINCT o.session_id) AS session_count,
           MAX(o.created_at)         AS last_seen
    FROM ioc_observations o
    JOIN sessions s ON s.id = o.session_id
    WHERE ${clauses.join(' AND ')}
    GROUP BY o.ioc_type, o.ioc_value_norm
    ORDER BY session_count DESC, last_seen DESC
    LIMIT ?
  `).all(...params)) as Array<{
    ioc_type: string; ioc_value: string; ioc_value_norm: string;
    session_count: number; last_seen: number;
  }>;

  res.json({
    indicators: rows.map((r) => ({
      type: r.ioc_type,
      value: r.ioc_value,
      norm: r.ioc_value_norm,
      sessionCount: Number(r.session_count),
      lastSeen: Number(r.last_seen),
    })),
  });
});

// GET /api/iocs/occurrences — incidents + attributed actors sharing one indicator.
router.get('/occurrences', async (req: Request, res: Response) => {
  const authReq = req as AuthenticatedRequest;
  const teamId = authReq.teamId;
  const type = ((req.query['type'] as string) || '').trim();
  const value = ((req.query['value'] as string) || '').trim();
  if (!type || !value) {
    res.status(400).json({ error: 'type and value are required' });
    return;
  }
  const norm = normalizeIocValue(type, value);
  const db = getDb();

  const sessions = (await db.prepare(`
    SELECT DISTINCT s.id, s.name, s.severity, s.created_at
    FROM ioc_observations o
    JOIN sessions s ON s.id = o.session_id
    WHERE o.team_id = ? AND o.ioc_type = ? AND o.ioc_value_norm = ?
      AND s.deleted_at IS NULL AND s.status = 'complete'
    ORDER BY s.created_at DESC
  `).all(teamId, type, norm)) as Array<{ id: string; name: string; severity: string | null; created_at: number }>;

  const actors = (await db.prepare(`
    SELECT DISTINCT ta.id, ta.name
    FROM ioc_observations o
    JOIN sessions s ON s.id = o.session_id AND s.deleted_at IS NULL AND s.status = 'complete'
    JOIN session_threat_actors sta ON sta.session_id = o.session_id
    JOIN threat_actors ta ON ta.id = sta.threat_actor_id AND ta.name <> 'Unattributed'
    WHERE o.team_id = ? AND o.ioc_type = ? AND o.ioc_value_norm = ?
  `).all(teamId, type, norm)) as Array<{ id: string; name: string }>;

  res.json({
    type,
    value,
    sessions: sessions.map((s) => ({ id: s.id, name: s.name, severity: s.severity, createdAt: Number(s.created_at) })),
    actors,
  });
});

export default router;
