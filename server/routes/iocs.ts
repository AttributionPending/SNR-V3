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
import crypto from 'node:crypto';
import { getDb } from '../db/database.js';
import { normalizeIocValue } from '../lib/ioc-index.js';
import { combinedIndicatorsCte, COMBINED_SELECT, mapMergedIndicator } from '../lib/ioc-holdings.js';
import type { Request, Response } from 'express';
import type { AuthenticatedRequest } from '../middleware/auth.js';

const router = Router();

// GET /api/iocs — distinct indicators (report-derived + manual) with incident counts.
router.get('/', async (req: Request, res: Response) => {
  const authReq = req as AuthenticatedRequest;
  const teamId = authReq.teamId;
  const q = ((req.query['q'] as string) || '').trim().toLowerCase();
  const type = ((req.query['type'] as string) || '').trim();
  const limit = Math.min(parseInt(req.query['limit'] as string) || 50, 200);
  const order = req.query['order'] === 'recent' ? 'last_seen DESC' : 'session_count DESC, last_seen DESC';

  const db = getDb();
  const { cte, params } = combinedIndicatorsCte(teamId);
  const clauses: string[] = [];
  if (type) { clauses.push('type = ?'); params.push(type); }
  if (q) { clauses.push('norm LIKE ?'); params.push(`%${q}%`); }
  const where = clauses.length ? `WHERE ${clauses.join(' AND ')}` : '';
  params.push(limit);

  const rows = (await db.prepare(`
    ${cte}
    SELECT ${COMBINED_SELECT}
    FROM combined
    ${where}
    GROUP BY type, norm
    ORDER BY ${order}
    LIMIT ?
  `).all(...params)) as Array<Record<string, unknown>>;

  res.json({ indicators: rows.map(mapMergedIndicator) });
});

// POST /api/iocs — add a manual (curated) indicator, not tied to any report.
router.post('/', async (req: Request, res: Response) => {
  const authReq = req as AuthenticatedRequest;
  if (authReq.user.role === 'viewer') { res.status(403).json({ error: 'Viewers cannot add indicators' }); return; }
  const body = req.body as Record<string, unknown>;
  const type = String(body['type'] ?? '').trim();
  const value = String(body['value'] ?? '').trim();
  if (!type || !value) { res.status(400).json({ error: 'type and value are required' }); return; }
  if (value.length > 2048) { res.status(400).json({ error: 'value too long' }); return; }
  const context = String(body['context'] ?? '').trim().slice(0, 2000);
  const source = String(body['source'] ?? '').trim().slice(0, 500);
  const confidenceRaw = String(body['confidence'] ?? '').trim();
  const confidence = ['Low', 'Medium', 'High'].includes(confidenceRaw) ? confidenceRaw : null;
  const norm = normalizeIocValue(type, value);

  const db = getDb();
  const id = crypto.randomUUID();
  const now = Date.now();
  // Upsert on (team, type, norm): re-adding refreshes the curated metadata.
  await db.prepare(`
    INSERT INTO manual_iocs (id, team_id, ioc_type, ioc_value, ioc_value_norm, context, confidence, source, created_by, author_name, created_at, updated_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ON CONFLICT (team_id, ioc_type, ioc_value_norm) DO UPDATE SET
      ioc_value = EXCLUDED.ioc_value, context = EXCLUDED.context,
      confidence = EXCLUDED.confidence, source = EXCLUDED.source, updated_at = EXCLUDED.updated_at
  `).run(id, authReq.teamId, type, value, norm, context, confidence, source, authReq.user.id, authReq.user.displayName, now, now);

  res.json({ ok: true, indicator: { type, value, norm, context, confidence, source, manual: true } });
});

// DELETE /api/iocs/manual?type=&value= — remove a manual indicator (by type+value).
router.delete('/manual', async (req: Request, res: Response) => {
  const authReq = req as AuthenticatedRequest;
  if (authReq.user.role === 'viewer') { res.status(403).json({ error: 'Viewers cannot remove indicators' }); return; }
  const type = ((req.query['type'] as string) || '').trim();
  const value = ((req.query['value'] as string) || '').trim();
  if (!type || !value) { res.status(400).json({ error: 'type and value are required' }); return; }
  const norm = normalizeIocValue(type, value);
  const db = getDb();
  await db.prepare('DELETE FROM manual_iocs WHERE team_id = ? AND ioc_type = ? AND ioc_value_norm = ?').run(authReq.teamId, type, norm);
  res.json({ ok: true });
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

  // Curated (manual) provenance for this indicator, if any.
  const manualRow = (await db.prepare(
    'SELECT context, confidence, source, author_name, created_at FROM manual_iocs WHERE team_id = ? AND ioc_type = ? AND ioc_value_norm = ?'
  ).get(teamId, type, norm)) as { context: string; confidence: string | null; source: string; author_name: string; created_at: number } | undefined;

  res.json({
    type,
    value,
    sessions: sessions.map((s) => ({ id: s.id, name: s.name, severity: s.severity, createdAt: Number(s.created_at) })),
    actors,
    manual: manualRow
      ? { context: manualRow.context, confidence: manualRow.confidence, source: manualRow.source, authorName: manualRow.author_name, createdAt: Number(manualRow.created_at) }
      : null,
  });
});

export default router;
