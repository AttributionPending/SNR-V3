/**
 * Analyst annotations on entities (IOCs and threat actors). Team-scoped; the
 * canonical entity_key is always derived server-side (iocIndexKey for IOCs, the
 * actor id for actors) so clients send raw (ioc_type, ioc_value) or actor_id.
 * Mounted at /api/annotations behind requireAuth + requireTeamMember.
 */
import { Router } from 'express';
import crypto from 'crypto';
import { getDb } from '../db/database.js';
import { iocIndexKey } from '../lib/ioc-index.js';
import type { Request, Response } from 'express';
import type { AuthenticatedRequest } from '../middleware/auth.js';

const router = Router();

/** 403 for viewers; returns false when the request should stop. */
function ensureEditor(authReq: AuthenticatedRequest, res: Response): boolean {
  if (authReq.user.role === 'viewer') {
    res.status(403).json({ error: 'Viewers cannot add annotations' });
    return false;
  }
  return true;
}

/**
 * Resolve the canonical (entity_type, entity_key, entity_label) from a request's
 * body or query. Returns null and sends 400 when the shape is invalid.
 */
function resolveEntity(
  src: Record<string, unknown>,
  res: Response,
): { entity_type: 'ioc' | 'actor'; entity_key: string; entity_label: string } | null {
  const entity_type = String(src.entity_type ?? '');
  const label = typeof src.label === 'string' ? src.label : '';
  if (entity_type === 'ioc') {
    const iocType = String(src.ioc_type ?? '').trim();
    const iocValue = String(src.ioc_value ?? '').trim();
    if (!iocType || !iocValue) { res.status(400).json({ error: 'ioc_type and ioc_value are required' }); return null; }
    return { entity_type, entity_key: iocIndexKey(iocType, iocValue), entity_label: label || iocValue };
  }
  if (entity_type === 'actor') {
    const actorId = String(src.actor_id ?? '').trim();
    if (!actorId) { res.status(400).json({ error: 'actor_id is required' }); return null; }
    return { entity_type, entity_key: actorId, entity_label: label };
  }
  res.status(400).json({ error: "entity_type must be 'ioc' or 'actor'" });
  return null;
}

// ── GET /api/annotations — list an entity's annotations (newest first) ────────
router.get('/', async (req: Request, res: Response) => {
  const authReq = req as AuthenticatedRequest;
  const ent = resolveEntity(req.query as Record<string, unknown>, res);
  if (!ent) return;
  const db = getDb();
  const rows = (await db.prepare(
    `SELECT id, entity_type, entity_key, entity_label, user_id, author_name, content, created_at, updated_at
     FROM entity_annotations
     WHERE team_id = ? AND entity_type = ? AND entity_key = ?
     ORDER BY created_at DESC`,
  ).all(authReq.teamId, ent.entity_type, ent.entity_key)) as Array<Record<string, unknown>>;
  res.json({ annotations: rows });
});

// ── POST /api/annotations — add an annotation ─────────────────────────────────
router.post('/', async (req: Request, res: Response) => {
  const authReq = req as AuthenticatedRequest;
  if (!ensureEditor(authReq, res)) return;
  const body = req.body as Record<string, unknown>;
  const ent = resolveEntity(body, res);
  if (!ent) return;
  const content = String(body.content ?? '').trim();
  if (!content) { res.status(400).json({ error: 'content is required' }); return; }
  if (content.length > 5000) { res.status(400).json({ error: 'content too long (max 5000)' }); return; }

  const db = getDb();
  const id = crypto.randomUUID();
  const now = Date.now();
  await db.prepare(
    `INSERT INTO entity_annotations (id, team_id, entity_type, entity_key, entity_label, user_id, author_name, content, created_at, updated_at)
     VALUES (?,?,?,?,?,?,?,?,?,?)`,
  ).run(id, authReq.teamId, ent.entity_type, ent.entity_key, ent.entity_label, authReq.user.id, authReq.user.displayName, content, now, now);

  res.json({ annotation: { id, entity_type: ent.entity_type, entity_key: ent.entity_key, entity_label: ent.entity_label, user_id: authReq.user.id, author_name: authReq.user.displayName, content, created_at: now, updated_at: now } });
});

// ── PATCH /api/annotations/:id — edit own annotation ──────────────────────────
router.patch('/:id', async (req: Request, res: Response) => {
  const authReq = req as AuthenticatedRequest;
  if (!ensureEditor(authReq, res)) return;
  const db = getDb();
  const row = (await db.prepare('SELECT user_id FROM entity_annotations WHERE id = ? AND team_id = ?').get(req.params['id'], authReq.teamId)) as { user_id: string | null } | undefined;
  if (!row) { res.status(404).json({ error: 'Annotation not found' }); return; }
  if (row.user_id !== authReq.user.id) { res.status(403).json({ error: 'You can only edit your own annotations' }); return; }
  const content = String((req.body as Record<string, unknown>).content ?? '').trim();
  if (!content) { res.status(400).json({ error: 'content is required' }); return; }
  if (content.length > 5000) { res.status(400).json({ error: 'content too long (max 5000)' }); return; }
  await db.prepare('UPDATE entity_annotations SET content = ?, updated_at = ? WHERE id = ?').run(content, Date.now(), req.params['id']);
  res.json({ ok: true });
});

// ── DELETE /api/annotations/:id — author or admin ─────────────────────────────
router.delete('/:id', async (req: Request, res: Response) => {
  const authReq = req as AuthenticatedRequest;
  if (!ensureEditor(authReq, res)) return;
  const db = getDb();
  const row = (await db.prepare('SELECT user_id FROM entity_annotations WHERE id = ? AND team_id = ?').get(req.params['id'], authReq.teamId)) as { user_id: string | null } | undefined;
  if (!row) { res.status(404).json({ error: 'Annotation not found' }); return; }
  if (row.user_id !== authReq.user.id && authReq.user.role !== 'admin') { res.status(403).json({ error: 'You can only delete your own annotations' }); return; }
  await db.prepare('DELETE FROM entity_annotations WHERE id = ?').run(req.params['id']);
  res.json({ ok: true });
});

// ── POST /api/annotations/counts — batch counts to badge search results ───────
// Returns a `counts` array aligned to the input `entities` order (0 for entities
// with no annotations or an unrecognized shape), so the client never needs the
// server-derived key.
router.post('/counts', async (req: Request, res: Response) => {
  const authReq = req as AuthenticatedRequest;
  const entities = (req.body as { entities?: Array<Record<string, unknown>> }).entities;
  if (!Array.isArray(entities) || entities.length === 0) { res.json({ counts: [] }); return; }

  const list = entities.slice(0, 300);
  const keyOf = (e: Record<string, unknown>): { type: string; key: string } | null => {
    const t = String(e.entity_type ?? '');
    if (t === 'ioc' && e.ioc_type && e.ioc_value) return { type: t, key: iocIndexKey(String(e.ioc_type), String(e.ioc_value)) };
    if (t === 'actor' && e.actor_id) return { type: t, key: String(e.actor_id) };
    return null;
  };
  const perEntity = list.map(keyOf);

  // One grouped query over the distinct valid keys.
  const distinct = new Map<string, { type: string; key: string }>();
  for (const k of perEntity) if (k) distinct.set(`${k.type}|${k.key}`, k);

  const countByKey = new Map<string, number>();
  if (distinct.size > 0) {
    const db = getDb();
    const vals = [...distinct.values()];
    const placeholders = vals.map(() => '(?,?)').join(',');
    const params: unknown[] = [authReq.teamId];
    for (const k of vals) { params.push(k.type, k.key); }
    const rows = (await db.prepare(
      `SELECT entity_type, entity_key, COUNT(*)::int AS c
       FROM entity_annotations
       WHERE team_id = ? AND (entity_type, entity_key) IN (${placeholders})
       GROUP BY entity_type, entity_key`,
    ).all(...params)) as Array<{ entity_type: string; entity_key: string; c: number }>;
    for (const r of rows) countByKey.set(`${r.entity_type}|${r.entity_key}`, Number(r.c));
  }

  const counts = perEntity.map((k) => (k ? countByKey.get(`${k.type}|${k.key}`) ?? 0 : 0));
  res.json({ counts });
});

export default router;
