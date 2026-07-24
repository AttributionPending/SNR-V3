/**
 * Threat-intel feed management (human/JWT auth, team-scoped, admin or team lead).
 * Mounted behind requireAuth + requireTeamMember. Auth tokens are write-only
 * (never returned). Test/poll trigger live network fetches.
 */
import { Router } from 'express';
import crypto from 'crypto';
import type { Request, Response } from 'express';
import type { AuthenticatedRequest } from '../middleware/auth.js';
import { getDb, appendAuditLog } from '../db/database.js';
import { pollFeed, testFeed } from '../lib/feeds/index.js';
import type { FeedRow } from '../lib/feeds/types.js';
import logger from '../lib/logger.js';

const router = Router();
const FEED_TYPES = ['taxii', 'misp', 'rss'];

/** Require the caller to be an admin or a lead of the active team. */
async function requireAdminOrLead(req: Request, res: Response): Promise<boolean> {
  const authReq = req as AuthenticatedRequest;
  if (!authReq.teamId) {
    res.status(400).json({ error: 'X-Team-Id header required' });
    return false;
  }
  if (authReq.user.role === 'admin') return true;
  const db = getDb();
  const m = (await db
    .prepare('SELECT role FROM team_members WHERE team_id = ? AND user_id = ?')
    .get(authReq.teamId, authReq.user.id)) as { role: string } | undefined;
  if (!m || m.role !== 'lead') {
    res.status(403).json({ error: 'Requires admin or team lead role' });
    return false;
  }
  return true;
}

async function ownFeed(req: Request, res: Response): Promise<FeedRow | null> {
  const authReq = req as AuthenticatedRequest;
  const db = getDb();
  const feed = (await db
    .prepare('SELECT * FROM feeds WHERE id = ? AND team_id = ?')
    .get(req.params.id, authReq.teamId)) as FeedRow | undefined;
  if (!feed) {
    res.status(404).json({ error: 'Feed not found' });
    return null;
  }
  return feed;
}

// GET /api/feeds — list feeds for the team (no auth tokens).
router.get('/', async (req: Request, res: Response) => {
  const authReq = req as AuthenticatedRequest;
  if (!authReq.teamId) {
    res.status(400).json({ error: 'X-Team-Id header required' });
    return;
  }
  const db = getDb();
  const rows = (await db
    .prepare(
      `SELECT id, name, type, url, audience, tags, cadence_minutes, max_items, enabled, allow_internal,
              last_polled_at, last_status, (auth_token IS NOT NULL) AS has_auth
       FROM feeds WHERE team_id = ? ORDER BY created_at DESC`
    )
    .all(authReq.teamId)) as Array<Record<string, unknown>>;
  res.json({ feeds: rows });
});

// POST /api/feeds — create a feed.
router.post('/', async (req: Request, res: Response) => {
  if (!(await requireAdminOrLead(req, res))) return;
  const authReq = req as AuthenticatedRequest;
  const { name, type, url, authToken, config, audience, tags, cadenceMinutes, maxItems, allowInternal } = req.body as Record<string, unknown>;
  if (!name || typeof name !== 'string' || !name.trim()) { res.status(400).json({ error: 'name is required' }); return; }
  if (typeof type !== 'string' || !FEED_TYPES.includes(type)) { res.status(400).json({ error: `type must be one of: ${FEED_TYPES.join(', ')}` }); return; }
  if (!url || typeof url !== 'string' || !/^https?:\/\//i.test(url)) { res.status(400).json({ error: 'url must be an http(s) URL' }); return; }

  const db = getDb();
  const id = crypto.randomUUID();
  const now = Date.now();
  await db
    .prepare(
      `INSERT INTO feeds (id, team_id, name, type, url, auth_token, config, audience, tags, cadence_minutes, max_items, allow_internal, created_by, created_at, updated_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
    )
    .run(
      id, authReq.teamId, name.trim(), type, url.trim(),
      (typeof authToken === 'string' && authToken) ? authToken : null,
      typeof config === 'string' ? config : '{}',
      typeof audience === 'string' && audience ? audience : 'soc',
      JSON.stringify(Array.isArray(tags) ? tags : []),
      typeof cadenceMinutes === 'number' ? cadenceMinutes : 60,
      typeof maxItems === 'number' ? maxItems : 5,
      allowInternal === true ? 1 : 0,
      authReq.user.id, now, now,
    );
  appendAuditLog({ analyst_name: authReq.user.displayName, user_id: authReq.user.id, action: 'feed_created', details: `name="${name.trim()}" type=${type}` });
  res.status(201).json({ id });
});

// PATCH /api/feeds/:id — update fields (auth token only updated if provided).
router.patch('/:id', async (req: Request, res: Response) => {
  if (!(await requireAdminOrLead(req, res))) return;
  const feed = await ownFeed(req, res);
  if (!feed) return;
  const db = getDb();
  const b = req.body as Record<string, unknown>;
  const sets: string[] = [];
  const params: unknown[] = [];
  const map: Record<string, string> = { name: 'name', url: 'url', audience: 'audience', config: 'config' };
  for (const [k, col] of Object.entries(map)) {
    if (typeof b[k] === 'string') { sets.push(`${col} = ?`); params.push((b[k] as string).trim()); }
  }
  if (Array.isArray(b.tags)) { sets.push('tags = ?'); params.push(JSON.stringify(b.tags)); }
  if (typeof b.cadenceMinutes === 'number') { sets.push('cadence_minutes = ?'); params.push(b.cadenceMinutes); }
  if (typeof b.maxItems === 'number') { sets.push('max_items = ?'); params.push(b.maxItems); }
  if (typeof b.enabled === 'boolean') { sets.push('enabled = ?'); params.push(b.enabled ? 1 : 0); }
  if (typeof b.allowInternal === 'boolean') { sets.push('allow_internal = ?'); params.push(b.allowInternal ? 1 : 0); }
  if (typeof b.authToken === 'string' && b.authToken) { sets.push('auth_token = ?'); params.push(b.authToken); }
  if (sets.length === 0) { res.status(400).json({ error: 'No fields to update' }); return; }
  sets.push('updated_at = ?'); params.push(Date.now());
  params.push(feed.id);
  await db.prepare(`UPDATE feeds SET ${sets.join(', ')} WHERE id = ?`).run(...params);
  res.json({ ok: true });
});

// DELETE /api/feeds/:id
router.delete('/:id', async (req: Request, res: Response) => {
  if (!(await requireAdminOrLead(req, res))) return;
  const feed = await ownFeed(req, res);
  if (!feed) return;
  const authReq = req as AuthenticatedRequest;
  await getDb().prepare('DELETE FROM feeds WHERE id = ?').run(feed.id);
  appendAuditLog({ analyst_name: authReq.user.displayName, user_id: authReq.user.id, action: 'feed_deleted', details: `name="${feed.name}"` });
  res.json({ ok: true });
});

// POST /api/feeds/:id/test — fetch items without ingesting.
router.post('/:id/test', async (req: Request, res: Response) => {
  if (!(await requireAdminOrLead(req, res))) return;
  const feed = await ownFeed(req, res);
  if (!feed) return;
  try {
    res.json(await testFeed(feed));
  } catch (err) {
    res.status(502).json({ error: err instanceof Error ? err.message : 'Feed test failed' });
  }
});

// POST /api/feeds/:id/poll — poll now (ingests new items immediately).
router.post('/:id/poll', async (req: Request, res: Response) => {
  if (!(await requireAdminOrLead(req, res))) return;
  const feed = await ownFeed(req, res);
  if (!feed) return;
  const authReq = req as AuthenticatedRequest;
  try {
    const result = await pollFeed(feed);
    await getDb().prepare('UPDATE feeds SET last_polled_at = ?, last_status = ? WHERE id = ?')
      .run(Date.now(), `manual: ${result.ingested} new, ${result.skipped} dup`, feed.id);
    appendAuditLog({ analyst_name: authReq.user.displayName, user_id: authReq.user.id, action: 'feed_polled', details: `name="${feed.name}" ingested=${result.ingested}` });
    logger.info({ feedId: feed.id, ...result }, 'Feed manually polled');
    res.json(result);
  } catch (err) {
    res.status(502).json({ error: err instanceof Error ? err.message : 'Feed poll failed' });
  }
});

export default router;
