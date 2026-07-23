/**
 * Case (investigation) API — list, detail with cross-session aggregation,
 * CRUD, session link/unlink, investigation log, and the case link-graph.
 * All endpoints are team-scoped via requireTeamMember. Mutations require a
 * non-viewer role (mirrors PUT /sessions/:id/result). Mirrors the threat-actor
 * router; actors and IOCs are DERIVED from linked sessions, not pinned.
 */
import { Router } from 'express';
import crypto from 'crypto';
import { getDb, appendAuditLog } from '../db/database.js';
import type { Request, Response } from 'express';
import type { AuthenticatedRequest } from '../middleware/auth.js';
import type { AnalysisResult } from '../lib/claude.js';
import { buildGraphForSessions } from '../lib/graph-db.js';
import { normalizeIocValue } from '../lib/ioc-index.js';
import logger from '../lib/logger.js';

const router = Router();

const STATUSES = ['open', 'monitoring', 'closed'];
const PRIORITIES = ['critical', 'high', 'medium', 'low'];

/** 403 for viewers; returns false when the request should stop. */
function ensureEditor(authReq: AuthenticatedRequest, res: Response): boolean {
  if (authReq.user.role === 'viewer') {
    res.status(403).json({ error: 'Viewers cannot modify cases' });
    return false;
  }
  return true;
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
async function addLog(db: any, caseId: string, authReq: AuthenticatedRequest, entryType: string, content: string): Promise<void> {
  await db.prepare(
    'INSERT INTO case_log (id, case_id, user_id, author_name, entry_type, content, created_at) VALUES (?,?,?,?,?,?,?)'
  ).run(crypto.randomUUID(), caseId, authReq.user.id, authReq.user.displayName, entryType, content, Date.now());
}

type ExclusionKind = 'ioc' | 'actor' | 'technique';

/** Per-case removed entities, grouped by kind. Derived entities would otherwise
 *  reappear from their linked sessions on every load. */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
async function fetchExclusions(db: any, caseId: string): Promise<Record<ExclusionKind, Set<string>>> {
  const rows = (await db.prepare('SELECT entity_type, entity_key FROM case_exclusions WHERE case_id = ?').all(caseId)) as Array<{ entity_type: ExclusionKind; entity_key: string }>;
  const out: Record<ExclusionKind, Set<string>> = { ioc: new Set(), actor: new Set(), technique: new Set() };
  for (const r of rows) out[r.entity_type]?.add(r.entity_key);
  return out;
}

/** Record a removal so a session-derived entity stops showing in this case. */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
async function addExclusion(db: any, caseId: string, kind: ExclusionKind, key: string, authReq: AuthenticatedRequest): Promise<void> {
  await db.prepare('INSERT INTO case_exclusions (case_id, entity_type, entity_key, excluded_at, excluded_by) VALUES (?,?,?,?,?) ON CONFLICT DO NOTHING')
    .run(caseId, kind, key, Date.now(), authReq.user.id);
}

/** Re-adding an entity clears any prior removal, so remove/add stays symmetric. */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
async function clearExclusion(db: any, caseId: string, kind: ExclusionKind, key: string): Promise<void> {
  await db.prepare('DELETE FROM case_exclusions WHERE case_id = ? AND entity_type = ? AND entity_key = ?').run(caseId, kind, key);
}

/** Fetch a case row scoped to the caller's team, or send 404 and return null. */
async function fetchCase(req: Request, res: Response): Promise<Record<string, unknown> | null> {
  const authReq = req as AuthenticatedRequest;
  const db = getDb();
  const row = (await db.prepare('SELECT * FROM cases WHERE id = ? AND team_id = ?')
    .get(req.params['id'], authReq.teamId)) as Record<string, unknown> | undefined;
  if (!row) { res.status(404).json({ error: 'Case not found' }); return null; }
  return row;
}

// ── POST /api/cases — create ──────────────────────────────────────────────────
router.post('/', async (req: Request, res: Response) => {
  const authReq = req as AuthenticatedRequest;
  if (!ensureEditor(authReq, res)) return;
  const db = getDb();
  const { name, summary, priority, sessionId } = req.body as { name?: string; summary?: string; priority?: string; sessionId?: string };

  if (!name?.trim()) { res.status(400).json({ error: 'name is required' }); return; }
  if (priority && !PRIORITIES.includes(priority)) { res.status(400).json({ error: 'invalid priority' }); return; }

  const id = crypto.randomUUID();
  const now = Date.now();
  await db.prepare(`
    INSERT INTO cases (id, name, summary, status, priority, assignee, team_id, created_by, created_at, updated_at)
    VALUES (?, ?, ?, 'open', ?, ?, ?, ?, ?, ?)
  `).run(id, name.trim(), summary ?? '', priority ?? 'medium', authReq.user.id, authReq.teamId, authReq.user.id, now, now);

  await addLog(db, id, authReq, 'created', `Case created by ${authReq.user.displayName}`);

  // Optionally seed the case with the session it was created from.
  if (sessionId) {
    const s = (await db.prepare('SELECT id, name FROM sessions WHERE id = ? AND team_id = ?').get(sessionId, authReq.teamId)) as { id: string; name: string } | undefined;
    if (s) {
      await db.prepare('INSERT INTO case_sessions (case_id, session_id, added_at, added_by) VALUES (?,?,?,?) ON CONFLICT DO NOTHING')
        .run(id, s.id, now, authReq.user.id);
      await addLog(db, id, authReq, 'session_added', `Added session "${s.name}"`);
    }
  }

  appendAuditLog({ analyst_name: authReq.user.displayName, user_id: authReq.user.id, action: 'case_created', details: `Created case "${name.trim()}" (${id})` });
  logger.info({ caseId: id, teamId: authReq.teamId }, 'Case created');
  res.json({ case: { id, name: name.trim(), summary: summary ?? '', status: 'open', priority: priority ?? 'medium', assignee: authReq.user.id, session_count: sessionId ? 1 : 0, created_at: now, updated_at: now } });
});

// ── GET /api/cases — list ─────────────────────────────────────────────────────
router.get('/', async (req: Request, res: Response) => {
  const authReq = req as AuthenticatedRequest;
  const db = getDb();
  const search = (req.query['search'] as string) || '';
  const limit = Math.min(parseInt(req.query['limit'] as string) || 50, 200);
  const offset = parseInt(req.query['offset'] as string) || 0;

  let where = 'WHERE c.team_id = ?';
  const params: unknown[] = [authReq.teamId];
  if (search.trim()) { where += ' AND LOWER(c.name) LIKE ?'; params.push(`%${search.trim().toLowerCase()}%`); }

  const countRow = (await db.prepare(`SELECT COUNT(*) as total FROM cases c ${where}`).get(...params)) as { total: number };
  const rows = (await db.prepare(`
    SELECT c.*, COUNT(cs.session_id) AS session_count, MAX(cs.added_at) AS latest_added
    FROM cases c
    LEFT JOIN case_sessions cs ON cs.case_id = c.id
    ${where}
    GROUP BY c.id
    ORDER BY c.updated_at DESC
    LIMIT ? OFFSET ?
  `).all(...params, limit, offset)) as Array<Record<string, unknown>>;

  res.json({
    cases: rows.map((c) => ({
      id: c.id, name: c.name, summary: c.summary, status: c.status, priority: c.priority,
      assignee: c.assignee, session_count: Number(c.session_count) || 0,
      created_at: c.created_at, updated_at: c.updated_at,
    })),
    total: countRow.total,
  });
});

// ── GET /api/cases/:id — detail with aggregation ──────────────────────────────
router.get('/:id', async (req: Request, res: Response) => {
  const c = await fetchCase(req, res);
  if (!c) return;
  const db = getDb();
  const caseId = req.params['id'];

  const sessions = (await db.prepare(`
    SELECT s.id, s.name, s.severity, s.audience, s.created_at, cs.added_at
    FROM case_sessions cs JOIN sessions s ON s.id = cs.session_id
    WHERE cs.case_id = ? AND s.deleted_at IS NULL
    ORDER BY s.created_at DESC
  `).all(caseId)) as Array<Record<string, unknown>>;
  const sessionIds = sessions.map((s) => s.id as string);

  // Aggregate TTPs from each session's latest result_json (same fold as the actor dossier).
  const aggregatedTtps = new Map<string, { technique_id: string; technique_name: string; tactic: string; session_count: number }>();
  for (const sid of sessionIds) {
    const row = (await db.prepare('SELECT result_json FROM analysis_results WHERE session_id = ? ORDER BY version DESC LIMIT 1').get(sid)) as { result_json: string } | undefined;
    if (!row) continue;
    let result: AnalysisResult;
    try { result = JSON.parse(row.result_json) as AnalysisResult; } catch { continue; }
    for (const t of result.attack_chain ?? []) {
      const key = t.sub_technique_id || t.technique_id;
      if (!key) continue;
      const ex = aggregatedTtps.get(key);
      if (ex) ex.session_count++;
      else aggregatedTtps.set(key, { technique_id: key, technique_name: t.sub_technique_name || t.technique_name, tactic: t.tactic, session_count: 1 });
    }
  }

  // Aggregate IOCs from the ioc_observations index (fast; FP-aware).
  let aggregatedIocs: Array<Record<string, unknown>> = [];
  let derivedActors: Array<Record<string, unknown>> = [];
  if (sessionIds.length > 0) {
    const ph = sessionIds.map(() => '?').join(',');
    aggregatedIocs = (await db.prepare(`
      SELECT o.ioc_type AS type, MIN(o.ioc_value) AS value, o.ioc_value_norm AS norm,
             COUNT(DISTINCT o.session_id) AS session_count,
             MIN(s.created_at) AS first_seen, MAX(s.created_at) AS last_seen,
             BOOL_OR(o.is_false_positive = 1) AS any_false_positive
      FROM ioc_observations o JOIN sessions s ON s.id = o.session_id
      WHERE o.session_id IN (${ph})
      GROUP BY o.ioc_type, o.ioc_value_norm
      ORDER BY session_count DESC
      LIMIT 500
    `).all(...sessionIds)) as Array<Record<string, unknown>>;

    derivedActors = (await db.prepare(`
      SELECT ta.id, ta.name, COUNT(DISTINCT sta.session_id) AS session_count
      FROM session_threat_actors sta JOIN threat_actors ta ON ta.id = sta.threat_actor_id
      WHERE sta.session_id IN (${ph}) AND ta.name <> 'Unattributed'
      GROUP BY ta.id, ta.name
      ORDER BY session_count DESC
    `).all(...sessionIds)) as Array<Record<string, unknown>>;
  }

  // Entities pinned directly to the case, merged with the session-derived ones.
  const pinnedActorRows = (await db.prepare('SELECT ta.id, ta.name FROM case_actors ca JOIN threat_actors ta ON ta.id = ca.threat_actor_id WHERE ca.case_id = ? ORDER BY ca.added_at DESC').all(caseId)) as Array<{ id: string; name: string }>;
  const pinnedTechRows = (await db.prepare('SELECT technique_id, technique_name, tactic FROM case_techniques WHERE case_id = ? ORDER BY added_at DESC').all(caseId)) as Array<{ technique_id: string; technique_name: string; tactic: string }>;
  const pinnedIocRows = (await db.prepare('SELECT ioc_type AS type, ioc_value AS value, ioc_value_norm AS norm, context FROM case_iocs WHERE case_id = ? ORDER BY added_at DESC').all(caseId)) as Array<{ type: string; value: string; norm: string; context: string }>;

  const byPinnedThenCount = (a: { pinned: boolean; session_count: number }, b: { pinned: boolean; session_count: number }) =>
    (Number(b.pinned) - Number(a.pinned)) || (b.session_count - a.session_count);

  const ttpMap = new Map<string, { technique_id: string; technique_name: string; tactic: string; session_count: number; pinned: boolean }>();
  for (const t of aggregatedTtps.values()) ttpMap.set(t.technique_id, { ...t, pinned: false });
  for (const p of pinnedTechRows) {
    const ex = ttpMap.get(p.technique_id);
    if (ex) ex.pinned = true;
    else ttpMap.set(p.technique_id, { technique_id: p.technique_id, technique_name: p.technique_name, tactic: p.tactic, session_count: 0, pinned: true });
  }

  const actorMap = new Map<string, { id: string; name: string; session_count: number; pinned: boolean }>();
  for (const a of derivedActors) actorMap.set(a.id as string, { id: a.id as string, name: a.name as string, session_count: Number(a.session_count), pinned: false });
  for (const p of pinnedActorRows) {
    const ex = actorMap.get(p.id);
    if (ex) ex.pinned = true;
    else actorMap.set(p.id, { id: p.id, name: p.name, session_count: 0, pinned: true });
  }

  const iocMap = new Map<string, Record<string, unknown>>();
  for (const i of aggregatedIocs) iocMap.set(`${i.type}::${i.norm}`, { ...i, pinned: false });
  for (const p of pinnedIocRows) {
    const key = `${p.type}::${p.norm}`;
    const ex = iocMap.get(key);
    if (ex) ex.pinned = true;
    else iocMap.set(key, { type: p.type, value: p.value, norm: p.norm, session_count: 0, first_seen: null, last_seen: null, any_false_positive: false, pinned: true, context: p.context });
  }

  // Entities the analyst removed from this case (derived ones would otherwise
  // reappear on every load). Filtered out of all three lists.
  const excluded = await fetchExclusions(db, caseId);

  const log = (await db.prepare('SELECT id, user_id, author_name, entry_type, content, created_at FROM case_log WHERE case_id = ? ORDER BY created_at DESC').all(caseId)) as Array<Record<string, unknown>>;

  res.json({
    case: {
      id: c.id, name: c.name, summary: c.summary, status: c.status, priority: c.priority,
      assignee: c.assignee, created_at: c.created_at, updated_at: c.updated_at, session_count: sessions.length,
    },
    sessions,
    aggregated_ttps: [...ttpMap.values()].filter((t) => !excluded.technique.has(t.technique_id)).sort(byPinnedThenCount),
    aggregated_iocs: [...iocMap.values()]
      .filter((i) => !excluded.ioc.has(`${String(i.type)}::${String(i.norm)}`))
      .sort((a, b) => (Number(b.pinned) - Number(a.pinned)) || (Number(b.session_count) - Number(a.session_count))),
    actors: [...actorMap.values()].filter((a) => !excluded.actor.has(a.id)).sort(byPinnedThenCount),
    log,
  });
});

// ── PATCH /api/cases/:id — update metadata / status ───────────────────────────
router.patch('/:id', async (req: Request, res: Response) => {
  const authReq = req as AuthenticatedRequest;
  if (!ensureEditor(authReq, res)) return;
  const c = await fetchCase(req, res);
  if (!c) return;
  const db = getDb();
  const caseId = req.params['id'];
  const { name, summary, status, priority, assignee } = req.body as { name?: string; summary?: string; status?: string; priority?: string; assignee?: string | null };

  if (status !== undefined && !STATUSES.includes(status)) { res.status(400).json({ error: 'invalid status' }); return; }
  if (priority !== undefined && !PRIORITIES.includes(priority)) { res.status(400).json({ error: 'invalid priority' }); return; }

  const updates: string[] = [];
  const params: unknown[] = [];
  if (name !== undefined && name.trim()) { updates.push('name = ?'); params.push(name.trim()); }
  if (summary !== undefined) { updates.push('summary = ?'); params.push(summary); }
  if (status !== undefined) { updates.push('status = ?'); params.push(status); }
  if (priority !== undefined) { updates.push('priority = ?'); params.push(priority); }
  if (assignee !== undefined) { updates.push('assignee = ?'); params.push(assignee); }
  if (updates.length === 0) { res.status(400).json({ error: 'No fields to update' }); return; }
  updates.push('updated_at = ?'); params.push(Date.now()); params.push(caseId);

  await db.prepare(`UPDATE cases SET ${updates.join(', ')} WHERE id = ?`).run(...params);
  if (status !== undefined && status !== c.status) await addLog(db, caseId, authReq, 'status_change', `Status changed ${String(c.status)} → ${status}`);

  appendAuditLog({ analyst_name: authReq.user.displayName, user_id: authReq.user.id, action: 'case_update', details: `Updated case "${String(c.name)}" (${caseId})` });
  res.json({ ok: true });
});

// ── POST /api/cases/:id/log — append an investigation-log note ────────────────
router.post('/:id/log', async (req: Request, res: Response) => {
  const authReq = req as AuthenticatedRequest;
  if (!ensureEditor(authReq, res)) return;
  const c = await fetchCase(req, res);
  if (!c) return;
  const db = getDb();
  const { content } = req.body as { content?: string };
  if (!content?.trim()) { res.status(400).json({ error: 'content is required' }); return; }
  if (content.length > 5000) { res.status(400).json({ error: 'note too long' }); return; }
  await addLog(db, req.params['id'], authReq, 'note', content.trim());
  res.json({ ok: true });
});

// ── POST /api/cases/:id/sessions — bulk link sessions ─────────────────────────
router.post('/:id/sessions', async (req: Request, res: Response) => {
  const authReq = req as AuthenticatedRequest;
  if (!ensureEditor(authReq, res)) return;
  const c = await fetchCase(req, res);
  if (!c) return;
  const db = getDb();
  const caseId = req.params['id'];
  const { session_ids } = req.body as { session_ids?: string[] };
  if (!Array.isArray(session_ids) || session_ids.length === 0) { res.status(400).json({ error: 'session_ids required' }); return; }
  if (session_ids.length > 50) { res.status(400).json({ error: 'Too many sessions (max 50)' }); return; }

  const now = Date.now();
  let added = 0;
  for (const sid of session_ids) {
    const s = (await db.prepare('SELECT id, name FROM sessions WHERE id = ? AND team_id = ? AND deleted_at IS NULL').get(sid, authReq.teamId)) as { id: string; name: string } | undefined;
    if (!s) continue;
    const r = await db.prepare('INSERT INTO case_sessions (case_id, session_id, added_at, added_by) VALUES (?,?,?,?) ON CONFLICT DO NOTHING').run(caseId, s.id, now, authReq.user.id);
    if (r.changes > 0) { added++; await addLog(db, caseId, authReq, 'session_added', `Added session "${s.name}"`); }
  }
  await db.prepare('UPDATE cases SET updated_at = ? WHERE id = ?').run(now, caseId);
  res.json({ ok: true, added });
});

// ── DELETE /api/cases/:id/sessions/:sessionId — unlink ────────────────────────
router.delete('/:id/sessions/:sessionId', async (req: Request, res: Response) => {
  const authReq = req as AuthenticatedRequest;
  if (!ensureEditor(authReq, res)) return;
  const c = await fetchCase(req, res);
  if (!c) return;
  const db = getDb();
  const caseId = req.params['id'];
  const sid = req.params['sessionId'];
  const s = (await db.prepare('SELECT name FROM sessions WHERE id = ?').get(sid)) as { name: string } | undefined;
  const r = await db.prepare('DELETE FROM case_sessions WHERE case_id = ? AND session_id = ?').run(caseId, sid);
  if (r.changes > 0) {
    await addLog(db, caseId, authReq, 'session_removed', `Removed session "${s?.name ?? sid}"`);
    await db.prepare('UPDATE cases SET updated_at = ? WHERE id = ?').run(Date.now(), caseId);
  }
  res.json({ ok: true });
});

// ── GET /api/cases/:id/sessions/available — link-picker candidates ────────────
router.get('/:id/sessions/available', async (req: Request, res: Response) => {
  const authReq = req as AuthenticatedRequest;
  const c = await fetchCase(req, res);
  if (!c) return;
  const db = getDb();
  const caseId = req.params['id'];
  const search = (req.query['search'] as string) || '';
  let query = `
    SELECT s.id, s.name, s.severity, s.audience, s.created_at
    FROM sessions s
    WHERE s.team_id = ? AND s.status = 'complete' AND s.deleted_at IS NULL
      AND s.id NOT IN (SELECT session_id FROM case_sessions WHERE case_id = ?)
  `;
  const params: unknown[] = [authReq.teamId, caseId];
  if (search.trim()) { query += ' AND LOWER(s.name) LIKE ?'; params.push(`%${search.trim().toLowerCase()}%`); }
  query += ' ORDER BY s.created_at DESC LIMIT 20';
  const sessions = (await db.prepare(query).all(...params)) as Array<Record<string, unknown>>;
  res.json({ sessions });
});

// ── Actors pinned directly to the case ────────────────────────────────────────
// POST /api/cases/:id/actors { actor_id? } | { name? } — pin an existing actor,
// or create-and-pin a new actor by name.
router.post('/:id/actors', async (req: Request, res: Response) => {
  const authReq = req as AuthenticatedRequest;
  if (!ensureEditor(authReq, res)) return;
  const c = await fetchCase(req, res);
  if (!c) return;
  const db = getDb();
  const caseId = req.params['id'];
  const { actor_id, name } = req.body as { actor_id?: string; name?: string };
  const now = Date.now();

  let actor: { id: string; name: string } | undefined;
  if (actor_id) {
    actor = (await db.prepare('SELECT id, name FROM threat_actors WHERE id = ? AND team_id = ?').get(actor_id, authReq.teamId)) as { id: string; name: string } | undefined;
    if (!actor) { res.status(404).json({ error: 'Actor not found' }); return; }
  } else if (name?.trim()) {
    const nm = name.trim();
    actor = (await db.prepare('SELECT id, name FROM threat_actors WHERE team_id = ? AND LOWER(name) = LOWER(?)').get(authReq.teamId, nm)) as { id: string; name: string } | undefined;
    if (!actor) {
      const newId = crypto.randomUUID();
      await db.prepare('INSERT INTO threat_actors (id, name, team_id, created_by, created_at, updated_at) VALUES (?,?,?,?,?,?)').run(newId, nm, authReq.teamId, authReq.user.id, now, now);
      actor = { id: newId, name: nm };
    }
  } else {
    res.status(400).json({ error: 'actor_id or name is required' }); return;
  }

  const r = await db.prepare('INSERT INTO case_actors (case_id, threat_actor_id, added_at, added_by) VALUES (?,?,?,?) ON CONFLICT DO NOTHING').run(caseId, actor.id, now, authReq.user.id);
  await clearExclusion(db, caseId, 'actor', actor.id);
  if (r.changes > 0) {
    await addLog(db, caseId, authReq, 'actor_added', `Added actor "${actor.name}"`);
    await db.prepare('UPDATE cases SET updated_at = ? WHERE id = ?').run(now, caseId);
  }
  res.json({ ok: true, actor });
});

// DELETE /api/cases/:id/actors/:actorId — unpin.
router.delete('/:id/actors/:actorId', async (req: Request, res: Response) => {
  const authReq = req as AuthenticatedRequest;
  if (!ensureEditor(authReq, res)) return;
  const c = await fetchCase(req, res);
  if (!c) return;
  const db = getDb();
  const caseId = req.params['id'];
  const a = (await db.prepare('SELECT name FROM threat_actors WHERE id = ?').get(req.params['actorId'])) as { name: string } | undefined;
  // Unpin if pinned, and record an exclusion so a session-derived actor stays gone.
  await db.prepare('DELETE FROM case_actors WHERE case_id = ? AND threat_actor_id = ?').run(caseId, req.params['actorId']);
  await addExclusion(db, caseId, 'actor', req.params['actorId'], authReq);
  await addLog(db, caseId, authReq, 'actor_removed', `Removed actor "${a?.name ?? req.params['actorId']}"`);
  await db.prepare('UPDATE cases SET updated_at = ? WHERE id = ?').run(Date.now(), caseId);
  res.json({ ok: true });
});

// GET /api/cases/:id/actors/available?search= — team actors not yet pinned.
router.get('/:id/actors/available', async (req: Request, res: Response) => {
  const authReq = req as AuthenticatedRequest;
  const c = await fetchCase(req, res);
  if (!c) return;
  const db = getDb();
  const caseId = req.params['id'];
  const search = (req.query['search'] as string) || '';
  let query = `SELECT id, name FROM threat_actors WHERE team_id = ? AND name <> 'Unattributed'
      AND id NOT IN (SELECT threat_actor_id FROM case_actors WHERE case_id = ?)`;
  const params: unknown[] = [authReq.teamId, caseId];
  if (search.trim()) { query += ' AND LOWER(name) LIKE ?'; params.push(`%${search.trim().toLowerCase()}%`); }
  query += ' ORDER BY name LIMIT 20';
  const actors = (await db.prepare(query).all(...params)) as Array<Record<string, unknown>>;
  res.json({ actors });
});

// ── ATT&CK techniques pinned directly to the case ─────────────────────────────
// POST /api/cases/:id/techniques { technique_id, technique_name, tactic }
router.post('/:id/techniques', async (req: Request, res: Response) => {
  const authReq = req as AuthenticatedRequest;
  if (!ensureEditor(authReq, res)) return;
  const c = await fetchCase(req, res);
  if (!c) return;
  const db = getDb();
  const caseId = req.params['id'];
  const { technique_id, technique_name, tactic } = req.body as { technique_id?: string; technique_name?: string; tactic?: string };
  const tid = (technique_id ?? '').trim();
  if (!tid) { res.status(400).json({ error: 'technique_id is required' }); return; }
  const now = Date.now();
  const r = await db.prepare('INSERT INTO case_techniques (case_id, technique_id, technique_name, tactic, added_at, added_by) VALUES (?,?,?,?,?,?) ON CONFLICT DO NOTHING')
    .run(caseId, tid, (technique_name ?? '').trim(), (tactic ?? '').trim(), now, authReq.user.id);
  await clearExclusion(db, caseId, 'technique', tid);
  if (r.changes > 0) { await addLog(db, caseId, authReq, 'technique_added', `Added technique ${tid}${technique_name ? ` (${technique_name})` : ''}`); await db.prepare('UPDATE cases SET updated_at = ? WHERE id = ?').run(now, caseId); }
  res.json({ ok: true });
});

// DELETE /api/cases/:id/techniques/:techniqueId — unpin.
router.delete('/:id/techniques/:techniqueId', async (req: Request, res: Response) => {
  const authReq = req as AuthenticatedRequest;
  if (!ensureEditor(authReq, res)) return;
  const c = await fetchCase(req, res);
  if (!c) return;
  const db = getDb();
  const caseId = req.params['id'];
  await db.prepare('DELETE FROM case_techniques WHERE case_id = ? AND technique_id = ?').run(caseId, req.params['techniqueId']);
  await addExclusion(db, caseId, 'technique', req.params['techniqueId'], authReq);
  await addLog(db, caseId, authReq, 'technique_removed', `Removed technique ${req.params['techniqueId']}`);
  await db.prepare('UPDATE cases SET updated_at = ? WHERE id = ?').run(Date.now(), caseId);
  res.json({ ok: true });
});

// ── IOCs pinned directly to the case ──────────────────────────────────────────
// POST /api/cases/:id/iocs { type, value, context? }
router.post('/:id/iocs', async (req: Request, res: Response) => {
  const authReq = req as AuthenticatedRequest;
  if (!ensureEditor(authReq, res)) return;
  const c = await fetchCase(req, res);
  if (!c) return;
  const db = getDb();
  const caseId = req.params['id'];
  const { type, value, context } = req.body as { type?: string; value?: string; context?: string };
  const t = (type ?? '').trim();
  const v = (value ?? '').trim();
  if (!t || !v) { res.status(400).json({ error: 'type and value are required' }); return; }
  if (v.length > 2048) { res.status(400).json({ error: 'value too long' }); return; }
  const norm = normalizeIocValue(t, v);
  const now = Date.now();
  const r = await db.prepare('INSERT INTO case_iocs (case_id, ioc_type, ioc_value, ioc_value_norm, context, added_at, added_by) VALUES (?,?,?,?,?,?,?) ON CONFLICT DO NOTHING')
    .run(caseId, t, v, norm, (context ?? '').trim().slice(0, 2000), now, authReq.user.id);
  await clearExclusion(db, caseId, 'ioc', `${t}::${norm}`);
  if (r.changes > 0) { await addLog(db, caseId, authReq, 'ioc_added', `Added indicator ${v} (${t})`); await db.prepare('UPDATE cases SET updated_at = ? WHERE id = ?').run(now, caseId); }
  res.json({ ok: true });
});

// DELETE /api/cases/:id/iocs?type=&value= — unpin.
router.delete('/:id/iocs', async (req: Request, res: Response) => {
  const authReq = req as AuthenticatedRequest;
  if (!ensureEditor(authReq, res)) return;
  const c = await fetchCase(req, res);
  if (!c) return;
  const db = getDb();
  const caseId = req.params['id'];
  const t = ((req.query['type'] as string) || '').trim();
  const v = ((req.query['value'] as string) || '').trim();
  if (!t || !v) { res.status(400).json({ error: 'type and value are required' }); return; }
  const norm = normalizeIocValue(t, v);
  await db.prepare('DELETE FROM case_iocs WHERE case_id = ? AND ioc_type = ? AND ioc_value_norm = ?').run(caseId, t, norm);
  await addExclusion(db, caseId, 'ioc', `${t}::${norm}`, authReq);
  await addLog(db, caseId, authReq, 'ioc_removed', `Removed indicator ${v} (${t})`);
  await db.prepare('UPDATE cases SET updated_at = ? WHERE id = ?').run(Date.now(), caseId);
  res.json({ ok: true });
});

// ── GET /api/cases/:id/graph — the case link-analysis subgraph ────────────────
router.get('/:id/graph', async (req: Request, res: Response) => {
  const c = await fetchCase(req, res);
  if (!c) return;
  const db = getDb();
  const rows = (await db.prepare('SELECT session_id FROM case_sessions WHERE case_id = ?').all(req.params['id'])) as Array<{ session_id: string }>;
  const graph = await buildGraphForSessions(db, rows.map((r) => r.session_id), { id: c.id as string, name: c.name as string });

  // Drop entities the analyst removed from this case (and any edge touching them).
  const excluded = await fetchExclusions(db, req.params['id'] as string);
  const isExcluded = (nodeId: string): boolean => {
    if (nodeId.startsWith('actor:')) return excluded.actor.has(nodeId.slice('actor:'.length));
    if (nodeId.startsWith('technique:')) return excluded.technique.has(nodeId.slice('technique:'.length));
    if (nodeId.startsWith('ioc:')) {
      const rest = nodeId.slice('ioc:'.length);
      const sep = rest.indexOf(':');
      return sep > 0 && excluded.ioc.has(`${rest.slice(0, sep)}::${rest.slice(sep + 1)}`);
    }
    return false;
  };
  const nodes = graph.nodes.filter((n) => !isExcluded(n.id));
  const kept = new Set(nodes.map((n) => n.id));
  res.json({ nodes, edges: graph.edges.filter((e) => kept.has(e.source) && kept.has(e.target)) });
});

// ── DELETE /api/cases/:id — delete (sessions untouched) ───────────────────────
router.delete('/:id', async (req: Request, res: Response) => {
  const authReq = req as AuthenticatedRequest;
  if (!ensureEditor(authReq, res)) return;
  const c = await fetchCase(req, res);
  if (!c) return;
  const db = getDb();
  // case_sessions + case_log cascade via FK; sessions are never deleted.
  await db.prepare('DELETE FROM cases WHERE id = ?').run(req.params['id']);
  appendAuditLog({ analyst_name: authReq.user.displayName, user_id: authReq.user.id, action: 'case_delete', details: `Deleted case "${String(c.name)}" (${req.params['id']})` });
  res.json({ ok: true });
});

export default router;
