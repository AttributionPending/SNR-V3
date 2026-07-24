import { Router } from 'express';
import { v4 as uuidv4 } from 'uuid';
import { getDb, appendAuditLog, loadMergedSettings } from '../db/database.js';
import type { Request, Response } from 'express';
import type { AuthenticatedRequest } from '../middleware/auth.js';
import { validateAndDeduplicateIOCs } from '../lib/ioc-validator.js';
import { validateAttackFlow } from '../lib/attack-flow.js';
import { autoLinkThreatActor } from '../lib/threat-actor-linker.js';
import { reindexSessionIocs, parseFalsePositiveKeys, iocIndexKey } from '../lib/ioc-index.js';
import { reindexSessionDetectionRules } from '../lib/detection-index.js';
import { extractReferences } from '../lib/references.js';
import { generateBrief, extractTechnical, generateDetectionRules, type AnalysisResult } from '../lib/claude.js';
import { parseSections } from '../lib/sections.js';
import logger from '../lib/logger.js';

const router = Router();

/**
 * Helper: fetch a session by ID and verify team ownership.
 * Returns the session row or sends an error response and returns null.
 */
async function fetchSessionWithTeamCheck(
  req: Request,
  res: Response,
): Promise<Record<string, unknown> | null> {
  const authReq = req as AuthenticatedRequest;
  const db = getDb();
  const session = (await db.prepare('SELECT * FROM sessions WHERE id = ? AND deleted_at IS NULL').get(req.params.id)) as Record<string, unknown> | undefined;
  if (!session) {
    res.status(404).json({ error: 'Session not found' });
    return null;
  }
  // Admins (empty teamId = global context) bypass team check
  if (authReq.teamId && session.team_id !== authReq.teamId) {
    res.status(404).json({ error: 'Session not found' });
    return null;
  }
  return session;
}

// GET /api/sessions — list sessions with optional pagination and filtering
router.get('/', async (req: Request, res: Response) => {
  const authReq = req as AuthenticatedRequest;
  const db = getDb();
  const limit = Math.min(parseInt(req.query.limit as string ?? '20', 10) || 20, 200);
  const offset = parseInt(req.query.offset as string ?? '0', 10) || 0;

  // Optional filters
  const search = (req.query.search as string | undefined)?.trim() || '';
  const severity = (req.query.severity as string | undefined)?.trim() || '';
  const audience = (req.query.audience as string | undefined)?.trim() || '';

  // Build dynamic WHERE clauses
  const conditions: string[] = ['s.deleted_at IS NULL'];
  const params: unknown[] = [];

  if (authReq.teamId) {
    conditions.push('s.team_id = ?');
    params.push(authReq.teamId);
  }

  if (search) {
    conditions.push('(s.name LIKE ? OR s.incident_id LIKE ?)');
    const searchPattern = `%${search}%`;
    params.push(searchPattern, searchPattern);
  }

  if (severity) {
    conditions.push('s.severity = ?');
    params.push(severity);
  }

  if (audience) {
    conditions.push('s.audience = ?');
    params.push(audience);
  }

  // Tag filter — supports comma-separated values (match any)
  const tagsParam = (req.query.tags as string | undefined)?.trim() || '';
  if (tagsParam) {
    const tagList = tagsParam.split(',').map((t) => t.trim().toLowerCase()).filter(Boolean);
    if (tagList.length > 0) {
      // Match sessions where at least one requested tag appears in the JSON tags array
      const tagConditions = tagList.map(() => "LOWER(s.tags) LIKE ?");
      conditions.push(`(${tagConditions.join(' OR ')})`);
      for (const tag of tagList) {
        params.push(`%"${tag}"%`);
      }
    }
  }

  const whereClauseFinal = conditions.length > 0 ? `WHERE ${conditions.join(' AND ')}` : '';

  const sessions = await db.prepare(`
    SELECT s.id, s.name, s.incident_id, s.created_at, s.updated_at,
           s.severity, s.audience, s.version, s.status, s.tags, s.origin
    FROM sessions s
    ${whereClauseFinal}
    ORDER BY s.created_at DESC
    LIMIT ? OFFSET ?
  `).all(...params, limit, offset);

  const total = ((await db.prepare(`SELECT COUNT(*) as count FROM sessions s ${whereClauseFinal}`).get(...params)) as { count: number }).count;

  res.json({ sessions, total, limit, offset });
});

// GET /api/sessions/deleted — soft-deleted sessions still within the 7-day
// retention window (most recent first). Defined before /:id to avoid shadowing.
router.get('/deleted', async (req: Request, res: Response) => {
  const authReq = req as AuthenticatedRequest;
  const db = getDb();
  const cutoff = Date.now() - 7 * 24 * 60 * 60 * 1000;

  const conditions: string[] = ['s.deleted_at IS NOT NULL', 's.deleted_at >= ?'];
  const params: unknown[] = [cutoff];
  if (authReq.teamId) {
    conditions.push('s.team_id = ?');
    params.push(authReq.teamId);
  }
  const whereClause = `WHERE ${conditions.join(' AND ')}`;

  const sessions = await db.prepare(`
    SELECT s.id, s.name, s.incident_id, s.created_at, s.updated_at, s.deleted_at,
           s.severity, s.audience, s.version, s.status, s.tags
    FROM sessions s
    ${whereClause}
    ORDER BY s.deleted_at DESC
    LIMIT 200
  `).all(...params);

  res.json({ sessions });
});

// GET /api/sessions/audit/log — audit log (must be before /:id to avoid shadowing)
router.get('/audit/log', async (req: Request, res: Response) => {
  const authReq = req as AuthenticatedRequest;
  const db = getDb();

  let rows;
  if (authReq.user.role === 'admin' && !authReq.teamId) {
    // Admin without team context — return all audit log entries
    rows = await db.prepare('SELECT * FROM audit_log ORDER BY timestamp DESC LIMIT 100').all();
  } else {
    // Scoped to sessions belonging to the team
    rows = await db.prepare(`
      SELECT al.* FROM audit_log al
      WHERE al.session_id IN (SELECT id FROM sessions WHERE team_id = ?)
      ORDER BY al.timestamp DESC
      LIMIT 100
    `).all(authReq.teamId);
  }

  res.json({ rows });
});

// GET /api/sessions/tags/all — list all unique tags used across the team
// (Must be defined before /:id to avoid Express treating "tags" as a session ID)
router.get('/tags/all', async (req: Request, res: Response) => {
  const authReq = req as AuthenticatedRequest;
  const db = getDb();

  const rows = authReq.teamId
    ? (await db.prepare(`
        SELECT DISTINCT t.value AS tag
        FROM sessions s, jsonb_array_elements_text(s.tags::jsonb) AS t(value)
        WHERE s.team_id = ? AND s.tags IS NOT NULL AND s.tags != '[]' AND s.deleted_at IS NULL
        ORDER BY tag ASC
      `).all(authReq.teamId)) as Array<{ tag: string }>
    : (await db.prepare(`
        SELECT DISTINCT t.value AS tag
        FROM sessions s, jsonb_array_elements_text(s.tags::jsonb) AS t(value)
        WHERE s.tags IS NOT NULL AND s.tags != '[]' AND s.deleted_at IS NULL
        ORDER BY tag ASC
      `).all()) as Array<{ tag: string }>;

  res.json({ tags: rows.map((r) => r.tag) });
});

// GET /api/sessions/ungrouped — sessions not linked to any real threat actor
// (Must be defined before /:id to avoid Express treating "ungrouped" as a session ID)
router.get('/ungrouped', async (req: Request, res: Response) => {
  const authReq = req as AuthenticatedRequest;
  const db = getDb();
  const search = (req.query.search as string || '').trim();
  const limit = Math.min(parseInt(req.query.limit as string ?? '50', 10) || 50, 200);

  let query = `
    SELECT s.id, s.name, s.severity, s.audience, s.created_at
    FROM sessions s
    WHERE s.team_id = ? AND s.status = 'complete' AND s.deleted_at IS NULL
    AND s.id NOT IN (
      SELECT sta.session_id FROM session_threat_actors sta
      JOIN threat_actors ta ON ta.id = sta.threat_actor_id
      WHERE ta.name != 'Unattributed'
    )
  `;
  const params: unknown[] = [authReq.teamId];

  if (search) {
    query += ' AND LOWER(s.name) LIKE ?';
    params.push(`%${search.toLowerCase()}%`);
  }

  query += ' ORDER BY s.created_at DESC LIMIT ?';
  params.push(limit);

  const sessions = (await db.prepare(query).all(...params)) as Array<Record<string, unknown>>;
  res.json({ sessions });
});

// GET /api/sessions/:id — get session detail with result
router.get('/:id', async (req: Request, res: Response) => {
  const session = await fetchSessionWithTeamCheck(req, res);
  if (!session) return;

  const db = getDb();

  const result = (await db.prepare(`
    SELECT * FROM analysis_results WHERE session_id = ? ORDER BY version DESC LIMIT 1
  `).get(req.params.id)) as { result_json: string; analyst_overrides?: string } | undefined;

  const inputs = await db.prepare('SELECT * FROM session_inputs WHERE session_id = ?').all(req.params.id);
  const note = (await db.prepare('SELECT * FROM analyst_notes WHERE session_id = ?').get(req.params.id)) as { content: string } | undefined;

  // Fetch linked threat actor (first non-Unattributed, or fallback to any)
  const linkedActor = (await db.prepare(`
    SELECT ta.id, ta.name FROM session_threat_actors sta
    JOIN threat_actors ta ON ta.id = sta.threat_actor_id
    WHERE sta.session_id = ?
    ORDER BY CASE WHEN ta.name = 'Unattributed' THEN 1 ELSE 0 END, sta.linked_at DESC
    LIMIT 1
  `).get(req.params.id)) as { id: string; name: string } | undefined;

  let parsedResult = null;
  let parsedOverrides: Record<string, string> = {};
  if (result) {
    try {
      parsedResult = JSON.parse(result.result_json);
      parsedOverrides = result.analyst_overrides ? JSON.parse(result.analyst_overrides) : {};
    } catch {
      res.status(500).json({ error: 'Stored analysis data is corrupted' });
      return;
    }
  }

  res.json({
    session,
    result: parsedResult,
    analystOverrides: parsedOverrides,
    inputs,
    note: note?.content ?? '',
    linked_threat_actor: linkedActor ? { id: linkedActor.id, name: linkedActor.name } : null,
  });
});

// POST /api/sessions — create session record before analysis
router.post('/', async (req: Request, res: Response) => {
  const authReq = req as AuthenticatedRequest;
  const db = getDb();
  const id = uuidv4();
  const now = Date.now();
  const { name, incident_id, audience, origin } = req.body as {
    name?: string;
    incident_id?: string;
    audience?: string;
    origin?: string;
  };
  const sessionOrigin = origin === 'workbench' ? 'workbench' : 'analysis';

  await db.prepare(`
    INSERT INTO sessions (id, name, incident_id, created_at, updated_at, audience, status, team_id, created_by, origin)
    VALUES (?, ?, ?, ?, ?, ?, 'pending', ?, ?, ?)
  `).run(
    id,
    name ?? `Incident ${new Date(now).toISOString().split('T')[0]}`,
    incident_id ?? null,
    now,
    now,
    audience ?? 'soc',
    authReq.teamId || null,
    authReq.user.id,
    sessionOrigin,
  );

  appendAuditLog({
    analyst_name: authReq.user.displayName,
    user_id: authReq.user.id,
    session_id: id,
    action: 'session_created',
    details: JSON.stringify({ name, incident_id, audience }),
  });

  res.json({ id });
});

// PATCH /api/sessions/:id/name — rename session
router.patch('/:id/name', async (req: Request, res: Response) => {
  const authReq = req as AuthenticatedRequest;
  const session = await fetchSessionWithTeamCheck(req, res);
  if (!session) return;

  const db = getDb();
  const { name } = req.body as { name: string };
  if (!name?.trim()) return res.status(400).json({ error: 'name required' });
  await db.prepare('UPDATE sessions SET name = ?, updated_at = ? WHERE id = ?')
    .run(name.trim(), Date.now(), req.params.id);

  appendAuditLog({
    analyst_name: authReq.user.displayName,
    user_id: authReq.user.id,
    session_id: req.params.id,
    action: 'session_renamed',
    details: JSON.stringify({ name: name.trim() }),
  });

  res.json({ ok: true });
});

// PATCH /api/sessions/:id/note — save analyst note
router.patch('/:id/note', async (req: Request, res: Response) => {
  const authReq = req as AuthenticatedRequest;
  const session = await fetchSessionWithTeamCheck(req, res);
  if (!session) return;

  const db = getDb();
  const { content } = req.body as { content: string };
  const now = Date.now();
  const existing = await db.prepare('SELECT id FROM analyst_notes WHERE session_id = ?').get(req.params.id);

  if (existing) {
    await db.prepare('UPDATE analyst_notes SET content = ?, updated_at = ? WHERE session_id = ?')
      .run(content, now, req.params.id);
  } else {
    await db.prepare('INSERT INTO analyst_notes (id, session_id, content, created_at, updated_at) VALUES (?,?,?,?,?)')
      .run(uuidv4(), req.params.id, content, now, now);
  }

  appendAuditLog({
    analyst_name: authReq.user.displayName,
    user_id: authReq.user.id,
    session_id: req.params.id,
    action: 'note_updated',
    details: JSON.stringify({ length: content?.length ?? 0 }),
  });

  res.json({ ok: true });
});

// PATCH /api/sessions/:id/overrides — save analyst overrides
router.patch('/:id/overrides', async (req: Request, res: Response) => {
  const authReq = req as AuthenticatedRequest;
  const session = await fetchSessionWithTeamCheck(req, res);
  if (!session) return;

  const db = getDb();
  const { overrides, expectedVersion } = req.body as { overrides: Record<string, string>; expectedVersion?: number };

  // Optimistic locking — reject if version has changed since client loaded data
  if (expectedVersion !== undefined) {
    const current = (await db.prepare('SELECT MAX(version) as v FROM analysis_results WHERE session_id = ?').get(req.params.id)) as { v: number | null };
    if (current.v !== null && current.v !== expectedVersion) {
      res.status(409).json({ error: 'Analysis was updated by another user. Please reload and try again.' });
      return;
    }
  }

  await db.prepare('UPDATE analysis_results SET analyst_overrides = ? WHERE session_id = ? AND version = (SELECT MAX(version) FROM analysis_results WHERE session_id = ?)')
    .run(JSON.stringify(overrides), req.params.id, req.params.id);
  // Sync severity to sessions table so the sidebar reflects the change immediately
  if (overrides.severity_badge) {
    await db.prepare('UPDATE sessions SET severity = ?, updated_at = ? WHERE id = ?')
      .run(overrides.severity_badge, Date.now(), req.params.id);
  }

  // Re-sync the false-positive flag on the IOC index so correlations/actor
  // suggestions exclude analyst-flagged FPs. Best-effort (failure-safe).
  try {
    const fpKeys = new Set(parseFalsePositiveKeys(JSON.stringify(overrides)).map((k) => k.toLowerCase()));
    const rows = (await db.prepare('SELECT id, ioc_type, ioc_value FROM ioc_observations WHERE session_id = ?').all(req.params.id)) as Array<{ id: string; ioc_type: string; ioc_value: string }>;
    for (const r of rows) {
      const plainKey = `${r.ioc_type}::${r.ioc_value.trim().toLowerCase()}`;
      const normKey = iocIndexKey(r.ioc_type, r.ioc_value);
      const isFp = fpKeys.has(plainKey) || fpKeys.has(normKey.toLowerCase());
      await db.prepare('UPDATE ioc_observations SET is_false_positive = ? WHERE id = ?').run(isFp ? 1 : 0, r.id);
    }
  } catch (err) {
    logger.warn({ err, session_id: req.params.id }, 'IOC false-positive re-sync failed (non-fatal)');
  }

  appendAuditLog({
    analyst_name: authReq.user.displayName,
    user_id: authReq.user.id,
    session_id: req.params.id,
    action: 'overrides_updated',
    details: JSON.stringify({ keys: Object.keys(overrides) }),
  });

  res.json({ ok: true });
});

// GET /api/sessions/:id/ioc-correlations — for each of this session's indicators,
// how many OTHER incidents share it and which threat actors those incidents are
// attributed to. Drives the IOC-table "seen in N" chip and the actor-suggestion
// banner. Keyed by the UI's iocKey (`type::lower(trim(value))`). FP-flagged
// observations are excluded so noise doesn't drive false attribution.
router.get('/:id/ioc-correlations', async (req: Request, res: Response) => {
  const authReq = req as AuthenticatedRequest;
  const session = await fetchSessionWithTeamCheck(req, res);
  if (!session) return;
  const db = getDb();
  const teamId = (session.team_id as string) || authReq.teamId;
  const sid = req.params.id;

  // This session's own indicators (type, display value, normalized key).
  const mine = (await db.prepare(
    'SELECT DISTINCT ioc_type, ioc_value, ioc_value_norm FROM ioc_observations WHERE session_id = ?'
  ).all(sid)) as Array<{ ioc_type: string; ioc_value: string; ioc_value_norm: string }>;

  if (mine.length === 0) {
    res.json({ correlations: {}, suggestedActors: [] });
    return;
  }

  // Other incidents (same team, live, complete, non-FP) sharing each (type, norm),
  // with the actors they're attributed to. One pass; aggregated in JS.
  const shared = (await db.prepare(`
    SELECT o.ioc_type, o.ioc_value_norm,
           o.session_id AS other_session,
           ta.id AS actor_id, ta.name AS actor_name
    FROM ioc_observations o
    JOIN ioc_observations me
      ON me.session_id = ? AND me.ioc_type = o.ioc_type AND me.ioc_value_norm = o.ioc_value_norm
    JOIN sessions s ON s.id = o.session_id AND s.deleted_at IS NULL AND s.status = 'complete'
    LEFT JOIN session_threat_actors sta ON sta.session_id = o.session_id
    LEFT JOIN threat_actors ta ON ta.id = sta.threat_actor_id AND ta.name <> 'Unattributed'
    WHERE o.team_id = ? AND o.session_id <> ? AND o.is_false_positive = 0
  `).all(sid, teamId, sid)) as Array<{
    ioc_type: string; ioc_value_norm: string; other_session: string;
    actor_id: string | null; actor_name: string | null;
  }>;

  // Aggregate: per (type, norm) → distinct other sessions + actor tallies.
  type Agg = { others: Set<string>; actors: Map<string, { name: string; sessions: Set<string> }> };
  const byNorm = new Map<string, Agg>();
  for (const row of shared) {
    const nk = `${row.ioc_type}::${row.ioc_value_norm}`;
    let agg = byNorm.get(nk);
    if (!agg) { agg = { others: new Set(), actors: new Map() }; byNorm.set(nk, agg); }
    agg.others.add(row.other_session);
    if (row.actor_id && row.actor_name) {
      let a = agg.actors.get(row.actor_id);
      if (!a) { a = { name: row.actor_name, sessions: new Set() }; agg.actors.set(row.actor_id, a); }
      a.sessions.add(row.other_session);
    }
  }

  // Build the per-IOC map keyed by the UI iocKey, plus a session-level actor roll-up.
  const correlations: Record<string, { others: number; actors: { id: string; name: string; shared: number }[] }> = {};
  const actorTally = new Map<string, { name: string; indicators: Set<string> }>();
  for (const m of mine) {
    const nk = `${m.ioc_type}::${m.ioc_value_norm}`;
    const agg = byNorm.get(nk);
    if (!agg || agg.others.size === 0) continue;
    const uiKey = `${m.ioc_type}::${m.ioc_value.trim().toLowerCase()}`;
    const actors = [...agg.actors.entries()]
      .map(([id, a]) => ({ id, name: a.name, shared: a.sessions.size }))
      .sort((x, y) => y.shared - x.shared);
    correlations[uiKey] = { others: agg.others.size, actors };
    for (const a of actors) {
      let t = actorTally.get(a.id);
      if (!t) { t = { name: a.name, indicators: new Set() }; actorTally.set(a.id, t); }
      t.indicators.add(nk);
    }
  }

  const suggestedActors = [...actorTally.entries()]
    .map(([id, t]) => ({ id, name: t.name, indicators: t.indicators.size }))
    .sort((x, y) => y.indicators - x.indicators);

  res.json({ correlations, suggestedActors });
});

// PUT /api/sessions/:id/result — save an analyst-authored AnalysisResult (Workbench).
// Mirrors the worker's persistence (analysis_results versioning + session status) but
// without the LLM: the analyst *is* the source. Reuses the same validators/linker.
router.put('/:id/result', async (req: Request, res: Response) => {
  const authReq = req as AuthenticatedRequest;
  if (authReq.user.role === 'viewer') {
    res.status(403).json({ error: 'Viewers cannot author reports' });
    return;
  }
  const session = await fetchSessionWithTeamCheck(req, res);
  if (!session) return;

  const db = getDb();
  const { result, expectedVersion } = req.body as { result?: AnalysisResult; expectedVersion?: number };

  if (!result || typeof result !== 'object') {
    res.status(400).json({ error: 'result object is required' });
    return;
  }
  if (!result.incident_summary?.title?.trim() || !result.incident_summary?.severity) {
    res.status(400).json({ error: 'incident_summary.title and severity are required' });
    return;
  }
  // Bound the payload — reject implausibly large authored reports (cost/DoS guard;
  // the 12mb JSON body limit is the outer cap, these are the semantic caps).
  if ((result.attack_chain?.length ?? 0) > 200 || (result.iocs?.length ?? 0) > 1000 ||
      (result.detection_rules?.length ?? 0) > 200 || (result.affected_assets?.length ?? 0) > 500 ||
      (result.attack_flow?.nodes?.length ?? 0) > 50 || (result.attack_flow?.edges?.length ?? 0) > 200) {
    res.status(400).json({ error: 'Report is too large (too many techniques/IOCs/rules/flow nodes).' });
    return;
  }

  // Optimistic locking — reject if another writer bumped the version meanwhile.
  if (expectedVersion !== undefined) {
    const current = (await db.prepare('SELECT MAX(version) as v FROM analysis_results WHERE session_id = ?').get(req.params.id)) as { v: number | null };
    if (current.v !== null && current.v !== expectedVersion) {
      res.status(409).json({ error: 'This report was updated elsewhere. Reload and try again.' });
      return;
    }
  }

  // Normalize / validate — same passes the worker applies to LLM output.
  result.attack_chain = Array.isArray(result.attack_chain)
    ? result.attack_chain.map((t, i) => ({ ...t, order: i }))
    : [];
  result.iocs = Array.isArray(result.iocs) && result.iocs.length > 0
    ? validateAndDeduplicateIOCs(result.iocs)
    : (result.iocs ?? []);
  result.detection_rules = result.detection_rules ?? [];
  result.affected_assets = result.affected_assets ?? [];
  result.attack_flow = validateAttackFlow(result.attack_flow, result.attack_chain);
  // References: derive deterministically from the analyst's cited sources
  // (notes + description; IOC URLs excluded) unless the analyst authored the
  // section directly. Mirrors the LLM pipeline's deterministic References.
  if (result.email_content && !String(result.email_content.references ?? '').trim()) {
    const cited = [result.incident_summary.analyst_notes, result.incident_summary.description].filter(Boolean).join('\n\n');
    result.email_content.references = extractReferences(cited, result.iocs.map((i) => i.value));
  }

  const now = Date.now();
  const latest = ((await db.prepare('SELECT MAX(version) as v FROM analysis_results WHERE session_id = ?').get(req.params.id)) as { v: number | null }).v ?? 0;
  const newVersion = latest + 1;

  await db.prepare('INSERT INTO analysis_results (id, session_id, version, result_json, created_at) VALUES (?,?,?,?,?)')
    .run(uuidv4(), req.params.id, newVersion, JSON.stringify(result), now);
  await db.prepare('UPDATE sessions SET status = ?, updated_at = ?, severity = ?, version = ? WHERE id = ?')
    .run('complete', now, result.incident_summary.severity, newVersion, req.params.id);

  // Best-effort threat-actor auto-link (same as the analysis pipeline).
  try {
    await autoLinkThreatActor(db, req.params.id, result, (session.team_id as string) || authReq.teamId, authReq.user.id);
  } catch (err) {
    logger.warn({ err, session_id: req.params.id }, 'Threat actor auto-link failed (non-fatal)');
  }

  // Rebuild the cross-session IOC index (additive, failure-safe). A newly authored
  // version has no false-positive overrides yet; they re-sync on the overrides PATCH.
  try {
    await reindexSessionIocs(db, req.params.id, (session.team_id as string) || authReq.teamId, result, []);
  } catch (err) {
    logger.warn({ err, session_id: req.params.id }, 'IOC reindex failed (non-fatal)');
  }

  // Same for the detection-rule index that powers coverage.
  try {
    await reindexSessionDetectionRules(db, req.params.id, (session.team_id as string) || authReq.teamId, result);
  } catch (err) {
    logger.warn({ err, session_id: req.params.id }, 'Detection-rule reindex failed (non-fatal)');
  }

  appendAuditLog({
    analyst_name: authReq.user.displayName,
    user_id: authReq.user.id,
    session_id: req.params.id,
    action: 'report_authored',
    techniques_identified: result.attack_chain.map((t) => t.sub_technique_id ?? t.technique_id),
    details: `severity=${result.incident_summary.severity}, version=${newVersion}`,
  });

  res.json({ ok: true, version: newVersion });
});

// POST /api/sessions/:id/assist/brief — AI-draft the stakeholder narrative from the
// analyst's authored (possibly unsaved) findings. Returns email_content for review;
// never persists — the analyst accepts it in the Workbench, then Saves.
router.post('/:id/assist/brief', async (req: Request, res: Response) => {
  const authReq = req as AuthenticatedRequest;
  if (authReq.user.role === 'viewer') { res.status(403).json({ error: 'Viewers cannot use AI assist' }); return; }
  const session = await fetchSessionWithTeamCheck(req, res);
  if (!session) return;

  const { result, audience } = req.body as { result?: AnalysisResult; audience?: string };
  if (!result?.incident_summary?.title?.trim()) {
    res.status(400).json({ error: 'Add an incident title and some findings before drafting a brief.' });
    return;
  }
  try {
    const settings = await loadMergedSettings(authReq.teamId);
    const sections = parseSections(settings.report_sections || '');
    const { email_content: _drop, ...technical } = result;
    void _drop;
    const audienceKey = audience || (session.audience as string) || 'soc';
    const emailContent = await generateBrief(technical, settings, audienceKey, sections);
    appendAuditLog({
      analyst_name: authReq.user.displayName,
      user_id: authReq.user.id,
      session_id: req.params.id,
      action: 'assist_brief',
      details: `audience=${audienceKey}`,
    });
    res.json({ email_content: emailContent });
  } catch (err) {
    logger.warn({ err, session_id: req.params.id }, 'AI brief draft failed');
    res.status(502).json({ error: err instanceof Error ? err.message : 'AI draft failed' });
  }
});

// POST /api/sessions/:id/assist/extract — Phase-1 extraction over the analyst's
// freeform notes. Returns suggested techniques / IOCs / rules / actor / flow to
// MERGE into the Workbench draft. Never persists.
router.post('/:id/assist/extract', async (req: Request, res: Response) => {
  const authReq = req as AuthenticatedRequest;
  if (authReq.user.role === 'viewer') { res.status(403).json({ error: 'Viewers cannot use AI assist' }); return; }
  const session = await fetchSessionWithTeamCheck(req, res);
  if (!session) return;

  const { notes } = req.body as { notes?: string };
  if (!notes || !notes.trim()) { res.status(400).json({ error: 'notes are required' }); return; }
  if (notes.length > 20000) { res.status(400).json({ error: 'Notes are too long (max 20,000 characters). Trim or split them.' }); return; }
  try {
    const settings = await loadMergedSettings(authReq.teamId);
    const technical = await extractTechnical({
      text: notes,
      audience: (session.audience as string) || 'soc',
      orgEvaluationCriteria: settings.org_evaluation_criteria || undefined,
      orgDetectionContext: settings.org_detection_context || undefined,
      systemPromptOverride: settings.system_prompt_override || undefined,
      phase1InstructionsOverride: settings.phase1_instructions_override || undefined,
      providerSettings: settings,
    });
    appendAuditLog({
      analyst_name: authReq.user.displayName,
      user_id: authReq.user.id,
      session_id: req.params.id,
      action: 'assist_extract',
      details: `techniques=${technical.attack_chain?.length ?? 0}, iocs=${technical.iocs?.length ?? 0}`,
    });
    res.json({ technical });
  } catch (err) {
    logger.warn({ err, session_id: req.params.id }, 'AI extract failed');
    res.status(502).json({ error: err instanceof Error ? err.message : 'AI extract failed' });
  }
});

// POST /api/sessions/:id/assist/rules — generate detection rules for the analyst's
// current techniques. Returns rules to MERGE into the draft. Never persists.
router.post('/:id/assist/rules', async (req: Request, res: Response) => {
  const authReq = req as AuthenticatedRequest;
  if (authReq.user.role === 'viewer') { res.status(403).json({ error: 'Viewers cannot use AI assist' }); return; }
  const session = await fetchSessionWithTeamCheck(req, res);
  if (!session) return;

  const { result } = req.body as { result?: AnalysisResult };
  if (!result?.attack_chain?.length) { res.status(400).json({ error: 'Add at least one ATT&CK technique first' }); return; }
  try {
    const settings = await loadMergedSettings(authReq.teamId);
    const { email_content: _drop, ...technical } = result;
    void _drop;
    // Bound cost — generate rules for at most the first 40 techniques.
    technical.attack_chain = (technical.attack_chain ?? []).slice(0, 40);
    const detection_rules = await generateDetectionRules(technical, settings);
    appendAuditLog({
      analyst_name: authReq.user.displayName,
      user_id: authReq.user.id,
      session_id: req.params.id,
      action: 'assist_rules',
      details: `rules=${detection_rules.length}`,
    });
    res.json({ detection_rules });
  } catch (err) {
    logger.warn({ err, session_id: req.params.id }, 'AI rules generation failed');
    res.status(502).json({ error: err instanceof Error ? err.message : 'AI rules generation failed' });
  }
});

// DELETE /api/sessions/:id — soft-delete a session (recoverable for 7 days,
// then purged with all related data on server start)
router.delete('/:id', async (req: Request, res: Response) => {
  const authReq = req as AuthenticatedRequest;
  const session = await fetchSessionWithTeamCheck(req, res);
  if (!session) return;

  const db = getDb();

  // Only session creator, team lead, or admin can delete
  if (authReq.user.role !== 'admin' && session.created_by !== authReq.user.id) {
    const membership = (await db.prepare('SELECT role FROM team_members WHERE team_id = ? AND user_id = ?')
      .get(authReq.teamId, authReq.user.id)) as { role: string } | undefined;
    if (!membership || membership.role !== 'lead') {
      res.status(403).json({ error: 'Only the session creator, team lead, or admin can delete sessions' });
      return;
    }
  }

  await db.prepare('UPDATE sessions SET deleted_at = ?, updated_at = ? WHERE id = ?')
    .run(Date.now(), Date.now(), req.params.id);

  appendAuditLog({
    analyst_name: authReq.user.displayName,
    user_id: authReq.user.id,
    session_id: req.params.id,
    action: 'session_deleted',
    details: `name="${session.name}"`,
  });

  res.json({ ok: true });
});

// POST /api/sessions/:id/restore — undo a soft delete (within retention window)
router.post('/:id/restore', async (req: Request, res: Response) => {
  const authReq = req as AuthenticatedRequest;
  const db = getDb();
  const session = (await db.prepare('SELECT * FROM sessions WHERE id = ? AND deleted_at IS NOT NULL')
    .get(req.params.id)) as Record<string, unknown> | undefined;

  if (!session || (authReq.teamId && session.team_id !== authReq.teamId)) {
    res.status(404).json({ error: 'Deleted session not found' });
    return;
  }

  await db.prepare('UPDATE sessions SET deleted_at = NULL, updated_at = ? WHERE id = ?')
    .run(Date.now(), req.params.id);

  appendAuditLog({
    analyst_name: authReq.user.displayName,
    user_id: authReq.user.id,
    session_id: req.params.id,
    action: 'session_restored',
    details: `name="${session.name}"`,
  });

  res.json({ ok: true });
});

// ── Bulk delete ────────────────────────────────────────────────────────────

router.post('/bulk-delete', async (req: Request, res: Response) => {
  const authReq = req as AuthenticatedRequest;
  const { session_ids } = req.body as { session_ids: string[] };

  if (!Array.isArray(session_ids) || session_ids.length === 0) {
    res.status(400).json({ error: 'session_ids must be a non-empty array' });
    return;
  }

  if (session_ids.length > 50) {
    res.status(400).json({ error: 'Cannot delete more than 50 sessions at once' });
    return;
  }

  const db = getDb();
  let deleted = 0;
  const errors: string[] = [];

  for (const id of session_ids) {
    const session = (await db.prepare('SELECT * FROM sessions WHERE id = ? AND deleted_at IS NULL').get(id)) as Record<string, unknown> | undefined;
    if (!session) continue;

    // Team scope check
    if (authReq.teamId && session.team_id !== authReq.teamId) continue;

    // Permission check: creator, team lead, or admin
    if (authReq.user.role !== 'admin' && session.created_by !== authReq.user.id) {
      const membership = (await db.prepare('SELECT role FROM team_members WHERE team_id = ? AND user_id = ?')
        .get(authReq.teamId, authReq.user.id)) as { role: string } | undefined;
      if (!membership || membership.role !== 'lead') {
        errors.push(`No permission to delete session ${id}`);
        continue;
      }
    }

    await db.prepare('UPDATE sessions SET deleted_at = ?, updated_at = ? WHERE id = ?')
      .run(Date.now(), Date.now(), id);
    deleted++;

    appendAuditLog({
      analyst_name: authReq.user.displayName,
      user_id: authReq.user.id,
      session_id: id,
      action: 'session_deleted',
      details: `bulk delete, name="${session.name}"`,
    });
  }

  logger.info({ deleted, total: session_ids.length, errors: errors.length }, 'Bulk delete completed');
  res.json({ ok: true, deleted, errors });
});

// ── Tags ──────────────────────────────────────────────────────────────────

// PATCH /api/sessions/:id/tags — set tags for a session
router.patch('/:id/tags', async (req: Request, res: Response) => {
  const authReq = req as AuthenticatedRequest;
  const session = await fetchSessionWithTeamCheck(req, res);
  if (!session) return;

  const { tags } = req.body as { tags: string[] };
  if (!Array.isArray(tags)) {
    res.status(400).json({ error: 'tags must be an array of strings' });
    return;
  }

  // Normalize: lowercase, trim, dedup, limit to 20 tags, max 30 chars each
  const normalized = [...new Set(
    tags.map((t) => String(t).trim().toLowerCase()).filter((t) => t.length > 0 && t.length <= 30)
  )].slice(0, 20);

  const db = getDb();
  await db.prepare('UPDATE sessions SET tags = ?, updated_at = ? WHERE id = ?')
    .run(JSON.stringify(normalized), Date.now(), req.params.id);

  res.json({ ok: true, tags: normalized });
});

// ── Threat Actor Assignment ─────────────────────────────────────────────────

// PUT /api/sessions/:id/threat-actor — assign or reassign a threat actor to a session
router.put('/:id/threat-actor', async (req: Request, res: Response) => {
  const authReq = req as AuthenticatedRequest;
  const session = await fetchSessionWithTeamCheck(req, res);
  if (!session) return;

  const { threat_actor_id } = req.body as { threat_actor_id: string | null };
  const db = getDb();

  if (threat_actor_id === null || threat_actor_id === undefined) {
    // Unassign — remove all threat actor links for this session
    const result = await db.prepare('DELETE FROM session_threat_actors WHERE session_id = ?').run(req.params.id);

    appendAuditLog({
      analyst_name: authReq.user.displayName,
      user_id: authReq.user.id,
      session_id: req.params.id,
      action: 'threat_actor_unassigned',
      details: `Removed threat actor assignment (${result.changes} link(s) removed)`,
    });

    res.json({ ok: true, threat_actor: null });
    return;
  }

  // Verify actor belongs to team
  const actor = (await db.prepare(
    'SELECT id, name FROM threat_actors WHERE id = ? AND team_id = ?'
  ).get(threat_actor_id, authReq.teamId)) as { id: string; name: string } | undefined;

  if (!actor) {
    res.status(404).json({ error: 'Threat actor not found' });
    return;
  }

  // Remove any existing links for this session first (reassignment)
  await db.prepare('DELETE FROM session_threat_actors WHERE session_id = ?').run(req.params.id);

  // Create new link
  await db.prepare(
    'INSERT INTO session_threat_actors (session_id, threat_actor_id, link_type, linked_at, linked_by) VALUES (?, ?, ?, ?, ?)'
  ).run(req.params.id, threat_actor_id, 'manual', Date.now(), authReq.user.id);

  appendAuditLog({
    analyst_name: authReq.user.displayName,
    user_id: authReq.user.id,
    session_id: req.params.id,
    action: 'threat_actor_assigned',
    details: `Assigned session to "${actor.name}" (${threat_actor_id})`,
  });

  res.json({ ok: true, threat_actor: { id: actor.id, name: actor.name } });
});

export default router;
