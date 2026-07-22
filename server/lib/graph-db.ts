/**
 * DB-facing helpers for the link-analysis graph. These load the rows for a set
 * of sessions (team-scoped, live, complete) and hand them to the pure
 * `assembleGraph`. Kept separate from graph.ts so the assembly logic stays
 * unit-testable without a database.
 */
import { assembleGraph, type Graph, type SessionRow, type SessionActorRow, type SessionIocRow } from './graph.js';

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type Db = any;

const placeholders = (n: number) => Array.from({ length: n }, () => '?').join(',');

async function fetchSessionRows(db: Db, ids: string[]): Promise<SessionRow[]> {
  if (ids.length === 0) return [];
  return (await db.prepare(
    `SELECT id, name, severity FROM sessions WHERE id IN (${placeholders(ids.length)}) AND deleted_at IS NULL`
  ).all(...ids)) as SessionRow[];
}

async function fetchSessionActorRows(db: Db, ids: string[]): Promise<SessionActorRow[]> {
  if (ids.length === 0) return [];
  return (await db.prepare(`
    SELECT sta.session_id, ta.id AS actor_id, ta.name AS actor_name, ta.malware_families
    FROM session_threat_actors sta
    JOIN threat_actors ta ON ta.id = sta.threat_actor_id
    WHERE sta.session_id IN (${placeholders(ids.length)}) AND ta.name <> 'Unattributed'
  `).all(...ids)) as SessionActorRow[];
}

async function fetchSessionIocRows(db: Db, ids: string[]): Promise<SessionIocRow[]> {
  if (ids.length === 0) return [];
  return (await db.prepare(`
    SELECT session_id, ioc_type, ioc_value, ioc_value_norm
    FROM ioc_observations
    WHERE session_id IN (${placeholders(ids.length)}) AND is_false_positive = 0
  `).all(...ids)) as SessionIocRow[];
}

/** Build the link graph for a set of session IDs (optionally rooted at a case). */
export async function buildGraphForSessions(
  db: Db,
  sessionIds: string[],
  caseNode?: { id: string; name: string },
): Promise<Graph> {
  const [sessions, sessionActors, sessionIocs] = await Promise.all([
    fetchSessionRows(db, sessionIds),
    fetchSessionActorRows(db, sessionIds),
    fetchSessionIocRows(db, sessionIds),
  ]);

  // Entities pinned directly to the case (independent of any session).
  let pinnedActors, pinnedIocs, pinnedTechniques;
  if (caseNode) {
    [pinnedActors, pinnedIocs, pinnedTechniques] = await Promise.all([
      db.prepare(`SELECT ta.id, ta.name FROM case_actors ca JOIN threat_actors ta ON ta.id = ca.threat_actor_id WHERE ca.case_id = ?`).all(caseNode.id),
      db.prepare(`SELECT ioc_type AS type, ioc_value AS value, ioc_value_norm AS norm FROM case_iocs WHERE case_id = ?`).all(caseNode.id),
      db.prepare(`SELECT technique_id, technique_name, tactic FROM case_techniques WHERE case_id = ?`).all(caseNode.id),
    ]);
  }

  return assembleGraph({ caseNode, sessions, sessionActors, sessionIocs, pinnedActors, pinnedIocs, pinnedTechniques });
}

/**
 * Resolve a neighborhood seed to a set of session IDs (team-scoped, live,
 * complete). Seed forms: `session:<id>`, `actor:<id>`, `ioc:<type>:<value>`.
 */
export async function resolveSeedSessions(db: Db, teamId: string, seed: string): Promise<string[]> {
  const [kind, ...rest] = seed.split(':');
  const live = "s.deleted_at IS NULL AND s.status = 'complete' AND s.team_id = ?";

  if (kind === 'session') {
    const id = rest.join(':');
    const row = (await db.prepare(`SELECT s.id FROM sessions s WHERE s.id = ? AND ${live}`).get(id, teamId)) as { id: string } | undefined;
    return row ? [row.id] : [];
  }
  if (kind === 'actor') {
    const id = rest.join(':');
    const rows = (await db.prepare(`
      SELECT s.id FROM sessions s
      JOIN session_threat_actors sta ON sta.session_id = s.id
      WHERE sta.threat_actor_id = ? AND ${live}
    `).all(id, teamId)) as Array<{ id: string }>;
    return rows.map((r) => r.id);
  }
  if (kind === 'ioc') {
    // ioc:<type>:<value...> — value may itself contain ':'
    const type = rest[0] ?? '';
    const norm = rest.slice(1).join(':').trim().toLowerCase();
    const rows = (await db.prepare(`
      SELECT s.id FROM sessions s
      JOIN ioc_observations o ON o.session_id = s.id
      WHERE o.ioc_type = ? AND o.ioc_value_norm = ? AND o.is_false_positive = 0 AND ${live}
    `).all(type, norm, teamId)) as Array<{ id: string }>;
    return rows.map((r) => r.id);
  }
  return [];
}
