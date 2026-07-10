/**
 * Link-analysis graph builder for the Cases feature.
 *
 * `assembleGraph` is a pure function (no DB) so it is unit-testable: given the
 * rows already fetched for a set of sessions, it produces a deduplicated
 * node/edge graph across five entity kinds — case, session, actor, ioc, malware.
 * The DB-facing helpers (`resolveSeedSessions`, `fetchGraphForSessions`) load the
 * rows and hand them to `assembleGraph`.
 *
 * Edges: case→session (contains), session→actor (attributed-to),
 * session→ioc (observed), actor→malware (uses). IOC fan-out is capped to the
 * most-shared indicators so large investigations stay legible.
 */

export type GraphEntity = 'case' | 'session' | 'actor' | 'ioc' | 'malware';

export interface GraphNode {
  id: string;
  type: GraphEntity;
  label: string;
  meta?: Record<string, string | number | null>;
}
export interface GraphEdge {
  source: string;
  target: string;
  label: string;
}
export interface Graph {
  nodes: GraphNode[];
  edges: GraphEdge[];
}

export interface SessionRow { id: string; name: string; severity?: string | null }
export interface SessionActorRow { session_id: string; actor_id: string; actor_name: string; malware_families?: string | null }
export interface SessionIocRow { session_id: string; ioc_type: string; ioc_value: string; ioc_value_norm: string }

export interface AssembleInput {
  /** Optional root case node the sessions belong to. */
  caseNode?: { id: string; name: string };
  sessions: SessionRow[];
  sessionActors: SessionActorRow[];
  sessionIocs: SessionIocRow[];
  /** Keep only the N most-shared IOCs (by session count within the set). */
  maxIocs?: number;
}

const iocNodeId = (type: string, norm: string) => `ioc:${type}:${norm}`;

/** Build a deduplicated link graph from already-fetched rows. Pure. */
export function assembleGraph(input: AssembleInput): Graph {
  const { caseNode, sessions, sessionActors, sessionIocs, maxIocs = 60 } = input;

  const nodes = new Map<string, GraphNode>();
  const edges = new Map<string, GraphEdge>();
  const addNode = (n: GraphNode) => { if (!nodes.has(n.id)) nodes.set(n.id, n); };
  const addEdge = (source: string, target: string, label: string) => {
    const key = `${source}->${target}`;
    if (!edges.has(key)) edges.set(key, { source, target, label });
  };

  if (caseNode) addNode({ id: `case:${caseNode.id}`, type: 'case', label: caseNode.name });

  const sessionIds = new Set(sessions.map((s) => s.id));
  for (const s of sessions) {
    addNode({ id: `session:${s.id}`, type: 'session', label: s.name, meta: { severity: s.severity ?? null } });
    if (caseNode) addEdge(`case:${caseNode.id}`, `session:${s.id}`, 'contains');
  }

  // Actors (+ their malware families) attributed to sessions in the set.
  for (const r of sessionActors) {
    if (!sessionIds.has(r.session_id)) continue;
    const actorId = `actor:${r.actor_id}`;
    addNode({ id: actorId, type: 'actor', label: r.actor_name });
    addEdge(`session:${r.session_id}`, actorId, 'attributed-to');
    let malware: string[] = [];
    try { malware = r.malware_families ? (JSON.parse(r.malware_families) as string[]) : []; } catch { malware = []; }
    for (const m of malware) {
      if (!m || !m.trim()) continue;
      const mid = `malware:${m.toLowerCase()}`;
      addNode({ id: mid, type: 'malware', label: m });
      addEdge(actorId, mid, 'uses');
    }
  }

  // IOCs — count how many sessions in the set share each (type, norm); keep top N.
  const iocAgg = new Map<string, { type: string; value: string; norm: string; sessions: Set<string> }>();
  for (const r of sessionIocs) {
    if (!sessionIds.has(r.session_id)) continue;
    const key = `${r.ioc_type}::${r.ioc_value_norm}`;
    let a = iocAgg.get(key);
    if (!a) { a = { type: r.ioc_type, value: r.ioc_value, norm: r.ioc_value_norm, sessions: new Set() }; iocAgg.set(key, a); }
    a.sessions.add(r.session_id);
  }
  const kept = [...iocAgg.values()]
    .sort((x, y) => y.sessions.size - x.sessions.size)
    .slice(0, Math.max(0, maxIocs));
  for (const a of kept) {
    const iid = iocNodeId(a.type, a.norm);
    addNode({ id: iid, type: 'ioc', label: a.value, meta: { iocType: a.type, sessions: a.sessions.size } });
    for (const sid of a.sessions) addEdge(`session:${sid}`, iid, 'observed');
  }

  return { nodes: [...nodes.values()], edges: [...edges.values()] };
}
