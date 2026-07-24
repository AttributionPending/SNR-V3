/**
 * Pure layout math for the link-analysis graph (see components/LinkGraph.tsx).
 *
 * Kept free of React/reactflow so the geometry is unit-testable — these
 * functions decide the shape the analyst actually sees, and emergent shapes
 * (e.g. rings landing on the cardinal axes) are a real readability problem.
 */
import dagre from 'dagre';
import type { GraphData, GraphNode } from '@/lib/api';

export type EntityType = GraphNode['type'];
export type LayoutMode = 'lanes' | 'tree' | 'radial' | 'force';
export type Pt = { x: number; y: number };

/** Canonical left-to-right ordering of entity kinds. */
export const TYPE_ORDER: EntityType[] = ['case', 'session', 'actor', 'ioc', 'malware', 'technique'];

export const NODE_W = 190;
export const NODE_H = 46;

const LANE_W = 280;
const LANE_ROW_H = 66;
const RING_R = 260;
/** Rotating each ring by the golden angle stops successive rings from stacking
 *  into an axis-aligned cross. */
const GOLDEN_ANGLE = 2.399963;

function buildAdjacency(data: GraphData): Map<string, string[]> {
  const adj = new Map<string, string[]>();
  for (const n of data.nodes) adj.set(n.id, []);
  for (const e of data.edges) {
    adj.get(e.source)?.push(e.target);
    adj.get(e.target)?.push(e.source);
  }
  return adj;
}

function degrees(data: GraphData): Map<string, number> {
  const d = new Map<string, number>();
  for (const e of data.edges) {
    d.set(e.source, (d.get(e.source) ?? 0) + 1);
    d.set(e.target, (d.get(e.target) ?? 0) + 1);
  }
  return d;
}

/**
 * Count edge crossings between two adjacent, ordered columns. Used by the tests
 * to prove the ordering pass actually helps.
 */
export function countCrossings(
  data: GraphData,
  left: string[],
  right: string[],
): number {
  const li = new Map(left.map((id, i) => [id, i]));
  const ri = new Map(right.map((id, i) => [id, i]));
  const pairs: Array<[number, number]> = [];
  for (const e of data.edges) {
    // Consider each edge in whichever direction spans left → right.
    if (li.has(e.source) && ri.has(e.target)) pairs.push([li.get(e.source)!, ri.get(e.target)!]);
    else if (li.has(e.target) && ri.has(e.source)) pairs.push([li.get(e.target)!, ri.get(e.source)!]);
  }
  let crossings = 0;
  for (let i = 0; i < pairs.length; i++) {
    for (let j = i + 1; j < pairs.length; j++) {
      const [a1, b1] = pairs[i]!, [a2, b2] = pairs[j]!;
      if ((a1 - a2) * (b1 - b2) < 0) crossings++;
    }
  }
  return crossings;
}

/**
 * One column per entity kind, nodes stacked so links between adjacent columns
 * cross as little as possible. Deterministic, free of radiating symmetry, and
 * the easiest layout to scan.
 *
 * Ordering uses the barycenter heuristic (the standard layered-graph crossing
 * reduction): repeatedly reposition each column by the mean position of each
 * node's neighbours in the neighbouring column, sweeping forwards and back.
 * Without this, a fan of many indicators hanging off a couple of incidents
 * produces a wall of crossing lines.
 */
export function lanePositions(data: GraphData): Map<string, Pt> {
  const pos = new Map<string, Pt>();
  const byType = new Map<EntityType, GraphNode[]>();
  for (const n of data.nodes) {
    const list = byType.get(n.type) ?? [];
    list.push(n);
    byType.set(n.type, list);
  }
  const degree = degrees(data);
  const adj = buildAdjacency(data);
  const cols = TYPE_ORDER.filter((t) => byType.has(t));

  // Seed: most-connected first, then alphabetical — stable and meaningful.
  const order: string[][] = cols.map((t) =>
    [...byType.get(t)!]
      .sort((a, b) => (degree.get(b.id) ?? 0) - (degree.get(a.id) ?? 0) || a.label.localeCompare(b.label))
      .map((n) => n.id),
  );

  /** Reorder column `ci` by the mean index of each node's neighbours in `ref`. */
  const sweep = (ci: number, ref: string[]) => {
    const refIndex = new Map(ref.map((id, i) => [id, i]));
    const current = new Map(order[ci]!.map((id, i) => [id, i]));
    order[ci] = [...order[ci]!].sort((a, b) => {
      const bary = (id: string) => {
        const ns = (adj.get(id) ?? []).map((n) => refIndex.get(n)).filter((v): v is number => v !== undefined);
        // No neighbour in the reference column → hold current position.
        return ns.length ? ns.reduce((s, v) => s + v, 0) / ns.length : current.get(id)!;
      };
      return bary(a) - bary(b) || current.get(a)! - current.get(b)!;
    });
  };

  for (let pass = 0; pass < 4; pass++) {
    for (let ci = 1; ci < order.length; ci++) sweep(ci, order[ci - 1]!);
    for (let ci = order.length - 2; ci >= 0; ci--) sweep(ci, order[ci + 1]!);
  }

  order.forEach((ids, ci) => {
    const top = -((ids.length * LANE_ROW_H) / 2);   // centre each column vertically
    ids.forEach((id, ri) => pos.set(id, { x: ci * LANE_W, y: top + ri * LANE_ROW_H + LANE_ROW_H / 2 }));
  });
  return pos;
}

/** Column order produced by the lanes layout, top to bottom. Exposed for tests. */
export function laneOrder(data: GraphData): string[][] {
  const pos = lanePositions(data);
  const byX = new Map<number, Array<{ id: string; y: number }>>();
  for (const [id, p] of pos) {
    const list = byX.get(p.x) ?? [];
    list.push({ id, y: p.y });
    byX.set(p.x, list);
  }
  return [...byX.entries()]
    .sort((a, b) => a[0] - b[0])
    .map(([, list]) => list.sort((a, b) => a.y - b.y).map((n) => n.id));
}

/** Dagre left-to-right hierarchy — returns CENTER positions per node id. */
export function treePositions(data: GraphData): Map<string, Pt> {
  const g = new dagre.graphlib.Graph();
  g.setDefaultEdgeLabel(() => ({}));
  g.setGraph({ rankdir: 'LR', ranksep: 110, nodesep: 30, edgesep: 20, marginx: 24, marginy: 24 });
  for (const n of data.nodes) g.setNode(n.id, { width: NODE_W, height: NODE_H });
  for (const e of data.edges) if (g.hasNode(e.source) && g.hasNode(e.target)) g.setEdge(e.source, e.target, {});
  dagre.layout(g);
  const pos = new Map<string, Pt>();
  for (const n of data.nodes) { const p = g.node(n.id); pos.set(n.id, { x: p?.x ?? 0, y: p?.y ?? 0 }); }
  return pos;
}

/** Concentric BFS rings from the case (or highest-degree) node. */
export function radialPositions(data: GraphData): Map<string, Pt> {
  const pos = new Map<string, Pt>();
  if (!data.nodes.length) return pos;
  const adj = buildAdjacency(data);
  const root = data.nodes.find((n) => n.type === 'case')?.id
    ?? [...data.nodes].sort((a, b) => (adj.get(b.id)?.length ?? 0) - (adj.get(a.id)?.length ?? 0))[0]!.id;

  const depth = new Map<string, number>([[root, 0]]);
  const queue = [root];
  while (queue.length) {
    const cur = queue.shift()!;
    const d = depth.get(cur)!;
    for (const nb of adj.get(cur) ?? []) if (!depth.has(nb)) { depth.set(nb, d + 1); queue.push(nb); }
  }
  let maxD = 0;
  for (const d of depth.values()) maxD = Math.max(maxD, d);
  for (const n of data.nodes) if (!depth.has(n.id)) depth.set(n.id, maxD + 1);   // disconnected → outer ring

  const byDepth = new Map<number, string[]>();
  for (const n of data.nodes) {
    const d = depth.get(n.id)!;
    const list = byDepth.get(d) ?? [];
    list.push(n.id);
    byDepth.set(d, list);
  }

  for (const [d, ids] of byDepth) {
    if (d === 0 && ids.length === 1) { pos.set(ids[0]!, { x: 0, y: 0 }); continue; }
    const radius = Math.max(d, 0.5) * RING_R;
    const phase = d * GOLDEN_ANGLE;
    ids.forEach((id, i) => {
      const a = (2 * Math.PI * i) / ids.length + phase;
      pos.set(id, { x: Math.cos(a) * radius, y: Math.sin(a) * radius });
    });
  }
  return pos;
}

/** Fruchterman–Reingold force-directed layout, seeded from the radial layout. */
export function forcePositions(data: GraphData): Map<string, Pt> {
  const seed = radialPositions(data);
  const ids = data.nodes.map((n) => n.id);
  if (ids.length <= 1) return seed;
  const P = new Map<string, Pt>();
  for (const id of ids) { const s = seed.get(id) ?? { x: 0, y: 0 }; P.set(id, { x: s.x, y: s.y }); }
  const edges = data.edges.filter((e) => P.has(e.source) && P.has(e.target));

  const k = 320;
  const iterations = ids.length > 150 ? 140 : 260;
  let temp = k * 0.9;
  for (let it = 0; it < iterations; it++) {
    const disp = new Map<string, Pt>();
    for (const id of ids) disp.set(id, { x: 0, y: 0 });
    for (let i = 0; i < ids.length; i++) {
      for (let j = i + 1; j < ids.length; j++) {
        const a = P.get(ids[i]!)!, b = P.get(ids[j]!)!;
        const dx = a.x - b.x, dy = a.y - b.y;
        const dist = Math.hypot(dx, dy) || 0.01;
        const f = (k * k) / dist;
        const ux = dx / dist, uy = dy / dist;
        const di = disp.get(ids[i]!)!; di.x += ux * f; di.y += uy * f;
        const dj = disp.get(ids[j]!)!; dj.x -= ux * f; dj.y -= uy * f;
      }
    }
    for (const e of edges) {
      const a = P.get(e.source)!, b = P.get(e.target)!;
      const dx = a.x - b.x, dy = a.y - b.y;
      const dist = Math.hypot(dx, dy) || 0.01;
      const f = (dist * dist) / k;
      const ux = dx / dist, uy = dy / dist;
      const da = disp.get(e.source)!; da.x -= ux * f; da.y -= uy * f;
      const db = disp.get(e.target)!; db.x += ux * f; db.y += uy * f;
    }
    for (const id of ids) {
      const d = disp.get(id)!;
      const dl = Math.hypot(d.x, d.y) || 0.01;
      const p = P.get(id)!;
      p.x += (d.x / dl) * Math.min(dl, temp);
      p.y += (d.y / dl) * Math.min(dl, temp);
    }
    temp = Math.max(temp * 0.97, k * 0.02);
  }
  return P;
}

export function computePositions(data: GraphData, mode: LayoutMode): Map<string, Pt> {
  if (mode === 'lanes') return lanePositions(data);
  if (mode === 'radial') return radialPositions(data);
  if (mode === 'force') return forcePositions(data);
  return treePositions(data);
}

/**
 * Edge routing per layout:
 *  - tree   → orthogonal (smoothstep), which suits a dagre hierarchy.
 *  - lanes  → bezier. A hub fanning out to many nodes produces overlapping
 *             collinear runs with orthogonal routing; curves separate cleanly.
 *  - radial/force → straight. Right-angle bends on a radiating layout read as
 *             bent arms rather than links.
 */
export function edgeTypeFor(mode: LayoutMode): 'smoothstep' | 'straight' | 'default' {
  if (mode === 'radial' || mode === 'force') return 'straight';
  if (mode === 'lanes') return 'default';   // reactflow's bezier edge
  return 'smoothstep';
}

/**
 * Repeating the same relation ("observed") on dozens of edges is noise that
 * buries the graph. Past this many edges, labels are shown only for the
 * currently focused node's links.
 */
export const EDGE_LABEL_LIMIT = 12;
