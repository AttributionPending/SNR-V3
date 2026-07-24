import { describe, it, expect } from 'vitest';
import {
  lanePositions, radialPositions, computePositions, edgeTypeFor, TYPE_ORDER,
  laneOrder, countCrossings,
} from './graph-layout';
import type { GraphData } from './api';

/**
 * The reported problem shape: two incidents fanning out to many indicators,
 * interleaved so a naive ordering produces a wall of crossing lines.
 */
function fanGraph(indicatorCount: number): GraphData {
  const nodes: GraphData['nodes'] = [
    { id: 'case:c', type: 'case', label: 'Case' },
    { id: 'session:A', type: 'session', label: 'Incident A' },
    { id: 'session:B', type: 'session', label: 'Incident B' },
  ];
  const edges: GraphData['edges'] = [
    { source: 'case:c', target: 'session:A', label: 'contains' },
    { source: 'case:c', target: 'session:B', label: 'contains' },
  ];
  for (let i = 0; i < indicatorCount; i++) {
    const id = `ioc:ipv4:10.0.0.${i}`;
    nodes.push({ id, type: 'ioc', label: `10.0.0.${i}` });
    // Alternate parents so the seed order interleaves the two fans.
    edges.push({ source: i % 2 === 0 ? 'session:A' : 'session:B', target: id, label: 'observed' });
  }
  return { nodes, edges };
}

/** A case with 4 incidents — the shape that produced an axis-aligned cross. */
const fourWay: GraphData = {
  nodes: [
    { id: 'case:c', type: 'case', label: 'Case' },
    { id: 'session:1', type: 'session', label: 'S1' },
    { id: 'session:2', type: 'session', label: 'S2' },
    { id: 'session:3', type: 'session', label: 'S3' },
    { id: 'session:4', type: 'session', label: 'S4' },
  ],
  edges: [1, 2, 3, 4].map((i) => ({ source: 'case:c', target: `session:${i}`, label: 'contains' })),
};

const mixed: GraphData = {
  nodes: [
    { id: 'case:c', type: 'case', label: 'Case' },
    { id: 'session:1', type: 'session', label: 'Bravo' },
    { id: 'session:2', type: 'session', label: 'Alpha' },
    { id: 'actor:a', type: 'actor', label: 'APT-X' },
    { id: 'ioc:ipv4:1.1.1.1', type: 'ioc', label: '1.1.1.1' },
    { id: 'ioc:ipv4:2.2.2.2', type: 'ioc', label: '2.2.2.2' },
    { id: 'technique:T1566', type: 'technique', label: 'T1566 Phishing' },
  ],
  edges: [
    { source: 'case:c', target: 'session:1', label: 'contains' },
    { source: 'case:c', target: 'session:2', label: 'contains' },
    { source: 'session:1', target: 'actor:a', label: 'attributed-to' },
    { source: 'session:1', target: 'ioc:ipv4:1.1.1.1', label: 'observed' },
    { source: 'session:2', target: 'ioc:ipv4:2.2.2.2', label: 'observed' },
    { source: 'case:c', target: 'technique:T1566', label: 'tracks' },
  ],
};

describe('lanes layout', () => {
  const pos = lanePositions(mixed);

  it('places every node', () => {
    expect(pos.size).toBe(mixed.nodes.length);
  });

  it('gives each entity kind its own column, ordered canonically', () => {
    const xOf = (id: string) => pos.get(id)!.x;
    // One distinct x per kind…
    expect(xOf('session:1')).toBe(xOf('session:2'));
    expect(xOf('ioc:ipv4:1.1.1.1')).toBe(xOf('ioc:ipv4:2.2.2.2'));
    // …advancing left-to-right in TYPE_ORDER.
    const order = ['case:c', 'session:1', 'actor:a', 'ioc:ipv4:1.1.1.1', 'technique:T1566'];
    const xs = order.map(xOf);
    expect(xs).toEqual([...xs].sort((a, b) => a - b));
    expect(new Set(xs).size).toBe(order.length);
    expect(TYPE_ORDER.indexOf('case')).toBeLessThan(TYPE_ORDER.indexOf('ioc'));
  });

  it('stacks a column without overlapping and centres it', () => {
    const ys = [pos.get('session:1')!.y, pos.get('session:2')!.y];
    expect(ys[0]).not.toBe(ys[1]);
    expect(ys[0]! + ys[1]!).toBeCloseTo(0, 6);   // centred about the origin
  });

  it('orders a column by connectedness first', () => {
    // session:1 has 3 edges, session:2 has 2 → session:1 sits above.
    expect(pos.get('session:1')!.y).toBeLessThan(pos.get('session:2')!.y);
  });

  it('is deterministic', () => {
    const a = lanePositions(mixed), b = lanePositions(mixed);
    for (const [id, p] of a) expect(b.get(id)).toEqual(p);
  });
});

describe('radial layout does not form an axis-aligned cross', () => {
  // Regression guard: a 4-node ring previously landed exactly on N/E/S/W which,
  // combined with right-angle edges, read as bent arms off a centre point.
  const pos = radialPositions(fourWay);

  it('keeps ring nodes off the cardinal axes', () => {
    for (const id of ['session:1', 'session:2', 'session:3', 'session:4']) {
      const p = pos.get(id)!;
      expect(Math.abs(p.x), `${id} x`).toBeGreaterThan(1);
      expect(Math.abs(p.y), `${id} y`).toBeGreaterThan(1);
    }
  });

  it('still spreads the ring evenly around the centre', () => {
    const root = pos.get('case:c')!;
    expect(root).toEqual({ x: 0, y: 0 });
    const radii = ['session:1', 'session:2', 'session:3', 'session:4']
      .map((id) => Math.hypot(pos.get(id)!.x, pos.get(id)!.y));
    for (const r of radii) expect(r).toBeCloseTo(radii[0]!, 6);
  });
});

describe('lanes crossing reduction', () => {
  const graph = fanGraph(18);   // the reported shape: 2 incidents, 18 indicators

  it('groups each incident\'s indicators together instead of interleaving them', () => {
    const cols = laneOrder(graph);
    const iocCol = cols[cols.length - 1]!;          // indicators are the last lane
    expect(iocCol).toHaveLength(18);

    const parentOf = (id: string) =>
      graph.edges.find((e) => e.target === id)!.source;
    const parents = iocCol.map(parentOf);
    // Contiguous blocks: the parent changes at most once down the column.
    const switches = parents.filter((p, i) => i > 0 && p !== parents[i - 1]).length;
    expect(switches).toBe(1);
  });

  it('eliminates crossings between the incident and indicator lanes', () => {
    const cols = laneOrder(graph);
    const sessions = cols[1]!;
    const iocs = cols[cols.length - 1]!;
    expect(countCrossings(graph, sessions, iocs)).toBe(0);
  });

  it('beats the naive interleaved ordering it replaced', () => {
    const cols = laneOrder(graph);
    const sessions = cols[1]!;
    const optimised = countCrossings(graph, sessions, cols[cols.length - 1]!);
    // Seed order before the barycenter sweeps: indicators in creation order,
    // which alternates between the two incidents.
    const naive = graph.nodes.filter((n) => n.type === 'ioc').map((n) => n.id);
    expect(countCrossings(graph, sessions, naive)).toBeGreaterThan(0);
    expect(optimised).toBeLessThan(countCrossings(graph, sessions, naive));
  });

  it('stays deterministic under crossing reduction', () => {
    expect(laneOrder(graph)).toEqual(laneOrder(graph));
  });
});

describe('edge routing', () => {
  it('picks a routing that suits each layout', () => {
    // Right-angle bends turned radial spokes into bent arms.
    expect(edgeTypeFor('radial')).toBe('straight');
    expect(edgeTypeFor('force')).toBe('straight');
    // A hub fanning out to many nodes stacks into overlapping collinear runs
    // with orthogonal routing, so lanes uses curves.
    expect(edgeTypeFor('lanes')).toBe('default');
    expect(edgeTypeFor('tree')).toBe('smoothstep');
  });
});

describe('computePositions', () => {
  it('returns a position for every node in every mode', () => {
    for (const mode of ['lanes', 'tree', 'radial', 'force'] as const) {
      const p = computePositions(mixed, mode);
      expect(p.size, mode).toBe(mixed.nodes.length);
      for (const n of mixed.nodes) {
        const q = p.get(n.id)!;
        expect(Number.isFinite(q.x) && Number.isFinite(q.y), `${mode} ${n.id}`).toBe(true);
      }
    }
  });

  it('handles an empty graph and a single node', () => {
    for (const mode of ['lanes', 'tree', 'radial', 'force'] as const) {
      expect(computePositions({ nodes: [], edges: [] }, mode).size).toBe(0);
      const one: GraphData = { nodes: [{ id: 'case:c', type: 'case', label: 'C' }], edges: [] };
      expect(computePositions(one, mode).size).toBe(1);
    }
  });
});
