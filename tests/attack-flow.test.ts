import { describe, it, expect } from 'vitest';
import { validateAttackFlow } from '../server/lib/attack-flow.js';

type N = { id: string; type: string; name: string; technique_id?: string | null; description?: string };
type E = { source: string; target: string; label: string };
const chain = [{ technique_id: 'T1059', sub_technique_id: 'T1059.001' }, { technique_id: 'T1566', sub_technique_id: null }];
const flow = (nodes: N[], edges: E[]) => validateAttackFlow({ nodes, edges } as never, chain);

describe('validateAttackFlow', () => {
  it('keeps a valid 2-action DAG', () => {
    const r = flow(
      [{ id: 'a', type: 'action', name: 'A', technique_id: 'T1566' }, { id: 'b', type: 'action', name: 'B', technique_id: 'T1059.001' }],
      [{ source: 'a', target: 'b', label: 'leads to' }],
    );
    expect(r).toBeDefined();
    expect(r!.nodes).toHaveLength(2);
    expect(r!.edges).toHaveLength(1);
  });

  it('drops action nodes whose technique is not in the chain', () => {
    const r = flow(
      [{ id: 'a', type: 'action', name: 'A', technique_id: 'T1566' }, { id: 'b', type: 'action', name: 'B', technique_id: 'T9999' }, { id: 'c', type: 'action', name: 'C', technique_id: 'T1059.001' }],
      [{ source: 'a', target: 'b', label: 'leads to' }, { source: 'a', target: 'c', label: 'leads to' }],
    );
    // 'b' (unknown technique) is removed; a→c remains → 2 actions, 1 edge.
    expect(r).toBeDefined();
    expect(r!.nodes.find((n) => n.id === 'b')).toBeUndefined();
    expect(r!.nodes).toHaveLength(2);
  });

  it('discards a flow with fewer than 2 action nodes', () => {
    const r = flow(
      [{ id: 'a', type: 'action', name: 'A', technique_id: 'T1566' }, { id: 'x', type: 'asset', name: 'srv' }],
      [{ source: 'a', target: 'x', label: 'targets' }],
    );
    expect(r).toBeUndefined();
  });

  it('discards a flow with no edges', () => {
    expect(flow(
      [{ id: 'a', type: 'action', name: 'A', technique_id: 'T1566' }, { id: 'b', type: 'action', name: 'B', technique_id: 'T1059.001' }],
      [],
    )).toBeUndefined();
  });

  it('breaks cycles to enforce a DAG', () => {
    const r = flow(
      [{ id: 'a', type: 'action', name: 'A', technique_id: 'T1566' }, { id: 'b', type: 'action', name: 'B', technique_id: 'T1059.001' }],
      [{ source: 'a', target: 'b', label: 'leads to' }, { source: 'b', target: 'a', label: 'leads to' }],
    );
    // One of the two edges (the back-edge) is removed; still ≥2 actions + ≥1 edge.
    expect(r).toBeDefined();
    expect(r!.edges.length).toBe(1);
  });

  it('dedupes duplicate edges and nodes', () => {
    const r = flow(
      [{ id: 'a', type: 'action', name: 'A', technique_id: 'T1566' }, { id: 'a', type: 'action', name: 'dup', technique_id: 'T1566' }, { id: 'b', type: 'action', name: 'B', technique_id: 'T1059.001' }],
      [{ source: 'a', target: 'b', label: 'leads to' }, { source: 'a', target: 'b', label: 'leads to' }],
    );
    expect(r).toBeDefined();
    expect(r!.nodes.filter((n) => n.id === 'a')).toHaveLength(1);
    expect(r!.edges).toHaveLength(1);
  });

  it('returns undefined for malformed input', () => {
    expect(validateAttackFlow(null, chain)).toBeUndefined();
    expect(validateAttackFlow(undefined, chain)).toBeUndefined();
    expect(validateAttackFlow({ nodes: 'x' } as never, chain)).toBeUndefined();
  });
});
