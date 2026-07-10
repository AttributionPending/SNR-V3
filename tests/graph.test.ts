import { describe, it, expect } from 'vitest';
import { assembleGraph } from '../server/lib/graph.js';

describe('assembleGraph', () => {
  it('links case → session → actor → malware and session → ioc, deduped', () => {
    const g = assembleGraph({
      caseNode: { id: 'c1', name: 'Op Nightfall' },
      sessions: [
        { id: 's1', name: 'Incident A', severity: 'High' },
        { id: 's2', name: 'Incident B', severity: 'Medium' },
      ],
      sessionActors: [
        { session_id: 's1', actor_id: 'a1', actor_name: 'APT-Foo', malware_families: JSON.stringify(['Cobalt Strike']) },
        { session_id: 's2', actor_id: 'a1', actor_name: 'APT-Foo', malware_families: JSON.stringify(['Cobalt Strike']) },
      ],
      sessionIocs: [
        { session_id: 's1', ioc_type: 'ipv4', ioc_value: '1.2.3.4', ioc_value_norm: '1.2.3.4' },
        { session_id: 's2', ioc_type: 'ipv4', ioc_value: '1.2.3.4', ioc_value_norm: '1.2.3.4' },
      ],
    });

    const ids = g.nodes.map((n) => n.id).sort();
    expect(ids).toEqual(['actor:a1', 'case:c1', 'ioc:ipv4:1.2.3.4', 'malware:cobalt strike', 'session:s1', 'session:s2']);

    // actor node appears once despite two links; malware once.
    expect(g.nodes.filter((n) => n.type === 'actor')).toHaveLength(1);
    expect(g.nodes.filter((n) => n.type === 'malware')).toHaveLength(1);

    // both sessions connect to the shared indicator (the IOC node fans in from 2 sessions).
    const iocEdges = g.edges.filter((e) => e.target === 'ioc:ipv4:1.2.3.4');
    expect(iocEdges.map((e) => e.source).sort()).toEqual(['session:s1', 'session:s2']);

    // case contains both sessions; actor uses malware.
    expect(g.edges).toContainEqual({ source: 'case:c1', target: 'session:s1', label: 'contains' });
    expect(g.edges).toContainEqual({ source: 'actor:a1', target: 'malware:cobalt strike', label: 'uses' });

    // no duplicate edges.
    const edgeKeys = g.edges.map((e) => `${e.source}->${e.target}`);
    expect(new Set(edgeKeys).size).toBe(edgeKeys.length);
  });

  it('ignores actors/iocs referencing sessions outside the set', () => {
    const g = assembleGraph({
      sessions: [{ id: 's1', name: 'A' }],
      sessionActors: [{ session_id: 'sX', actor_id: 'a9', actor_name: 'Ghost' }],
      sessionIocs: [{ session_id: 'sX', ioc_type: 'domain', ioc_value: 'evil.com', ioc_value_norm: 'evil.com' }],
    });
    expect(g.nodes.map((n) => n.id)).toEqual(['session:s1']);
    expect(g.edges).toHaveLength(0);
  });

  it('caps IOC fan-out to the most-shared indicators', () => {
    const sessions = Array.from({ length: 3 }, (_, i) => ({ id: `s${i}`, name: `S${i}` }));
    // ioc A is in all 3 sessions; iocs B,C,D each in 1 session.
    const sessionIocs = [
      ...sessions.map((s) => ({ session_id: s.id, ioc_type: 'ipv4', ioc_value: '10.0.0.1', ioc_value_norm: '10.0.0.1' })),
      { session_id: 's0', ioc_type: 'ipv4', ioc_value: '10.0.0.2', ioc_value_norm: '10.0.0.2' },
      { session_id: 's1', ioc_type: 'ipv4', ioc_value: '10.0.0.3', ioc_value_norm: '10.0.0.3' },
    ];
    const g = assembleGraph({ sessions, sessionActors: [], sessionIocs, maxIocs: 1 });
    const iocNodes = g.nodes.filter((n) => n.type === 'ioc');
    expect(iocNodes).toHaveLength(1);
    expect(iocNodes[0].id).toBe('ioc:ipv4:10.0.0.1'); // the most-shared one survives the cap
  });
});
