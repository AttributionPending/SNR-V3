import { describe, it, expect } from 'vitest';
import { mergeExtracted, mergeRules } from '../src/lib/workbench-merge.js';
import type { AnalysisResult } from '../src/types/index.js';

function tech(id: string, sub: string | null = null): AnalysisResult['attack_chain'][number] {
  return { technique_id: id, technique_name: id, tactic: 'Execution', tactic_id: '', sub_technique_id: sub, sub_technique_name: null, evidence: '', confidence: 'Medium', detection_coverage: 'Unknown', detection_recommendation: '', order: 0 };
}
function ioc(type: AnalysisResult['iocs'][number]['type'], value: string): AnalysisResult['iocs'][number] {
  return { type, value, context: '', confidence: 'Medium' };
}
function rule(name: string): AnalysisResult['detection_rules'][number] {
  return { rule_type: 'sigma', rule_name: name, rule_content: '', description: '', source: 'generated', confidence: 'Medium', related_technique: null };
}
function blank(overrides: Partial<AnalysisResult> = {}): AnalysisResult {
  return {
    incident_summary: { title: 't', severity: 'Medium', confidence: 'Medium', description: '', analyst_notes: '' },
    attack_chain: [], iocs: [], detection_rules: [],
    threat_actor: { name: null, aliases: [], motivation: null, attribution_confidence: null, malware_families: [] },
    affected_assets: [], email_content: { subject: '', severity_badge: 'Medium' }, ...overrides,
  };
}

describe('mergeExtracted', () => {
  it('appends new techniques/IOCs/rules and dedupes existing ones', () => {
    const draft = blank({ attack_chain: [tech('T1059', 'T1059.001')], iocs: [ioc('domain', 'a.com')], detection_rules: [rule('R1')] });
    const t = {
      attack_chain: [tech('T1059', 'T1059.001') /* dup */, tech('T1566', 'T1566.001') /* new */],
      iocs: [ioc('domain', 'a.com') /* dup */, ioc('ipv4', '1.2.3.4') /* new */],
      detection_rules: [rule('R1') /* dup */, rule('R2') /* new */],
    };
    const { result, counts } = mergeExtracted(draft, t);
    expect(counts).toMatchObject({ techniques: 1, iocs: 1, rules: 1, flowAdded: false });
    expect(result.attack_chain.map((x) => x.sub_technique_id)).toEqual(['T1059.001', 'T1566.001']);
    expect(result.iocs.map((x) => x.value)).toEqual(['a.com', '1.2.3.4']);
    expect(result.detection_rules.map((x) => x.rule_name)).toEqual(['R1', 'R2']);
  });

  it('re-sequences attack_chain order after merge', () => {
    const draft = blank({ attack_chain: [tech('T1000')] });
    const { result } = mergeExtracted(draft, { attack_chain: [tech('T2000'), tech('T3000')] });
    expect(result.attack_chain.map((x) => x.order)).toEqual([0, 1, 2]);
  });

  it('seeds threat_actor/assets/flow only when the draft is empty', () => {
    const draftEmpty = blank();
    const t = { threat_actor: { name: 'APT-X', aliases: [], motivation: null, attribution_confidence: null, malware_families: [] }, affected_assets: [{ hostname: 'h', ip: null, role: 'x', compromise_confidence: 'High' as const }], attack_flow: { nodes: [{ id: 'f1', type: 'action' as const, name: 'n', technique_id: 'T1', description: '' }], edges: [] } };
    const merged = mergeExtracted(draftEmpty, t);
    expect(merged.result.threat_actor.name).toBe('APT-X');
    expect(merged.result.affected_assets).toHaveLength(1);
    expect(merged.counts.flowAdded).toBe(true);

    // When the draft already has these, they are preserved (not overwritten).
    const draftFull = blank({ threat_actor: { name: 'MINE', aliases: [], motivation: null, attribution_confidence: null, malware_families: [] }, attack_flow: { nodes: [{ id: 'x', type: 'action', name: 'mine', technique_id: 'T9', description: '' }], edges: [] } });
    const kept = mergeExtracted(draftFull, t);
    expect(kept.result.threat_actor.name).toBe('MINE');
    expect(kept.result.attack_flow?.nodes[0].id).toBe('x');
    expect(kept.counts.flowAdded).toBe(false);
  });
});

describe('mergeRules', () => {
  it('appends new rules and dedupes by name (case-insensitive)', () => {
    const draft = blank({ detection_rules: [rule('Alpha')] });
    const { result, added } = mergeRules(draft, [rule('alpha') /* dup */, rule('Beta') /* new */]);
    expect(added).toBe(1);
    expect(result.detection_rules.map((r) => r.rule_name)).toEqual(['Alpha', 'Beta']);
  });
});
