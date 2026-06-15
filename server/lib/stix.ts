import { v4 as uuidv4 } from 'uuid';
import type { AnalysisResult } from './claude.js';

type TLPLevel = 'CLEAR' | 'GREEN' | 'AMBER' | 'AMBER+STRICT' | 'RED';

const TLP_MARKING_IDS: Record<TLPLevel, string> = {
  CLEAR: 'marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9',
  GREEN: 'marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da',
  AMBER: 'marking-definition--f88d31f6-1088-4ef0-bc0d-9a28e79c5f8a',
  'AMBER+STRICT': 'marking-definition--939a9414-2ddd-4d32-a254-ea7b0f76bdc2',
  RED: 'marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed',
};

function stixTimestamp(date?: Date): string {
  return (date ?? new Date()).toISOString().replace(/\.\d{3}Z$/, '.000Z');
}

function stixId(type: string): string {
  return `${type}--${uuidv4()}`;
}

export interface StixBundle {
  type: 'bundle';
  id: string;
  spec_version: '2.1';
  objects: Record<string, unknown>[];
}

export function buildStixBundle(
  result: AnalysisResult,
  incidentId: string,
  tlp: TLPLevel,
  analystName: string,
  analystOrg: string,
  analystOverrides?: Record<string, string>
): StixBundle {
  const now = stixTimestamp();
  const markingRef = TLP_MARKING_IDS[tlp];
  const objects: Record<string, unknown>[] = [];

  // Identity: source organization
  const identityId = stixId('identity');
  objects.push({
    type: 'identity',
    spec_version: '2.1',
    id: identityId,
    created: now,
    modified: now,
    name: analystOrg,
    identity_class: 'organization',
    object_marking_refs: [markingRef],
  });

  // Identity: analyst
  const analystIdentityId = stixId('identity');
  objects.push({
    type: 'identity',
    spec_version: '2.1',
    id: analystIdentityId,
    created: now,
    modified: now,
    name: analystName,
    identity_class: 'individual',
    object_marking_refs: [markingRef],
  });

  // Threat Actor (if attributable)
  let threatActorId: string | null = null;
  if (result.threat_actor?.name) {
    threatActorId = stixId('threat-actor');
    objects.push({
      type: 'threat-actor',
      spec_version: '2.1',
      id: threatActorId,
      created: now,
      modified: now,
      name: result.threat_actor.name,
      aliases: result.threat_actor.aliases ?? [],
      threat_actor_types: ['unknown'],
      ...(result.threat_actor.motivation && { primary_motivation: result.threat_actor.motivation }),
      confidence: result.threat_actor.attribution_confidence === 'High' ? 85
        : result.threat_actor.attribution_confidence === 'Medium' ? 50 : 25,
      created_by_ref: identityId,
      object_marking_refs: [markingRef],
    });
  }

  // Attack Pattern objects (one per ATT&CK technique)
  const attackPatternIds: string[] = [];
  for (const technique of result.attack_chain) {
    const apId = stixId('attack-pattern');
    attackPatternIds.push(apId);
    const externalRef: Record<string, unknown>[] = [{
      source_name: 'mitre-attack',
      external_id: technique.sub_technique_id ?? technique.technique_id,
      url: `https://attack.mitre.org/techniques/${(technique.sub_technique_id ?? technique.technique_id).replace('.', '/')}`,
    }];
    objects.push({
      type: 'attack-pattern',
      spec_version: '2.1',
      id: apId,
      created: now,
      modified: now,
      name: technique.sub_technique_name ?? technique.technique_name,
      description: technique.evidence,
      kill_chain_phases: [{
        kill_chain_name: 'mitre-attack',
        phase_name: technique.tactic.toLowerCase().replace(/\s+/g, '-'),
      }],
      external_references: externalRef,
      x_snr_confidence: technique.confidence,
      x_snr_detection_coverage: technique.detection_coverage,
      x_snr_detection_recommendation: technique.detection_recommendation,
      created_by_ref: identityId,
      object_marking_refs: [markingRef],
    });

    // Relationship: threat-actor uses attack-pattern
    if (threatActorId) {
      objects.push({
        type: 'relationship',
        spec_version: '2.1',
        id: stixId('relationship'),
        created: now,
        modified: now,
        relationship_type: 'uses',
        source_ref: threatActorId,
        target_ref: apId,
        created_by_ref: identityId,
        object_marking_refs: [markingRef],
      });
    }
  }

  // Indicator objects (IOCs)
  const indicatorIds: string[] = [];
  for (const ioc of result.iocs) {
    const indicatorId = stixId('indicator');
    indicatorIds.push(indicatorId);
    const pattern = buildStixPattern(ioc.type, ioc.value);
    if (!pattern) continue;

    objects.push({
      type: 'indicator',
      spec_version: '2.1',
      id: indicatorId,
      created: now,
      modified: now,
      name: ioc.value,
      description: ioc.context,
      indicator_types: ['malicious-activity'],
      pattern,
      pattern_type: 'stix',
      valid_from: now,
      x_snr_ioc_type: ioc.type,
      x_snr_confidence: ioc.confidence,
      created_by_ref: identityId,
      object_marking_refs: [markingRef],
    });
  }

  // Observed Data (affected assets)
  if (result.affected_assets.length > 0) {
    const obsId = stixId('observed-data');
    objects.push({
      type: 'observed-data',
      spec_version: '2.1',
      id: obsId,
      created: now,
      modified: now,
      first_observed: now,
      last_observed: now,
      number_observed: result.affected_assets.length,
      object_refs: [],
      x_snr_affected_assets: result.affected_assets,
      created_by_ref: identityId,
      object_marking_refs: [markingRef],
    });
  }

  // Analyst Notes (overrides) — exclude internal bookkeeping keys like
  // ioc_false_positives (already applied as filtering, not analyst content)
  const displayOverrides = analystOverrides
    ? Object.fromEntries(Object.entries(analystOverrides).filter(([k]) => k !== 'ioc_false_positives'))
    : undefined;
  if (displayOverrides && Object.keys(displayOverrides).length > 0) {
    objects.push({
      type: 'note',
      spec_version: '2.1',
      id: stixId('note'),
      created: now,
      modified: now,
      content: `Analyst overrides applied:\n${JSON.stringify(displayOverrides, null, 2)}`,
      authors: [analystName],
      object_refs: attackPatternIds.length > 0 ? [attackPatternIds[0]] : [identityId],
      created_by_ref: analystIdentityId,
      object_marking_refs: [markingRef],
    });
  }

  // Incident note
  objects.push({
    type: 'note',
    spec_version: '2.1',
    id: stixId('note'),
    created: now,
    modified: now,
    content: `Incident: ${result.incident_summary.title}\nSeverity: ${result.incident_summary.severity}\nDescription: ${result.incident_summary.description}\n\nGenerated by SNR (Signal-to-Noise) v1.0`,
    authors: [analystName],
    x_snr_incident_id: incidentId,
    x_snr_generated_by: 'SNR v1.0',
    object_refs: attackPatternIds.length > 0 ? attackPatternIds : [identityId],
    created_by_ref: analystIdentityId,
    object_marking_refs: [markingRef],
  });

  // MITRE Attack Flow extension objects (additive — only when a flow exists)
  if (result.attack_flow && result.attack_flow.nodes.length > 0) {
    appendAttackFlowObjects(objects, result, identityId, markingRef, now);
  }

  return {
    type: 'bundle',
    id: stixId('bundle'),
    spec_version: '2.1',
    objects,
  };
}

// Official MITRE Attack Flow STIX 2.1 extension definition id
const ATTACK_FLOW_EXT_ID = 'extension-definition--fb9c968a-745b-4ade-9b25-c324172197f4';
const ATTACK_FLOW_EXT = { [ATTACK_FLOW_EXT_ID]: { extension_type: 'new-sdo' } };

/**
 * Append MITRE Attack Flow extension objects for the causal graph:
 * extension-definition, attack-flow SDO, and attack-action / attack-asset /
 * attack-operator SDOs plus tool/malware SDOs, wiring edges via effect_refs.
 * Purely additive — leaves all existing bundle objects untouched.
 */
function appendAttackFlowObjects(
  objects: Record<string, unknown>[],
  result: AnalysisResult,
  identityId: string,
  markingRef: string,
  now: string,
): void {
  const flow = result.attack_flow!;

  // Extension definition (self-describing, per the Attack Flow spec)
  objects.push({
    type: 'extension-definition',
    spec_version: '2.1',
    id: ATTACK_FLOW_EXT_ID,
    created: now,
    modified: now,
    name: 'Attack Flow',
    description: 'Extends STIX 2.1 with features to create Attack Flows.',
    created_by_ref: identityId,
    schema: 'https://center-for-threat-informed-defense.github.io/attack-flow/stix/attack-flow-schema.json',
    version: '2.0.0',
    extension_types: ['new-sdo'],
    object_marking_refs: [markingRef],
  });

  // Map flow node id → STIX object id (type depends on node type)
  const stixIdByNode = new Map<string, string>();
  for (const n of flow.nodes) {
    const t = n.type === 'action' ? 'attack-action'
      : n.type === 'asset' ? 'attack-asset'
      : n.type === 'tool' ? 'tool'
      : n.type === 'malware' ? 'malware'
      : 'attack-operator';
    stixIdByNode.set(n.id, stixId(t));
  }

  // Outgoing edges grouped by source (for effect_refs / relationships)
  const outBySource = new Map<string, { target: string; label: string }[]>();
  const incoming = new Set<string>();
  for (const e of flow.edges) {
    if (!outBySource.has(e.source)) outBySource.set(e.source, []);
    outBySource.get(e.source)!.push({ target: e.target, label: e.label });
    incoming.add(e.target);
  }

  // attack-flow SDO — start_refs are action nodes with no incoming edge
  const startRefs = flow.nodes
    .filter((n) => n.type === 'action' && !incoming.has(n.id))
    .map((n) => stixIdByNode.get(n.id)!);
  objects.push({
    type: 'attack-flow',
    spec_version: '2.1',
    id: stixId('attack-flow'),
    created: now,
    modified: now,
    name: result.incident_summary.title,
    description: result.incident_summary.description,
    scope: 'incident',
    start_refs: startRefs.length > 0 ? startRefs : flow.nodes.slice(0, 1).map((n) => stixIdByNode.get(n.id)!),
    created_by_ref: identityId,
    extensions: ATTACK_FLOW_EXT,
    object_marking_refs: [markingRef],
  });

  // Per-node SDOs
  for (const n of flow.nodes) {
    const id = stixIdByNode.get(n.id)!;
    const effectRefs = (outBySource.get(n.id) ?? []).map((e) => stixIdByNode.get(e.target)!).filter(Boolean);

    if (n.type === 'action') {
      objects.push({
        type: 'attack-action',
        spec_version: '2.1',
        id,
        created: now,
        modified: now,
        name: n.name,
        ...(n.technique_id && { technique_id: n.technique_id }),
        description: n.description,
        ...(effectRefs.length > 0 && { effect_refs: effectRefs }),
        created_by_ref: identityId,
        extensions: ATTACK_FLOW_EXT,
        object_marking_refs: [markingRef],
      });
    } else if (n.type === 'asset') {
      objects.push({
        type: 'attack-asset',
        spec_version: '2.1',
        id,
        created: now,
        modified: now,
        name: n.name,
        description: n.description,
        created_by_ref: identityId,
        extensions: ATTACK_FLOW_EXT,
        object_marking_refs: [markingRef],
      });
    } else if (n.type === 'operator_and' || n.type === 'operator_or') {
      objects.push({
        type: 'attack-operator',
        spec_version: '2.1',
        id,
        created: now,
        modified: now,
        operator: n.type === 'operator_and' ? 'AND' : 'OR',
        ...(effectRefs.length > 0 && { effect_refs: effectRefs }),
        created_by_ref: identityId,
        extensions: ATTACK_FLOW_EXT,
        object_marking_refs: [markingRef],
      });
    } else if (n.type === 'tool') {
      objects.push({
        type: 'tool', spec_version: '2.1', id, created: now, modified: now,
        name: n.name, description: n.description,
        created_by_ref: identityId, object_marking_refs: [markingRef],
      });
    } else if (n.type === 'malware') {
      objects.push({
        type: 'malware', spec_version: '2.1', id, created: now, modified: now,
        name: n.name, description: n.description, is_family: false,
        created_by_ref: identityId, object_marking_refs: [markingRef],
      });
    }
  }

  // Edges out of non-action/operator sources (e.g. asset→x) can't use
  // effect_refs — express them as standard STIX relationships instead.
  for (const [source, outs] of outBySource) {
    const srcNode = flow.nodes.find((n) => n.id === source);
    if (!srcNode || srcNode.type === 'action' || srcNode.type === 'operator_and' || srcNode.type === 'operator_or') continue;
    for (const e of outs) {
      objects.push({
        type: 'relationship',
        spec_version: '2.1',
        id: stixId('relationship'),
        created: now,
        modified: now,
        relationship_type: 'related-to',
        source_ref: stixIdByNode.get(source),
        target_ref: stixIdByNode.get(e.target),
        description: e.label,
        created_by_ref: identityId,
        object_marking_refs: [markingRef],
      });
    }
  }
}

function buildStixPattern(type: string, value: string): string | null {
  // Validate IOC values to prevent STIX pattern injection
  const validators: Record<string, RegExp> = {
    ipv4: /^(\d{1,3}\.){3}\d{1,3}(\/\d{1,2})?$/,
    ipv6: /^[0-9a-fA-F:]+$/,
    domain: /^([a-zA-Z0-9-]{1,63}\.)+[a-zA-Z]{2,}$/,
    url: /^https?:\/\/.+/,
    md5: /^[a-fA-F0-9]{32}$/,
    sha1: /^[a-fA-F0-9]{40}$/,
    sha256: /^[a-fA-F0-9]{64}$/,
    email: /^[^\s@]+@[^\s@]+\.[^\s@]+$/,
  };
  const validator = validators[type];
  if (validator && !validator.test(value)) return null;

  const escaped = value.replace(/'/g, "\\'").replace(/\\/g, '\\\\');
  switch (type) {
    case 'ipv4': return `[ipv4-addr:value = '${escaped}']`;
    case 'ipv6': return `[ipv6-addr:value = '${escaped}']`;
    case 'domain': return `[domain-name:value = '${escaped}']`;
    case 'url': return `[url:value = '${escaped}']`;
    case 'md5': return `[file:hashes.MD5 = '${escaped}']`;
    case 'sha1': return `[file:hashes.SHA-1 = '${escaped}']`;
    case 'sha256': return `[file:hashes.SHA-256 = '${escaped}']`;
    case 'email': return `[email-addr:value = '${escaped}']`;
    case 'filename': return `[file:name = '${escaped}']`;
    case 'registry': return `[windows-registry-key:key = '${escaped}']`;
    case 'user_agent': return `[network-traffic:extensions.'http-request-ext'.request_header.user-agent = '${escaped}']`;
    default: return null;
  }
}

export function buildNavigatorLayer(
  result: AnalysisResult,
  incidentTitle: string
): Record<string, unknown> {
  const techniqueColors: Record<string, string> = {
    High: '#ff6b35',
    Medium: '#ffd166',
    Low: '#06d6a0',
  };

  const techniques = result.attack_chain.map((t) => ({
    techniqueID: t.sub_technique_id ?? t.technique_id,
    tactic: t.tactic.toLowerCase().replace(/\s+/g, '-'),
    color: techniqueColors[t.confidence] ?? '#cccccc',
    comment: `Evidence: ${t.evidence}\nDetection: ${t.detection_coverage}\nRecommendation: ${t.detection_recommendation}`,
    enabled: true,
    metadata: [
      { name: 'confidence', value: t.confidence },
      { name: 'detection_coverage', value: t.detection_coverage },
      { name: 'snr_incident', value: incidentTitle },
    ],
    links: [],
    showSubtechniques: !!t.sub_technique_id,
  }));

  return {
    name: `SNR: ${incidentTitle}`,
    versions: {
      attack: '16',
      navigator: '5.1',
      layer: '4.5',
    },
    domain: 'enterprise-attack',
    description: `Generated by Signal-to-Noise (SNR) — ${new Date().toISOString()}`,
    filters: {
      platforms: ['Windows', 'Linux', 'macOS', 'Network', 'Cloud'],
    },
    sorting: 0,
    layout: {
      layout: 'side',
      aggregateFunction: 'average',
      showID: true,
      showName: true,
      showAggregateScores: false,
      countUnscored: false,
    },
    hideDisabled: false,
    techniques,
    gradient: {
      colors: ['#ff6666', '#ffe766', '#8ec843'],
      minValue: 0,
      maxValue: 100,
    },
    legendItems: [
      { label: 'High Confidence', color: '#ff6b35' },
      { label: 'Medium Confidence', color: '#ffd166' },
      { label: 'Low Confidence', color: '#06d6a0' },
    ],
    metadata: [
      { name: 'generated_by', value: 'SNR v1.0' },
      { name: 'generated_at', value: new Date().toISOString() },
    ],
    links: [],
    showTacticRowBackground: true,
    tacticRowBackground: '#0d1526',
    selectTechniquesAcrossTactics: false,
    selectSubtechniquesWithParent: false,
  };
}
