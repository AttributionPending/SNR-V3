/**
 * Attack Flow Builder (.afb) exporter.
 *
 * Produces the Attack Flow Builder v2 diagram format (anchors / latches /
 * handles / lines + a layout map + camera) so an analyst can open the flow in
 * MITRE's Attack Flow Builder and refine it. Adapted from the user's FlowViz
 * exporter (attackFlowV3Exporter.ts), reworked to run server-side on SNR's
 * AttackFlow model and to compute node positions with dagre (Node-compatible).
 */
import { v4 as uuidv4 } from 'uuid';
import dagre from 'dagre';
import type { AnalysisResult, AttackFlow, AttackFlowNode } from './claude.js';

interface AfbObject {
  id: string;
  instance: string;
  properties?: Array<[string, unknown]>;
  anchors?: Record<string, string>;
  objects?: string[];
  latches?: string[];
  source?: string;
  target?: string;
  handles?: string[];
}

const NODE_W = 210, NODE_H = 92, OP_W = 120, OP_H = 44;

const TEMPLATE: Record<string, string> = {
  action: 'action',
  asset: 'asset',
  tool: 'tool',
  malware: 'malware',
  operator_and: 'and_operator',
  operator_or: 'or_operator',
};

const ANCHOR_CONFIG: Array<{ angle: string; type: string }> = [
  { angle: '0', type: 'horizontal_anchor' }, { angle: '30', type: 'horizontal_anchor' },
  { angle: '60', type: 'vertical_anchor' }, { angle: '90', type: 'vertical_anchor' },
  { angle: '120', type: 'vertical_anchor' }, { angle: '150', type: 'horizontal_anchor' },
  { angle: '180', type: 'horizontal_anchor' }, { angle: '210', type: 'horizontal_anchor' },
  { angle: '240', type: 'vertical_anchor' }, { angle: '270', type: 'vertical_anchor' },
  { angle: '300', type: 'vertical_anchor' }, { angle: '330', type: 'horizontal_anchor' },
];

function mapConfidence(c: string | undefined): string {
  switch ((c ?? '').toLowerCase()) {
    case 'low': return 'doubtful';
    case 'medium': return 'probable';
    case 'high': return 'very-probable';
    default: return 'probable';
  }
}

/** Compute top-left positions for each flow node via dagre. */
function computePositions(flow: AttackFlow): Map<string, [number, number]> {
  const g = new dagre.graphlib.Graph();
  g.setDefaultEdgeLabel(() => ({}));
  g.setGraph({ rankdir: 'TB', ranksep: 110, nodesep: 60, marginx: 30, marginy: 30 });
  const typeById = new Map(flow.nodes.map((n) => [n.id, n.type]));
  for (const n of flow.nodes) {
    const op = n.type.startsWith('operator');
    g.setNode(n.id, { width: op ? OP_W : NODE_W, height: op ? OP_H : NODE_H });
  }
  for (const e of flow.edges) {
    const w = typeById.get(e.source) === 'action' && typeById.get(e.target) === 'action' ? 10 : 1;
    g.setEdge(e.source, e.target, { weight: w });
  }
  dagre.layout(g);
  const pos = new Map<string, [number, number]>();
  for (const n of flow.nodes) {
    const op = n.type.startsWith('operator');
    const node = g.node(n.id);
    pos.set(n.id, [
      Math.round(((node?.x ?? 0) - (op ? OP_W : NODE_W) / 2) / 5) * 5,
      Math.round(((node?.y ?? 0) - (op ? OP_H : NODE_H) / 2) / 5) * 5,
    ]);
  }
  return pos;
}

function nodeProperties(node: AttackFlowNode, chain: AnalysisResult['attack_chain']): Array<[string, unknown]> {
  const props: Array<[string, unknown]> = [['name', node.name || `Unnamed ${node.type}`]];
  if (node.type === 'action') {
    const tech = node.technique_id
      ? chain.find((t) => (t.sub_technique_id ?? t.technique_id) === node.technique_id || t.technique_id === node.technique_id)
      : undefined;
    props.push(['ttp', [['tactic', tech?.tactic_id ?? null], ['technique', node.technique_id ?? null]]]);
    props.push(['description', node.description || 'Attack technique']);
    props.push(['confidence', mapConfidence(tech?.confidence)]);
    props.push(['execution_start', null]);
    props.push(['execution_end', null]);
  } else if (node.type === 'malware') {
    props.push(['description', node.description || 'Malware']);
    props.push(['confidence', 'probable']);
    props.push(['is_family', 'false']);
    props.push(['aliases', []]);
    props.push(['kill_chain_phases', []]);
  } else if (node.type === 'tool') {
    props.push(['description', node.description || 'Tool']);
    props.push(['confidence', 'probable']);
    props.push(['aliases', []]);
    props.push(['kill_chain_phases', []]);
  } else if (node.type === 'asset') {
    props.push(['description', node.description || 'Asset']);
    props.push(['confidence', 'high']);
  }
  return props;
}

export function buildAfb(result: AnalysisResult): object {
  const flow = result.attack_flow!;
  const positions = computePositions(flow);

  const instanceByNode = new Map<string, string>();
  for (const n of flow.nodes) instanceByNode.set(n.id, uuidv4());

  const layout: Record<string, [number, number]> = {};
  const blockObjects: AfbObject[] = [];
  const blockInstances: string[] = [];
  // anchorId per node keyed by angle, for line wiring
  const nodeAnchors = new Map<string, Record<string, string>>();

  for (const n of flow.nodes) {
    const instance = instanceByNode.get(n.id)!;
    const anchors: Record<string, string> = {};
    const anchorObjs: AfbObject[] = [];
    for (const { angle, type } of ANCHOR_CONFIG) {
      const anchorId = uuidv4();
      anchors[angle] = anchorId;
      anchorObjs.push({ id: type, instance: anchorId, latches: [] });
    }
    nodeAnchors.set(n.id, anchors);

    blockObjects.push({
      id: TEMPLATE[n.type] ?? 'action',
      instance,
      anchors,
      properties: nodeProperties(n, result.attack_chain),
    });
    blockInstances.push(instance);
    blockObjects.push(...anchorObjs);
    layout[instance] = positions.get(n.id) ?? [0, 0];
  }

  // Index anchor objects by instance so we can attach latches
  const anchorByInstance = new Map<string, AfbObject>();
  for (const o of blockObjects) {
    if (o.id === 'vertical_anchor' || o.id === 'horizontal_anchor') anchorByInstance.set(o.instance, o);
  }

  // Lines (edges): bottom anchor (270) of source → top anchor (90) of target
  const lineAndLatch: AfbObject[] = [];
  const lineInstances: string[] = [];
  for (const e of flow.edges) {
    const srcAnchors = nodeAnchors.get(e.source);
    const tgtAnchors = nodeAnchors.get(e.target);
    if (!srcAnchors || !tgtAnchors) continue;
    const srcAnchor = anchorByInstance.get(srcAnchors['270']);
    const tgtAnchor = anchorByInstance.get(tgtAnchors['90']);
    if (!srcAnchor || !tgtAnchor) continue;

    const srcLatch = uuidv4(), tgtLatch = uuidv4(), handle = uuidv4(), line = uuidv4();
    (srcAnchor.latches ??= []).push(srcLatch);
    (tgtAnchor.latches ??= []).push(tgtLatch);
    lineAndLatch.push(
      { id: 'dynamic_line', instance: line, source: srcLatch, target: tgtLatch, handles: [handle] },
      { id: 'generic_latch', instance: srcLatch },
      { id: 'generic_latch', instance: tgtLatch },
      { id: 'generic_handle', instance: handle },
    );
    lineInstances.push(line);
  }

  const flowObject: AfbObject = {
    id: 'flow',
    instance: uuidv4(),
    objects: [...lineInstances, ...blockInstances],
    properties: [
      ['name', result.incident_summary.title || 'Attack Flow'],
      ['description', result.incident_summary.description || 'Exported from SNR'],
      ['author', [['name', 'SNR'], ['identity_class', 'system'], ['contact_information', '']]],
      ['scope', 'incident'],
      ['external_references', []],
      ['created', new Date().toISOString()],
    ],
  };

  // Camera centered on the average node position
  const xs = Object.values(layout).map((p) => p[0]);
  const ys = Object.values(layout).map((p) => p[1]);
  const avgX = xs.length ? xs.reduce((a, b) => a + b, 0) / xs.length : 0;
  const avgY = ys.length ? ys.reduce((a, b) => a + b, 0) / ys.length : 0;

  return {
    schema: 'attack_flow_v2',
    theme: 'dark_theme',
    objects: [flowObject, ...lineAndLatch, ...blockObjects],
    layout,
    camera: { x: -avgX, y: -avgY, k: 0.8 },
  };
}
