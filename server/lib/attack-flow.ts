/**
 * Attack Flow validation & repair.
 *
 * LLMs are good at naming techniques but inconsistent at producing a clean
 * causal graph. This sanitizes the model's `attack_flow` before it is stored:
 * drops dangling/duplicate edges, breaks cycles (Attack Flow must be a DAG),
 * removes action nodes that don't map to a real technique, prunes orphans,
 * and falls back to `undefined` when too little survives to be useful.
 *
 * Never throws — a bad flow degrades to no flow, and the rest of the analysis
 * pipeline is unaffected.
 */
import type { AttackFlow, AttackFlowNode, AttackFlowEdge } from './claude.js';
import logger from './logger.js';

const MAX_NODES = 30;
const ACTION_TYPES = new Set(['action']);

interface ChainTechnique {
  technique_id: string;
  sub_technique_id: string | null;
}

export function validateAttackFlow(
  flow: AttackFlow | undefined | null,
  attackChain: ChainTechnique[],
): AttackFlow | undefined {
  if (!flow || !Array.isArray(flow.nodes) || !Array.isArray(flow.edges)) return undefined;

  // Known technique IDs from the chain (both base and sub-technique forms)
  const knownTechniques = new Set<string>();
  for (const t of attackChain) {
    if (t.technique_id) knownTechniques.add(t.technique_id.toUpperCase());
    if (t.sub_technique_id) knownTechniques.add(t.sub_technique_id.toUpperCase());
  }

  // 1. Dedupe nodes by id; drop malformed nodes
  const seenIds = new Set<string>();
  let nodes: AttackFlowNode[] = [];
  for (const n of flow.nodes) {
    if (!n || typeof n.id !== 'string' || !n.id || typeof n.type !== 'string' || typeof n.name !== 'string') continue;
    if (seenIds.has(n.id)) continue;
    seenIds.add(n.id);
    nodes.push(n);
  }

  // 2. Drop action nodes whose technique_id doesn't map to the chain
  //    (fuzzy: matches a technique_id OR sub_technique_id). Keeps the flow
  //    anchored to techniques the analysis actually identified.
  let droppedActions = 0;
  nodes = nodes.filter((n) => {
    if (!ACTION_TYPES.has(n.type)) return true;
    const tid = (n.technique_id ?? '').toUpperCase();
    if (tid && knownTechniques.has(tid)) return true;
    // Also accept a sub-technique action when its base technique is known
    if (tid.includes('.') && knownTechniques.has(tid.split('.')[0])) return true;
    droppedActions++;
    return false;
  });

  // 3. Cap node count (prompt asks for ≤30; trim defensively)
  if (nodes.length > MAX_NODES) nodes = nodes.slice(0, MAX_NODES);

  const nodeIds = new Set(nodes.map((n) => n.id));

  // 4. Filter edges: valid endpoints, no self-loops, deduped
  const seenEdges = new Set<string>();
  let edges: AttackFlowEdge[] = [];
  for (const e of flow.edges) {
    if (!e || typeof e.source !== 'string' || typeof e.target !== 'string') continue;
    if (e.source === e.target) continue;
    if (!nodeIds.has(e.source) || !nodeIds.has(e.target)) continue;
    const key = `${e.source}->${e.target}`;
    if (seenEdges.has(key)) continue;
    seenEdges.add(key);
    edges.push({ source: e.source, target: e.target, label: typeof e.label === 'string' ? e.label : 'leads to' });
  }

  // 5. Break cycles — Attack Flow must be a DAG. DFS, drop back-edges.
  edges = removeBackEdges(nodes, edges);

  // 6. Drop zero-degree nodes (orphans that add nothing to a flow)
  const degree = new Map<string, number>();
  for (const e of edges) {
    degree.set(e.source, (degree.get(e.source) ?? 0) + 1);
    degree.set(e.target, (degree.get(e.target) ?? 0) + 1);
  }
  nodes = nodes.filter((n) => (degree.get(n.id) ?? 0) > 0);

  // 7. Threshold — need a real graph (≥2 actions, ≥1 edge) or bail out
  const actionCount = nodes.filter((n) => ACTION_TYPES.has(n.type)).length;
  if (actionCount < 2 || edges.length === 0) {
    if (flow.nodes.length > 0) {
      logger.info({ actionCount, edges: edges.length }, 'Attack flow discarded — insufficient causal structure');
    }
    return undefined;
  }

  if (droppedActions > 0) {
    logger.info({ droppedActions }, 'Attack flow: dropped action nodes with unmatched technique IDs');
  }

  return { nodes, edges };
}

/**
 * Remove back-edges via DFS coloring so the remaining graph is acyclic.
 * white = unvisited, gray = on current path, black = done.
 */
function removeBackEdges(nodes: AttackFlowNode[], edges: AttackFlowEdge[]): AttackFlowEdge[] {
  const adj = new Map<string, AttackFlowEdge[]>();
  for (const n of nodes) adj.set(n.id, []);
  for (const e of edges) adj.get(e.source)?.push(e);

  const color = new Map<string, 'white' | 'gray' | 'black'>();
  for (const n of nodes) color.set(n.id, 'white');
  const backEdges = new Set<AttackFlowEdge>();

  // Iterative DFS to avoid stack overflow on large graphs
  const visit = (root: string) => {
    const stack: Array<{ node: string; idx: number }> = [{ node: root, idx: 0 }];
    color.set(root, 'gray');
    while (stack.length > 0) {
      const frame = stack[stack.length - 1];
      const outEdges = adj.get(frame.node) ?? [];
      if (frame.idx >= outEdges.length) {
        color.set(frame.node, 'black');
        stack.pop();
        continue;
      }
      const edge = outEdges[frame.idx++];
      const targetColor = color.get(edge.target);
      if (targetColor === 'gray') {
        backEdges.add(edge); // edge into an ancestor → cycle
      } else if (targetColor === 'white') {
        color.set(edge.target, 'gray');
        stack.push({ node: edge.target, idx: 0 });
      }
    }
  };

  for (const n of nodes) {
    if (color.get(n.id) === 'white') visit(n.id);
  }

  if (backEdges.size > 0) {
    logger.info({ backEdges: backEdges.size }, 'Attack flow: removed back-edges to enforce DAG');
  }
  return edges.filter((e) => !backEdges.has(e));
}
