/**
 * AttackFlowView — renders a MITRE Attack Flow causal graph (DAG) with ReactFlow.
 * Complements the linear AttackChainView: shows how steps connect (actions,
 * assets, tools, malware, AND/OR operators) rather than a flat kill-chain order.
 *
 * Layout is computed once per result with dagre (top-to-bottom, action backbone
 * weighted to stay central). Clicking an action node opens the shared
 * TechniqueDetail modal via onExpand.
 */
import { useMemo } from 'react';
import dagre from 'dagre';
import ReactFlow, {
  Background,
  Controls,
  BackgroundVariant,
  Handle,
  Position,
  MarkerType,
  type Node,
  type Edge,
} from 'reactflow';
import 'reactflow/dist/style.css';
import { Shield, Server, Wrench, Bug } from 'lucide-react';
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from './ui/tooltip';
import { cn } from '@/lib/utils';
import { CONFIDENCE_COLORS } from '@/types';
import type { AttackFlow, AttackFlowNode, AttackTechnique } from '@/types';

// Node palette (matches FlowViz convention)
const TYPE_COLOR: Record<string, string> = {
  action: '#3b82f6',
  asset: '#f59e0b',
  tool: '#10b981',
  malware: '#ef4444',
  operator_and: '#64748b',
  operator_or: '#64748b',
};

const TYPE_ICON: Record<string, typeof Shield> = {
  action: Shield,
  asset: Server,
  tool: Wrench,
  malware: Bug,
};

// Layout dimensions
const NODE_W = 210;
const NODE_H = 92;
const OP_W = 120;
const OP_H = 44;

interface FlowNodeData {
  node: AttackFlowNode;
  technique?: AttackTechnique;
  onExpand: (t: AttackTechnique) => void;
}

function FlowCard({ data }: { data: FlowNodeData }) {
  const { node, technique, onExpand } = data;

  // Operator nodes render as slim AND/OR bars
  if (node.type === 'operator_and' || node.type === 'operator_or') {
    const label = node.type === 'operator_and' ? 'AND' : 'OR';
    return (
      <div
        className="flex items-center justify-center rounded-md border border-border bg-secondary text-muted-foreground font-bold text-[11px] tracking-widest"
        style={{ width: OP_W, height: OP_H }}
      >
        <Handle type="target" position={Position.Top} className="!bg-slate-500" />
        {label}
        <Handle type="source" position={Position.Bottom} className="!bg-slate-500" />
      </div>
    );
  }

  const color = TYPE_COLOR[node.type] ?? '#64748b';
  const Icon = TYPE_ICON[node.type] ?? Shield;
  const isAction = node.type === 'action';
  const confidenceColor = technique ? (CONFIDENCE_COLORS[technique.confidence] ?? color) : color;

  const card = (
    <div
      onClick={isAction && technique ? () => onExpand(technique) : undefined}
      className={cn(
        'rounded-lg border bg-navy-800 transition-all text-left',
        isAction && technique
          ? 'border-border hover:border-cyan-500/50 cursor-pointer'
          : 'border-border',
      )}
      style={{ width: NODE_W, minHeight: NODE_H, borderTopColor: color, borderTopWidth: 3 }}
    >
      <Handle type="target" position={Position.Top} className="!bg-slate-600" />
      <div className="p-2.5">
        <div className="flex items-center gap-1.5 mb-1">
          <Icon className="w-3 h-3 flex-shrink-0" style={{ color }} />
          <span className="text-[9px] uppercase tracking-wide font-semibold" style={{ color }}>
            {node.type}
          </span>
          {isAction && node.technique_id && (
            <span className="text-[9px] font-mono text-cyan-400 ml-auto">{node.technique_id}</span>
          )}
        </div>
        <div className="text-xs font-medium text-foreground leading-tight line-clamp-2">{node.name}</div>
        {node.description && (
          <p className="mt-1 text-[9px] leading-snug text-muted-foreground line-clamp-2">{node.description}</p>
        )}
        {isAction && technique && (
          <span
            className="inline-block mt-1.5 text-[8px] uppercase tracking-wide px-1.5 py-0.5 rounded"
            style={{ backgroundColor: confidenceColor + '22', color: confidenceColor }}
          >
            {technique.confidence}
          </span>
        )}
      </div>
      <Handle type="source" position={Position.Bottom} className="!bg-slate-600" />
    </div>
  );

  if (!node.description) return card;
  return (
    <TooltipProvider>
      <Tooltip>
        <TooltipTrigger asChild>{card}</TooltipTrigger>
        <TooltipContent side="bottom" className="max-w-xs text-xs">
          <p className="font-semibold mb-1">{node.name}</p>
          <p className="text-muted-foreground">{node.description}</p>
        </TooltipContent>
      </Tooltip>
    </TooltipProvider>
  );
}

const nodeTypes = { flowCard: FlowCard };

/** Match a flow action node to its chain technique (by technique_id or sub_technique_id). */
function findTechnique(node: AttackFlowNode, chain: AttackTechnique[]): AttackTechnique | undefined {
  if (!node.technique_id) return undefined;
  const tid = node.technique_id.toUpperCase();
  return chain.find(
    (t) => t.technique_id?.toUpperCase() === tid || t.sub_technique_id?.toUpperCase() === tid,
  ) ?? chain.find((t) => t.technique_id?.toUpperCase() === tid.split('.')[0]);
}

function layout(flow: AttackFlow): { nodes: Node[]; edges: Edge[]; chainLookup: Map<string, AttackFlowNode> } {
  const g = new dagre.graphlib.Graph();
  g.setDefaultEdgeLabel(() => ({}));
  g.setGraph({ rankdir: 'TB', ranksep: 110, nodesep: 60, edgesep: 30, marginx: 30, marginy: 30 });

  const typeById = new Map(flow.nodes.map((n) => [n.id, n.type]));

  for (const n of flow.nodes) {
    const isOp = n.type === 'operator_and' || n.type === 'operator_or';
    g.setNode(n.id, { width: isOp ? OP_W : NODE_W, height: isOp ? OP_H : NODE_H });
  }
  for (const e of flow.edges) {
    // Weight the action→action backbone so it stays vertically central
    const weight = typeById.get(e.source) === 'action' && typeById.get(e.target) === 'action' ? 10 : 1;
    g.setEdge(e.source, e.target, { weight });
  }
  dagre.layout(g);

  const chainLookup = new Map(flow.nodes.map((n) => [n.id, n]));

  return {
    chainLookup,
    nodes: flow.nodes.map((n) => {
      const pos = g.node(n.id);
      const isOp = n.type === 'operator_and' || n.type === 'operator_or';
      const w = isOp ? OP_W : NODE_W;
      const h = isOp ? OP_H : NODE_H;
      return {
        id: n.id,
        type: 'flowCard',
        position: { x: (pos?.x ?? 0) - w / 2, y: (pos?.y ?? 0) - h / 2 },
        data: { node: n },
      } as Node;
    }),
    edges: flow.edges.map((e, i) => {
      const backbone = typeById.get(e.source) === 'action' && typeById.get(e.target) === 'action';
      return {
        id: `e-${i}`,
        source: e.source,
        target: e.target,
        label: e.label,
        type: 'smoothstep',
        animated: backbone,
        style: { stroke: backbone ? 'rgba(63,131,230,0.55)' : 'rgba(148,163,184,0.4)', strokeWidth: 1.5 },
        labelStyle: { fontSize: 10, fill: 'rgba(226,232,240,0.75)' },
        labelBgStyle: { fill: 'hsl(var(--card))' },
        labelBgPadding: [3, 4] as [number, number],
        markerEnd: { type: MarkerType.ArrowClosed, width: 16, height: 16, color: backbone ? 'rgba(63,131,230,0.6)' : 'rgba(148,163,184,0.5)' },
      } as Edge;
    }),
  };
}

interface Props {
  flow: AttackFlow;
  attackChain: AttackTechnique[];
  onExpand: (t: AttackTechnique) => void;
}

export default function AttackFlowView({ flow, attackChain, onExpand }: Props) {
  const { nodes, edges } = useMemo(() => layout(flow), [flow]);

  // Inject per-node technique lookup + onExpand into node data
  const nodesWithData = useMemo(
    () =>
      nodes.map((n) => {
        const fn = (n.data as { node: AttackFlowNode }).node;
        return { ...n, data: { node: fn, technique: findTechnique(fn, attackChain), onExpand } };
      }),
    [nodes, attackChain, onExpand],
  );

  return (
    <div className="w-full h-full">
      <ReactFlow
        nodes={nodesWithData}
        edges={edges}
        nodeTypes={nodeTypes}
        fitView
        fitViewOptions={{ padding: 0.15 }}
        minZoom={0.2}
        maxZoom={1.5}
        proOptions={{ hideAttribution: true }}
        nodesDraggable
        nodesConnectable={false}
      >
        <Background variant={BackgroundVariant.Dots} gap={16} size={1} color="hsl(var(--n-600))" />
        <Controls showInteractive={false} />
      </ReactFlow>
    </div>
  );
}
