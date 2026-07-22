/**
 * LinkGraph — a Maltego/i2-style link-analysis graph over the CTI knowledge base,
 * connecting case, session, actor, ioc, and malware entities. Reuses the app's
 * reactflow v11 + dagre approach (see AttackFlowView) with a generic horizontal
 * (LR) auto-layout. Clicking a node navigates: session → open session, actor →
 * open actor, ioc → open the correlation pivot.
 */
import { useMemo } from 'react';
import dagre from 'dagre';
import ReactFlow, {
  Background, Controls, MiniMap, BackgroundVariant, Handle, Position, MarkerType,
  type Node, type Edge,
} from 'reactflow';
import 'reactflow/dist/style.css';
import { Folder, FileText, Shield, Crosshair, Bug } from 'lucide-react';
import { cn } from '@/lib/utils';
import type { GraphData, GraphNode } from '@/lib/api';

const ENTITY: Record<GraphNode['type'], { color: string; icon: typeof Shield; label: string }> = {
  case:    { color: '#8b5cf6', icon: Folder,    label: 'Case' },
  session: { color: '#8b93a3', icon: FileText,  label: 'Incident' },
  actor:   { color: '#ef4444', icon: Shield,    label: 'Actor' },
  ioc:     { color: '#f59e0b', icon: Crosshair, label: 'Indicator' },
  malware: { color: '#ec4899', icon: Bug,       label: 'Malware' },
};

const NODE_W = 190;
const NODE_H = 46;

interface NodeData {
  entity: GraphNode;
  onClick?: (n: GraphNode) => void;
}

function EntityNode({ data }: { data: NodeData }) {
  const { entity, onClick } = data;
  const spec = ENTITY[entity.type] ?? ENTITY.session;
  const Icon = spec.icon;
  const clickable = entity.type === 'session' || entity.type === 'actor' || entity.type === 'ioc';
  return (
    <div
      onClick={clickable && onClick ? () => onClick(entity) : undefined}
      className={cn(
        'flex items-center gap-2 rounded-md border px-2.5 py-2 shadow-sm bg-navy-900/95',
        clickable && 'cursor-pointer hover:brightness-125 transition-all',
      )}
      style={{ width: NODE_W, height: NODE_H, borderColor: spec.color }}
      title={`${spec.label}: ${entity.label}`}
    >
      <Handle type="target" position={Position.Left} style={{ background: spec.color, width: 6, height: 6 }} />
      <Icon className="w-3.5 h-3.5 flex-shrink-0" style={{ color: spec.color }} />
      <div className="min-w-0 flex-1">
        <div className="text-[9px] uppercase tracking-wide text-muted-foreground/60 leading-none">{spec.label}</div>
        <div className="text-[11px] text-foreground truncate leading-tight mt-0.5" style={{ maxWidth: NODE_W - 44 }}>{entity.label}</div>
      </div>
      <Handle type="source" position={Position.Right} style={{ background: spec.color, width: 6, height: 6 }} />
    </div>
  );
}

const nodeTypes = { entity: EntityNode };

function layout(data: GraphData): { nodes: Node[]; edges: Edge[] } {
  const g = new dagre.graphlib.Graph();
  g.setDefaultEdgeLabel(() => ({}));
  g.setGraph({ rankdir: 'LR', ranksep: 120, nodesep: 24, edgesep: 20, marginx: 24, marginy: 24 });

  for (const n of data.nodes) g.setNode(n.id, { width: NODE_W, height: NODE_H });
  for (const e of data.edges) if (g.hasNode(e.source) && g.hasNode(e.target)) g.setEdge(e.source, e.target, {});
  dagre.layout(g);

  const nodes: Node[] = data.nodes.map((n) => {
    const pos = g.node(n.id);
    return {
      id: n.id,
      type: 'entity',
      position: { x: (pos?.x ?? 0) - NODE_W / 2, y: (pos?.y ?? 0) - NODE_H / 2 },
      data: { entity: n },
    } as Node;
  });

  const edges: Edge[] = data.edges.map((e, i) => ({
    id: `e-${i}`,
    source: e.source,
    target: e.target,
    label: e.label,
    type: 'smoothstep',
    style: { stroke: 'rgba(148,163,184,0.35)', strokeWidth: 1.25 },
    labelStyle: { fontSize: 9, fill: 'rgba(226,232,240,0.6)' },
    labelBgStyle: { fill: 'hsl(var(--card))' },
    labelBgPadding: [2, 3] as [number, number],
    markerEnd: { type: MarkerType.ArrowClosed, width: 14, height: 14, color: 'rgba(148,163,184,0.45)' },
  } as Edge));

  return { nodes, edges };
}

interface Props {
  data: GraphData;
  onSelectSession?: (id: string) => void;
  onSelectActor?: (id: string) => void;
  onPivotIoc?: (type: string, value: string) => void;
}

export default function LinkGraph({ data, onSelectSession, onSelectActor, onPivotIoc }: Props) {
  const onClick = (n: GraphNode) => {
    if (n.type === 'session') onSelectSession?.(n.id.slice('session:'.length));
    else if (n.type === 'actor') onSelectActor?.(n.id.slice('actor:'.length));
    else if (n.type === 'ioc') onPivotIoc?.(String(n.meta?.iocType ?? ''), n.label);
  };

  const { nodes, edges } = useMemo(() => layout(data), [data]);
  const nodesWithHandlers = useMemo(
    () => nodes.map((n) => ({ ...n, data: { ...(n.data as NodeData), onClick } })),
    [nodes], // eslint-disable-line react-hooks/exhaustive-deps
  );

  if (data.nodes.length === 0) {
    return <div className="w-full h-full flex items-center justify-center text-xs text-muted-foreground">No linked entities yet — add sessions to build the graph.</div>;
  }

  return (
    <div className="w-full h-full">
      <ReactFlow
        nodes={nodesWithHandlers}
        edges={edges}
        nodeTypes={nodeTypes}
        fitView
        fitViewOptions={{ padding: 0.2 }}
        minZoom={0.2}
        maxZoom={1.6}
        proOptions={{ hideAttribution: true }}
        nodesDraggable
        nodesConnectable={false}
      >
        <Background variant={BackgroundVariant.Dots} gap={16} size={1} color="hsl(var(--n-600))" />
        <Controls showInteractive={false} />
        <MiniMap
          nodeColor={(n) => ENTITY[(n.data as NodeData)?.entity?.type]?.color ?? '#64748b'}
          maskColor="hsl(var(--background) / 0.6)"
          style={{ background: 'hsl(var(--card))' }}
        />
      </ReactFlow>
    </div>
  );
}
