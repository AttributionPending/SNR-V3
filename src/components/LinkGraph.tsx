/**
 * LinkGraph — a Maltego/i2-style link-analysis graph over the CTI knowledge base,
 * connecting case, session, actor, ioc, and malware entities. Built on reactflow v11.
 *
 * Layouts (toolbar toggle):
 *  - Tree:   dagre left-to-right hierarchy (good for case → incidents → indicators).
 *  - Radial: concentric BFS rings from the most-connected node (or the case).
 *  - Force:  a Fruchterman–Reingold spring simulation (organic clusters).
 *
 * Readability tools:
 *  - Type filters: toggle whole entity classes off; layout recomputes on the subset.
 *  - Search: highlights matching nodes and dims the rest; Enter zooms to matches.
 *  - Focus: hovering a node spotlights it + its neighbors; single-click PINS that
 *    focus (click the canvas to unpin). Double-click a node navigates
 *    (session → open, actor → open, ioc → correlation pivot).
 */
import { useEffect, useMemo, useRef, useState } from 'react';
import dagre from 'dagre';
import ReactFlow, {
  Background, Controls, MiniMap, BackgroundVariant, Handle, Position, MarkerType,
  type Node, type Edge, type ReactFlowInstance,
} from 'reactflow';
import 'reactflow/dist/style.css';
import { Folder, FileText, Shield, Crosshair, Bug, Search, X, GitBranch, Orbit, Share2 } from 'lucide-react';
import { cn } from '@/lib/utils';
import type { GraphData, GraphNode } from '@/lib/api';

type EntityType = GraphNode['type'];
type LayoutMode = 'tree' | 'radial' | 'force';

const ENTITY: Record<EntityType, { color: string; icon: typeof Shield; label: string }> = {
  case:    { color: '#8b5cf6', icon: Folder,    label: 'Case' },
  session: { color: '#8b93a3', icon: FileText,  label: 'Incident' },
  actor:   { color: '#ef4444', icon: Shield,    label: 'Actor' },
  ioc:     { color: '#f59e0b', icon: Crosshair, label: 'Indicator' },
  malware: { color: '#ec4899', icon: Bug,       label: 'Malware' },
};
const TYPE_ORDER: EntityType[] = ['case', 'session', 'actor', 'ioc', 'malware'];

const NODE_W = 190;
const NODE_H = 46;

interface NodeData {
  entity: GraphNode;
  dim?: boolean;
  highlight?: boolean;
}

function EntityNode({ data }: { data: NodeData }) {
  const { entity, dim, highlight } = data;
  const spec = ENTITY[entity.type] ?? ENTITY.session;
  const Icon = spec.icon;
  return (
    <div
      className={cn('flex items-center gap-2 rounded-md border px-2.5 py-2 shadow-sm bg-navy-900/95 cursor-pointer transition-all duration-150 hover:brightness-125')}
      style={{
        width: NODE_W, height: NODE_H,
        borderColor: spec.color,
        opacity: dim ? 0.18 : 1,
        boxShadow: highlight ? `0 0 0 2px ${spec.color}, 0 0 12px ${spec.color}55` : undefined,
      }}
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

type Pt = { x: number; y: number };

function buildAdjacency(data: GraphData): Map<string, string[]> {
  const adj = new Map<string, string[]>();
  for (const n of data.nodes) adj.set(n.id, []);
  for (const e of data.edges) {
    adj.get(e.source)?.push(e.target);
    adj.get(e.target)?.push(e.source);
  }
  return adj;
}

/** Dagre left-to-right hierarchy — returns CENTER positions per node id. */
function treePositions(data: GraphData): Map<string, Pt> {
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
function radialPositions(data: GraphData): Map<string, Pt> {
  const pos = new Map<string, Pt>();
  if (!data.nodes.length) return pos;
  const adj = buildAdjacency(data);
  const root = data.nodes.find((n) => n.type === 'case')?.id
    ?? [...data.nodes].sort((a, b) => (adj.get(b.id)?.length ?? 0) - (adj.get(a.id)?.length ?? 0))[0].id;

  const depth = new Map<string, number>([[root, 0]]);
  const queue = [root];
  while (queue.length) {
    const cur = queue.shift()!;
    const d = depth.get(cur)!;
    for (const nb of adj.get(cur) ?? []) if (!depth.has(nb)) { depth.set(nb, d + 1); queue.push(nb); }
  }
  // Disconnected nodes get pushed to an outer ring.
  let maxD = 0;
  for (const d of depth.values()) maxD = Math.max(maxD, d);
  for (const n of data.nodes) if (!depth.has(n.id)) depth.set(n.id, maxD + 1);

  const byDepth = new Map<number, string[]>();
  for (const n of data.nodes) {
    const d = depth.get(n.id)!;
    (byDepth.get(d) ?? byDepth.set(d, []).get(d)!).push(n.id);
  }
  const R = 260;
  for (const [d, ids] of byDepth) {
    if (d === 0 && ids.length === 1) { pos.set(ids[0], { x: 0, y: 0 }); continue; }
    const radius = Math.max(d, 0.5) * R;
    ids.forEach((id, i) => {
      const a = (2 * Math.PI * i) / ids.length - Math.PI / 2;
      pos.set(id, { x: Math.cos(a) * radius, y: Math.sin(a) * radius });
    });
  }
  return pos;
}

/** Fruchterman–Reingold force-directed layout, seeded from the radial layout. */
function forcePositions(data: GraphData): Map<string, Pt> {
  const seed = radialPositions(data);
  const ids = data.nodes.map((n) => n.id);
  if (ids.length <= 1) return seed;
  const P = new Map<string, Pt>();
  for (const id of ids) { const s = seed.get(id) ?? { x: 0, y: 0 }; P.set(id, { x: s.x, y: s.y }); }
  const edges = data.edges.filter((e) => P.has(e.source) && P.has(e.target));

  const k = 320;                       // ideal edge length
  const iterations = ids.length > 150 ? 140 : 260;
  let temp = k * 0.9;
  for (let it = 0; it < iterations; it++) {
    const disp = new Map<string, Pt>();
    for (const id of ids) disp.set(id, { x: 0, y: 0 });
    // Repulsion between every pair.
    for (let i = 0; i < ids.length; i++) {
      for (let j = i + 1; j < ids.length; j++) {
        const a = P.get(ids[i])!, b = P.get(ids[j])!;
        const dx = a.x - b.x, dy = a.y - b.y;
        const dist = Math.hypot(dx, dy) || 0.01;
        const f = (k * k) / dist;
        const ux = dx / dist, uy = dy / dist;
        const di = disp.get(ids[i])!; di.x += ux * f; di.y += uy * f;
        const dj = disp.get(ids[j])!; dj.x -= ux * f; dj.y -= uy * f;
      }
    }
    // Attraction along edges.
    for (const e of edges) {
      const a = P.get(e.source)!, b = P.get(e.target)!;
      const dx = a.x - b.x, dy = a.y - b.y;
      const dist = Math.hypot(dx, dy) || 0.01;
      const f = (dist * dist) / k;
      const ux = dx / dist, uy = dy / dist;
      const da = disp.get(e.source)!; da.x -= ux * f; da.y -= uy * f;
      const db = disp.get(e.target)!; db.x += ux * f; db.y += uy * f;
    }
    // Apply, capped by cooling temperature.
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

function computePositions(data: GraphData, mode: LayoutMode): Map<string, Pt> {
  if (mode === 'radial') return radialPositions(data);
  if (mode === 'force') return forcePositions(data);
  return treePositions(data);
}

const LAYOUTS: { mode: LayoutMode; label: string; icon: typeof GitBranch }[] = [
  { mode: 'tree', label: 'Tree', icon: GitBranch },
  { mode: 'radial', label: 'Radial', icon: Orbit },
  { mode: 'force', label: 'Force', icon: Share2 },
];

interface Props {
  data: GraphData;
  onSelectSession?: (id: string) => void;
  onSelectActor?: (id: string) => void;
  onPivotIoc?: (type: string, value: string) => void;
}

export default function LinkGraph({ data, onSelectSession, onSelectActor, onPivotIoc }: Props) {
  const [layoutMode, setLayoutMode] = useState<LayoutMode>('tree');
  const [hidden, setHidden] = useState<Set<EntityType>>(new Set());
  const [query, setQuery] = useState('');
  const [hoveredId, setHoveredId] = useState<string | null>(null);
  const [pinnedId, setPinnedId] = useState<string | null>(null);
  const rf = useRef<ReactFlowInstance | null>(null);
  const clickTimer = useRef<ReturnType<typeof setTimeout> | null>(null);

  const navigate = (n: GraphNode) => {
    if (n.type === 'session') onSelectSession?.(n.id.slice('session:'.length));
    else if (n.type === 'actor') onSelectActor?.(n.id.slice('actor:'.length));
    else if (n.type === 'ioc') onPivotIoc?.(String(n.meta?.iocType ?? ''), n.label);
  };

  const typeCounts = useMemo(() => {
    const m = {} as Record<EntityType, number>;
    for (const n of data.nodes) m[n.type] = (m[n.type] ?? 0) + 1;
    return m;
  }, [data]);
  const presentTypes = TYPE_ORDER.filter((t) => typeCounts[t]);

  const filtered = useMemo<GraphData>(() => {
    const nodes = data.nodes.filter((n) => !hidden.has(n.type));
    const keep = new Set(nodes.map((n) => n.id));
    const edges = data.edges.filter((e) => keep.has(e.source) && keep.has(e.target));
    return { nodes, edges };
  }, [data, hidden]);

  const base = useMemo(() => {
    const pos = computePositions(filtered, layoutMode);
    const nodes: Node[] = filtered.nodes.map((n) => {
      const p = pos.get(n.id) ?? { x: 0, y: 0 };
      return { id: n.id, type: 'entity', position: { x: p.x - NODE_W / 2, y: p.y - NODE_H / 2 }, data: { entity: n } } as Node;
    });
    const edges: Edge[] = filtered.edges.map((e, i) => ({
      id: `e-${i}`, source: e.source, target: e.target, label: e.label, type: 'smoothstep',
      markerEnd: { type: MarkerType.ArrowClosed, width: 14, height: 14 },
    } as Edge));
    return { nodes, edges };
  }, [filtered, layoutMode]);

  const adjacency = useMemo(() => {
    const m = new Map<string, Set<string>>();
    for (const e of filtered.edges) {
      (m.get(e.source) ?? m.set(e.source, new Set()).get(e.source)!).add(e.target);
      (m.get(e.target) ?? m.set(e.target, new Set()).get(e.target)!).add(e.source);
    }
    return m;
  }, [filtered]);

  const q = query.trim().toLowerCase();
  const matchIds = useMemo(() => {
    if (!q) return null;
    const ids = new Set<string>();
    for (const n of filtered.nodes) {
      if (n.label.toLowerCase().includes(q) || ENTITY[n.type].label.toLowerCase().includes(q)) ids.add(n.id);
    }
    return ids;
  }, [q, filtered]);

  // Spotlight: transient hover wins, else the pinned node, else search matches.
  const focusId = hoveredId ?? pinnedId;
  const activeSet = useMemo(() => {
    if (focusId && adjacency.has(focusId)) {
      const s = new Set<string>([focusId]);
      for (const nb of adjacency.get(focusId) ?? []) s.add(nb);
      return s;
    }
    if (matchIds) return matchIds;
    return null;
  }, [focusId, adjacency, matchIds]);

  const nodes = useMemo(() => base.nodes.map((n) => {
    const active = !activeSet || activeSet.has(n.id);
    const isMatch = !!matchIds && matchIds.has(n.id);
    return { ...n, data: { ...(n.data as NodeData), dim: !active, highlight: n.id === focusId || n.id === pinnedId || isMatch } };
  }), [base.nodes, activeSet, matchIds, focusId, pinnedId]);

  const edges = useMemo(() => base.edges.map((e) => {
    const active = !activeSet || (activeSet.has(e.source) && activeSet.has(e.target));
    const touchesFocus = focusId != null && (e.source === focusId || e.target === focusId);
    const stroke = touchesFocus ? 'rgba(59,130,246,0.9)' : active ? 'rgba(148,163,184,0.4)' : 'rgba(148,163,184,0.08)';
    return {
      ...e,
      style: { stroke, strokeWidth: touchesFocus ? 2 : 1.25 },
      labelStyle: { fontSize: 9, fill: `rgba(226,232,240,${active ? 0.6 : 0.12})` },
      labelBgStyle: { fill: 'hsl(var(--card))', fillOpacity: active ? 1 : 0.2 },
      labelBgPadding: [2, 3] as [number, number],
      markerEnd: { type: MarkerType.ArrowClosed, width: 14, height: 14, color: touchesFocus ? 'rgba(59,130,246,0.9)' : `rgba(148,163,184,${active ? 0.45 : 0.1})` },
    } as Edge;
  }), [base.edges, activeSet, focusId]);

  // Re-fit the view when the layout or the visible set changes.
  useEffect(() => {
    const id = requestAnimationFrame(() => rf.current?.fitView({ padding: 0.2, duration: 400 }));
    return () => cancelAnimationFrame(id);
  }, [layoutMode, filtered]);

  const toggleType = (t: EntityType) => setHidden((prev) => {
    const next = new Set(prev);
    if (next.has(t)) next.delete(t); else next.add(t);
    return next;
  });

  const zoomToMatches = () => {
    if (!matchIds || matchIds.size === 0 || !rf.current) return;
    const targets = base.nodes.filter((n) => matchIds.has(n.id)).map((n) => ({ id: n.id }));
    if (targets.length) rf.current.fitView({ nodes: targets, padding: 0.3, duration: 400, maxZoom: 1.4 });
  };

  // Single click pins focus (toggle); double click navigates. A short timer
  // disambiguates so a double-click doesn't also fire the pin.
  const handleNodeClick = (_: unknown, node: Node) => {
    if (clickTimer.current) return;
    clickTimer.current = setTimeout(() => {
      clickTimer.current = null;
      setPinnedId((prev) => (prev === node.id ? null : node.id));
    }, 220);
  };
  const handleNodeDoubleClick = (_: unknown, node: Node) => {
    if (clickTimer.current) { clearTimeout(clickTimer.current); clickTimer.current = null; }
    navigate((node.data as NodeData).entity);
  };

  if (data.nodes.length === 0) {
    return <div className="w-full h-full flex items-center justify-center text-xs text-muted-foreground">No linked entities yet — add sessions to build the graph.</div>;
  }

  return (
    <div className="w-full h-full relative">
      {/* Toolbar: search + type filters + layout toggle */}
      <div className="absolute top-2 left-2 z-10 flex flex-col gap-1.5 max-w-[calc(100%-1rem)]">
        <div className="flex items-center gap-1.5">
          <div className="flex items-center gap-1.5 bg-navy-900/95 border border-border rounded-md px-2 py-1 shadow-sm">
            <Search className="w-3 h-3 text-muted-foreground/60 flex-shrink-0" />
            <input
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              onKeyDown={(e) => { if (e.key === 'Enter') zoomToMatches(); if (e.key === 'Escape') setQuery(''); }}
              placeholder="Search nodes…"
              className="bg-transparent text-[11px] text-foreground placeholder:text-muted-foreground/50 focus:outline-none w-36"
            />
            {q && (
              <>
                <span className="text-[9px] text-muted-foreground/70 flex-shrink-0">{matchIds?.size ?? 0}</span>
                <button onClick={() => setQuery('')} className="text-muted-foreground/60 hover:text-foreground flex-shrink-0" aria-label="Clear search"><X className="w-3 h-3" /></button>
              </>
            )}
          </div>
          <div className="flex items-center gap-0.5 bg-navy-900/95 border border-border rounded-md p-0.5 shadow-sm">
            {LAYOUTS.map(({ mode, label, icon: Icon }) => (
              <button
                key={mode}
                onClick={() => setLayoutMode(mode)}
                className={cn(
                  'inline-flex items-center gap-1 rounded px-1.5 py-0.5 text-[10px] transition-colors',
                  layoutMode === mode ? 'bg-primary text-primary-foreground font-medium' : 'text-muted-foreground hover:text-foreground',
                )}
                title={`${label} layout`}
              >
                <Icon className="w-3 h-3" /> {label}
              </button>
            ))}
          </div>
        </div>
        <div className="flex flex-wrap items-center gap-1">
          {presentTypes.map((t) => {
            const off = hidden.has(t);
            const spec = ENTITY[t];
            return (
              <button
                key={t}
                onClick={() => toggleType(t)}
                className={cn(
                  'inline-flex items-center gap-1 rounded-full border pl-1.5 pr-2 py-0.5 text-[10px] transition-colors',
                  off ? 'border-border bg-navy-900/70 text-muted-foreground/50' : 'border-border bg-navy-900/95 text-foreground',
                )}
                title={off ? `Show ${spec.label}` : `Hide ${spec.label}`}
              >
                <span className="w-2 h-2 rounded-full flex-shrink-0" style={{ background: spec.color, opacity: off ? 0.3 : 1 }} />
                <span className={cn(off && 'line-through')}>{spec.label}</span>
                <span className="text-muted-foreground/60">{typeCounts[t]}</span>
              </button>
            );
          })}
          {pinnedId && (
            <span className="text-[9px] text-muted-foreground/60 ml-1">Pinned · double-click to open · click canvas to unpin</span>
          )}
        </div>
      </div>

      <ReactFlow
        nodes={nodes}
        edges={edges}
        nodeTypes={nodeTypes}
        onInit={(inst) => { rf.current = inst; }}
        onNodeMouseEnter={(_, n) => setHoveredId(n.id)}
        onNodeMouseLeave={() => setHoveredId(null)}
        onNodeClick={handleNodeClick}
        onNodeDoubleClick={handleNodeDoubleClick}
        onPaneClick={() => setPinnedId(null)}
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
