import React, { useCallback, useMemo, useRef, useEffect, useState } from 'react';
import { toPng } from 'html-to-image';
import ReactFlow, {
  Background,
  Controls,
  MiniMap,
  useNodesState,
  useEdgesState,
  BackgroundVariant,
  type Node,
  type Edge,
  type ReactFlowInstance,
} from 'reactflow';
import 'reactflow/dist/style.css';
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from './ui/tooltip';
import { cn } from '@/lib/utils';
import type { AttackTechnique } from '@/types';
import { CONFIDENCE_COLORS } from '@/types';

interface AttackNodeData {
  technique: AttackTechnique;
  onExpand: (t: AttackTechnique) => void;
  showEvidence?: boolean;
}

function AttackNode({ data }: { data: AttackNodeData }) {
  const { technique, onExpand, showEvidence } = data;
  const confidenceColor = CONFIDENCE_COLORS[technique.confidence] ?? '#888';

  const evidenceSnippet = technique.evidence
    ? technique.evidence.length > 160
      ? technique.evidence.slice(0, 160) + '…'
      : technique.evidence
    : '';

  return (
    <TooltipProvider>
      <Tooltip>
        <TooltipTrigger asChild>
          <button
            onClick={() => onExpand(technique)}
            className={cn(
              'group rounded-lg border border-slate-700 bg-navy-800 hover:border-cyan-500/50 transition-all cursor-pointer text-left focus:outline-none focus:ring-2 focus:ring-cyan-500',
              // Fill the ReactFlow node wrapper so the box width matches the
              // tactic header above it (196px normally, 220px during capture).
              'w-full',
            )}
            aria-label={`${technique.technique_id}: ${technique.technique_name}`}
          >
            {/* Confidence color stripe */}
            <div
              className="h-1 rounded-t-lg"
              style={{ backgroundColor: confidenceColor }}
            />
            <div className="p-2.5">
              <div className="text-[10px] font-mono text-cyan-400 mb-0.5">
                {technique.sub_technique_id ?? technique.technique_id}
              </div>
              <div className="text-xs font-medium text-foreground leading-tight line-clamp-2">
                {technique.sub_technique_name ?? technique.technique_name}
              </div>
              <div className="mt-1.5">
                <span className="text-[9px] uppercase tracking-wide px-1.5 py-0.5 rounded"
                  style={{ backgroundColor: confidenceColor + '22', color: confidenceColor }}>
                  {technique.confidence}
                </span>
              </div>
              {/* Evidence blurb — only rendered during capture for the email image */}
              {showEvidence && evidenceSnippet && (
                <div className="mt-2 pt-2 border-t border-slate-700/50">
                  <p className="text-[8px] leading-[1.35] text-slate-400">
                    {evidenceSnippet}
                  </p>
                </div>
              )}
            </div>
          </button>
        </TooltipTrigger>
        <TooltipContent side="bottom" className="max-w-xs text-xs">
          <p className="font-semibold mb-1">{technique.technique_name}</p>
          <p className="text-muted-foreground">{technique.evidence.slice(0, 120)}{technique.evidence.length > 120 ? '…' : ''}</p>
        </TooltipContent>
      </Tooltip>
    </TooltipProvider>
  );
}

const nodeTypes = { attackNode: AttackNode };

// Group techniques by tactic for layout
const TACTIC_ORDER = [
  'Reconnaissance', 'Resource Development', 'Initial Access', 'Execution',
  'Persistence', 'Privilege Escalation', 'Defense Evasion', 'Credential Access',
  'Discovery', 'Lateral Movement', 'Collection', 'Command and Control',
  'Exfiltration', 'Impact',
];

interface Props {
  techniques: AttackTechnique[];
  onSelectTechnique: (t: AttackTechnique) => void;
  onRegisterCapture?: (fn: () => Promise<string | null>) => void;
}

export default function AttackChainView({ techniques, onSelectTechnique, onRegisterCapture }: Props) {
  const containerRef = useRef<HTMLDivElement>(null);
  const [rfInstance, setRfInstance] = useState<ReactFlowInstance | null>(null);

  // ── Data memos ───────────────────────────────────────────────────────
  const sorted = useMemo(() => {
    return [...techniques].sort((a, b) => {
      const ai = TACTIC_ORDER.indexOf(a.tactic);
      const bi = TACTIC_ORDER.indexOf(b.tactic);
      return (ai === -1 ? 99 : ai) - (bi === -1 ? 99 : bi) || a.order - b.order;
    });
  }, [techniques]);

  const tacticGroups = useMemo(() => {
    const groups: Map<string, AttackTechnique[]> = new Map();
    for (const t of sorted) {
      const existing = groups.get(t.tactic) ?? [];
      existing.push(t);
      groups.set(t.tactic, existing);
    }
    return groups;
  }, [sorted]);

  const { nodes, edges } = useMemo(() => {
    const nodes: Node[] = [];
    const edges: Edge[] = [];
    const NODE_W = 196;
    const NODE_H = 90;
    const TACTIC_HEADER_H = 32;
    const GAP_X = 20;
    const GAP_Y = 12;

    let colX = 20;
    const tacticHeaders: Node[] = [];

    tacticGroups.forEach((techs, tactic) => {
      const colW = NODE_W;

      // Tactic header node
      const headerId = `tactic-${tactic}`;
      tacticHeaders.push({
        id: headerId,
        type: 'default',
        position: { x: colX, y: 0 },
        draggable: false,
        selectable: false,
        data: { label: tactic },
        style: {
          background: '#111c33',
          border: '1px solid #3f83e633',
          borderRadius: 6,
          color: '#3f83e6',
          fontSize: 10,
          fontWeight: 700,
          textTransform: 'uppercase',
          letterSpacing: 1,
          width: colW,
          height: TACTIC_HEADER_H,
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          padding: '0 8px',
        },
      });

      // Technique nodes in this column — include tactic slug in ID to prevent collision
      // when the same technique_id appears under multiple tactics
      techs.forEach((tech, idx) => {
        const nodeId = `tech-${tactic}-${tech.technique_id}-${idx}`;
        nodes.push({
          id: nodeId,
          type: 'attackNode',
          position: { x: colX, y: TACTIC_HEADER_H + 10 + idx * (NODE_H + GAP_Y) },
          draggable: false,
          data: { technique: tech, onExpand: onSelectTechnique },
          style: { width: NODE_W },
        });
      });

      colX += colW + GAP_X;
    });

    // Add tactic headers
    nodes.push(...tacticHeaders);

    // Edges: connect each technique to the next in chain order
    for (let i = 0; i < sorted.length - 1; i++) {
      const src = sorted[i];
      const tgt = sorted[i + 1];
      // Only connect if same or adjacent tactic
      const srcIdx = Array.from(tacticGroups.keys()).indexOf(src.tactic);
      const tgtIdx = Array.from(tacticGroups.keys()).indexOf(tgt.tactic);
      if (Math.abs(srcIdx - tgtIdx) <= 1) {
        edges.push({
          id: `edge-${i}`,
          source: `tech-${src.tactic}-${src.technique_id}-${Array.from(tacticGroups.get(src.tactic) ?? []).indexOf(src)}`,
          target: `tech-${tgt.tactic}-${tgt.technique_id}-${Array.from(tacticGroups.get(tgt.tactic) ?? []).indexOf(tgt)}`,
          animated: true,
          style: { stroke: '#3f83e655', strokeWidth: 1.5 },
          type: 'smoothstep',
        });
      }
    }

    return { nodes, edges };
  }, [tacticGroups, sorted, onSelectTechnique]);

  // ── ReactFlow state ──────────────────────────────────────────────────
  const [rfNodes, setRfNodes, onNodesChange] = useNodesState(nodes);
  const [rfEdges, setRfEdges, onEdgesChange] = useEdgesState(edges);

  // Keep ReactFlow state in sync when techniques (and thus nodes/edges) change
  useEffect(() => { setRfNodes(nodes); }, [nodes]);
  useEffect(() => { setRfEdges(edges); }, [edges]);

  // ── Capture handler (for email / export PNG) ─────────────────────────
  useEffect(() => {
    if (!onRegisterCapture) return;
    onRegisterCapture(async () => {
      if (!containerRef.current || !rfInstance) return null;
      try {
        // Save the original node state so we can restore after capture
        const originalNodes = rfInstance.getNodes();
        if (originalNodes.length === 0) return null;

        // ── Pass 1: Enable evidence blurbs on technique nodes ──────────
        // Also widen nodes to 220px and expand tactic headers to match.
        const CAPTURE_NODE_W = 220;
        const CAPTURE_COL_W = CAPTURE_NODE_W + 16; // slightly wider than node for padding
        const TACTIC_HEADER_H = 32;

        // Rebuild x positions so wider columns don't overlap
        const colXSet = new Set<number>();
        for (const n of originalNodes) {
          if (n.type === 'attackNode') colXSet.add(n.position.x);
        }
        const sortedColXs = Array.from(colXSet).sort((a, b) => a - b);
        const colXMap = new Map<number, number>(); // old x → new x
        let newColX = 20;
        for (const oldX of sortedColXs) {
          colXMap.set(oldX, newColX);
          newColX += CAPTURE_COL_W + 20; // column width + gap
        }

        const evidenceNodes = originalNodes.map((n) => {
          if (n.type === 'attackNode') {
            return {
              ...n,
              position: { ...n.position, x: colXMap.get(n.position.x) ?? n.position.x },
              data: { ...n.data, showEvidence: true },
              style: { ...n.style, width: CAPTURE_NODE_W },
            };
          }
          // Tactic header — widen and reposition to match column
          if (n.id.startsWith('tactic-')) {
            const matchedX = colXMap.get(n.position.x) ?? n.position.x;
            return {
              ...n,
              position: { ...n.position, x: matchedX },
              style: { ...n.style, width: CAPTURE_COL_W },
            };
          }
          return n;
        });
        setRfNodes(evidenceNodes);
        // Wait for React to render evidence text and ReactFlow to measure new heights
        await new Promise<void>((r) => setTimeout(r, 700));

        // ── Pass 2: Re-space vertically using actual measured heights ──
        const measuredNodes = rfInstance.getNodes();
        // Group technique nodes by column (x position)
        const columns = new Map<number, typeof measuredNodes>();
        for (const n of measuredNodes) {
          if (n.type !== 'attackNode') continue;
          const col = columns.get(n.position.x) ?? [];
          col.push(n);
          columns.set(n.position.x, col);
        }

        const GAP_Y = 16;
        const newPositions = new Map<string, { x: number; y: number }>();
        columns.forEach((colNodes) => {
          colNodes.sort((a, b) => a.position.y - b.position.y);
          let curY = TACTIC_HEADER_H + 14;
          for (const n of colNodes) {
            newPositions.set(n.id, { x: n.position.x, y: curY });
            curY += (n.height ?? 160) + GAP_Y;
          }
        });

        const spacedNodes = measuredNodes.map((n) => {
          const pos = newPositions.get(n.id);
          return pos ? { ...n, position: pos } : n;
        });
        setRfNodes(spacedNodes);
        await new Promise<void>((r) => setTimeout(r, 500));

        // ── Capture ────────────────────────────────────────────────────
        const finalNodes = rfInstance.getNodes();
        let minX = Infinity, minY = Infinity, maxX = -Infinity, maxY = -Infinity;
        for (const node of finalNodes) {
          const w = node.width ?? (node.style?.width as number | undefined) ?? CAPTURE_NODE_W;
          const h = node.height ?? 90;
          minX = Math.min(minX, node.position.x);
          minY = Math.min(minY, node.position.y);
          maxX = Math.max(maxX, node.position.x + w);
          maxY = Math.max(maxY, node.position.y + h);
        }

        const MARGIN = 60;
        const captureW = Math.ceil(maxX - minX) + MARGIN * 2;
        const captureH = Math.ceil(maxY - minY) + MARGIN * 2;

        const el = containerRef.current;
        const orig = {
          width: el.style.width,
          height: el.style.height,
          minHeight: el.style.minHeight,
          maxHeight: el.style.maxHeight,
          overflow: el.style.overflow,
        };

        el.style.width = `${captureW}px`;
        el.style.height = `${captureH}px`;
        el.style.minHeight = `${captureH}px`;
        el.style.maxHeight = `${captureH}px`;
        el.style.overflow = 'visible';

        // Set viewport directly — zoom 1, translate so content starts at MARGIN
        rfInstance.setViewport(
          { x: -minX + MARGIN, y: -minY + MARGIN, zoom: 1 },
          { duration: 0 },
        );
        await new Promise<void>((r) => setTimeout(r, 500));

        const dataUrl = await toPng(el, {
          backgroundColor: '#161922',
          skipFonts: true,
          pixelRatio: 2,
          width: captureW,
          height: captureH,
          filter: (node: HTMLElement) => {
            const cls = node.classList;
            if (!cls) return true;
            return !cls.contains('react-flow__controls') &&
                   !cls.contains('react-flow__minimap') &&
                   !cls.contains('react-flow__attribution');
          },
        });

        // ── Restore ────────────────────────────────────────────────────
        el.style.width = orig.width;
        el.style.height = orig.height;
        el.style.minHeight = orig.minHeight;
        el.style.maxHeight = orig.maxHeight;
        el.style.overflow = orig.overflow;
        setRfNodes(originalNodes);
        rfInstance.fitView({ padding: 0.2, duration: 0 });

        return dataUrl;
      } catch (e) {
        console.error('ATT&CK diagram capture failed:', e);
        return null;
      }
    });
  }, [onRegisterCapture, rfInstance, setRfNodes]);

  return (
    <div ref={containerRef} className="w-full h-full relative" style={{ minHeight: 340 }}>
      <ReactFlow
        nodes={rfNodes}
        edges={rfEdges}
        onNodesChange={onNodesChange}
        onEdgesChange={onEdgesChange}
        nodeTypes={nodeTypes}
        fitView
        fitViewOptions={{ padding: 0.2 }}
        minZoom={0.3}
        maxZoom={1.5}
        proOptions={{ hideAttribution: true }}
        onInit={setRfInstance}
      >
        <Background variant={BackgroundVariant.Dots} gap={20} size={1} color="#2a2f3a" />
        <Controls showInteractive={false} />
        <MiniMap
          nodeColor={(n) => {
            if (n.type === 'default') return '#111c33';
            const tech = (n.data as { technique?: AttackTechnique })?.technique;
            return tech ? (CONFIDENCE_COLORS[tech.confidence] ?? '#888') : '#888';
          }}
          maskColor="rgba(7,13,26,0.7)"
          style={{ background: '#161922' }}
        />
      </ReactFlow>
      {/* Legend */}
      <div className="absolute bottom-2 left-2 z-10 flex items-center gap-3 bg-navy-950/90 border border-border/60 rounded-md px-2.5 py-1.5 text-[9px] pointer-events-none select-none">
        <span className="text-muted-foreground/50 uppercase tracking-widest font-medium">Confidence</span>
        {Object.entries(CONFIDENCE_COLORS).map(([level, color]) => (
          <span key={level} className="flex items-center gap-1">
            <span className="w-2 h-2 rounded-sm flex-shrink-0" style={{ backgroundColor: color }} />
            <span style={{ color }}>{level}</span>
          </span>
        ))}
      </div>
    </div>
  );
}
