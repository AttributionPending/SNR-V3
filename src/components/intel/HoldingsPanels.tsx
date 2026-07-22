/**
 * Presentational holdings panels shared by the Intelligence dashboard and the
 * Search browse-state. Each takes already-fetched data plus generic select
 * callbacks so the host wires drill-in however it wants (overlay vs. detail
 * panel vs. navigation). Row renderers are exported so the paginated, sortable
 * HoldingsCard can reuse the exact same row markup.
 */
import { forwardRef } from 'react';
import { Globe, Shield, Crosshair, FileText, Server, Boxes, Clock } from 'lucide-react';
import { cn, formatTimestamp } from '@/lib/utils';
import { defangIoc } from '@/lib/defang';
import type { IocIndicator, IntelOverview, IntelActor, IntelTechnique, IntelSession } from '@/lib/api';

const SEV: Record<string, string> = { Critical: 'text-red-400', High: 'text-orange-400', Medium: 'text-yellow-400', Low: 'text-emerald-400', Informational: 'text-muted-foreground' };

export function StatTiles({ counts }: { counts: IntelOverview['counts'] }) {
  const tiles = [
    { label: 'Indicators', value: counts.indicators, icon: Globe },
    { label: 'Threat actors', value: counts.actors, icon: Shield },
    { label: 'Techniques', value: counts.techniques, icon: Crosshair },
    { label: 'Incidents', value: counts.incidents, icon: FileText },
    { label: 'Cases', value: counts.cases, icon: Boxes },
  ];
  return (
    <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-2">
      {tiles.map((t) => (
        <div key={t.label} className="bg-navy-800 border border-border rounded-lg px-3 py-2.5">
          <div className="flex items-center gap-1.5 text-[10px] uppercase tracking-wide text-muted-foreground/70"><t.icon className="w-3 h-3" />{t.label}</div>
          <div className="text-xl font-semibold text-foreground mt-0.5">{t.value.toLocaleString()}</div>
        </div>
      ))}
    </div>
  );
}

/** Panel shell. Optional `headerRight` (e.g. a sort control) and a scrollable
 *  body that forwards a ref + onScroll so hosts can wire infinite scroll. */
export const Panel = forwardRef<HTMLDivElement, {
  title: string; icon: React.ElementType; empty?: boolean;
  headerRight?: React.ReactNode; onScroll?: React.UIEventHandler<HTMLDivElement>;
  children: React.ReactNode;
}>(function Panel({ title, icon: Icon, empty, headerRight, onScroll, children }, ref) {
  return (
    <div className="bg-navy-800 border border-border rounded-lg flex flex-col min-h-0 h-full">
      <div className="px-3 py-2 border-b border-border flex items-center gap-1.5">
        <Icon className="w-3.5 h-3.5 text-muted-foreground" />
        <span className="text-[11px] font-semibold text-foreground uppercase tracking-wide flex-1">{title}</span>
        {headerRight}
      </div>
      <div ref={ref} onScroll={onScroll} className="p-1.5 overflow-y-auto flex-1">
        {empty ? <p className="text-xs text-muted-foreground/60 px-2 py-3">Nothing yet.</p> : children}
      </div>
    </div>
  );
});

const rowCls = 'w-full flex items-center gap-2 text-left px-2 py-1.5 rounded hover:bg-secondary/50 transition-colors group text-xs';
const IOC_TYPE_COLOR: Record<string, string> = { ipv4: 'text-red-400', ipv6: 'text-red-400', domain: 'text-orange-400', url: 'text-orange-400', md5: 'text-purple-400', sha1: 'text-purple-400', sha256: 'text-purple-400', email: 'text-blue-400' };

// ── Row renderers (shared by static panels + the paginated HoldingsCard) ──────

export function IndicatorRow({ item, onSelect }: { item: IocIndicator; onSelect: (type: string, value: string) => void }) {
  return (
    <button className={rowCls} onClick={() => onSelect(item.type, item.value)}>
      <span className={cn('font-mono text-[10px] w-14 flex-shrink-0 uppercase', IOC_TYPE_COLOR[item.type] ?? 'text-muted-foreground')}>{item.type}</span>
      <span className="font-mono flex-1 truncate text-foreground group-hover:text-cyan-300">{defangIoc(item.type, item.value)}</span>
      <span className="text-[10px] text-muted-foreground/70 flex-shrink-0">{item.sessionCount}</span>
    </button>
  );
}

export function ActorRow({ item, onSelect }: { item: IntelActor; onSelect: (id: string, name: string) => void }) {
  return (
    <button className={rowCls} onClick={() => onSelect(item.id, item.name)}>
      <Shield className="w-3 h-3 text-red-400/80 flex-shrink-0" />
      <span className="flex-1 truncate text-foreground group-hover:text-cyan-300">{item.name}</span>
      {item.attribution_confidence && <span className="text-[9px] text-muted-foreground/60">{item.attribution_confidence}</span>}
      <span className="text-[10px] text-muted-foreground/70 flex-shrink-0">{item.session_count}</span>
    </button>
  );
}

export function TechniqueRow({ item, onSelect }: { item: IntelTechnique; onSelect: (id: string) => void }) {
  return (
    <button className={rowCls} onClick={() => onSelect(item.technique_id)}>
      <span className="font-mono text-[10px] text-cyan-400 w-14 flex-shrink-0">{item.technique_id}</span>
      <span className="flex-1 min-w-0">
        <span className="truncate text-foreground group-hover:text-cyan-300 block">{item.technique_name}</span>
        <span className="text-[9px] text-muted-foreground/60">{item.tactic}</span>
      </span>
      <span className="text-[10px] text-muted-foreground/70 flex-shrink-0">{item.session_count}</span>
    </button>
  );
}

export function SessionRow({ item, onSelect }: { item: IntelSession; onSelect: (id: string) => void }) {
  return (
    <button className={rowCls} onClick={() => onSelect(item.id)}>
      <FileText className="w-3 h-3 text-muted-foreground/50 flex-shrink-0" />
      <span className="flex-1 truncate text-foreground group-hover:text-cyan-300">{item.name}</span>
      {item.severity && <span className={cn('text-[9px]', SEV[item.severity] ?? 'text-muted-foreground')}>{item.severity}</span>}
      <span className="text-[9px] text-muted-foreground/50 flex-shrink-0">{formatTimestamp(item.created_at)}</span>
    </button>
  );
}

// ── Static panels (used by the Search browse-state with overview data) ────────

export function TopIndicators({ title = 'Top indicators', items, onSelectIoc }: { title?: string; items: IocIndicator[]; onSelectIoc: (type: string, value: string) => void }) {
  return (
    <Panel title={title} icon={Globe} empty={items.length === 0}>
      <ul>{items.map((i) => <li key={`${i.type}:${i.norm}`}><IndicatorRow item={i} onSelect={onSelectIoc} /></li>)}</ul>
    </Panel>
  );
}

export function TopActors({ items, onSelectActor }: { items: IntelActor[]; onSelectActor: (id: string, name: string) => void }) {
  return (
    <Panel title="Threat actors" icon={Shield} empty={items.length === 0}>
      <ul>{items.map((a) => <li key={a.id}><ActorRow item={a} onSelect={onSelectActor} /></li>)}</ul>
    </Panel>
  );
}

export function TopTechniques({ items, onSelectTechnique }: { items: IntelTechnique[]; onSelectTechnique: (id: string) => void }) {
  return (
    <Panel title="Top ATT&CK techniques" icon={Crosshair} empty={items.length === 0}>
      <ul>{items.map((t) => <li key={t.technique_id}><TechniqueRow item={t} onSelect={onSelectTechnique} /></li>)}</ul>
    </Panel>
  );
}

export function RecentActivity({ iocs, sessions, onSelectIoc, onSelectSession }: {
  iocs: IocIndicator[]; sessions: IntelSession[];
  onSelectIoc: (type: string, value: string) => void; onSelectSession: (id: string) => void;
}) {
  return (
    <Panel title="Recent activity" icon={Clock} empty={iocs.length === 0 && sessions.length === 0}>
      {sessions.length > 0 && (
        <>
          <div className="text-[9px] uppercase tracking-wide text-muted-foreground/50 px-2 pt-1 pb-0.5">Latest incidents</div>
          <ul>{sessions.map((s) => <li key={s.id}><SessionRow item={s} onSelect={onSelectSession} /></li>)}</ul>
        </>
      )}
      {iocs.length > 0 && (
        <>
          <div className="text-[9px] uppercase tracking-wide text-muted-foreground/50 px-2 pt-2 pb-0.5">Newest indicators</div>
          <ul>{iocs.map((i) => (
            <li key={`${i.type}:${i.norm}`}>
              <button className={rowCls} onClick={() => onSelectIoc(i.type, i.value)}>
                <Server className="w-3 h-3 text-muted-foreground/50 flex-shrink-0" />
                <span className="font-mono flex-1 truncate text-foreground group-hover:text-cyan-300">{defangIoc(i.type, i.value)}</span>
                <span className="text-[10px] text-muted-foreground/70 flex-shrink-0">{i.sessionCount}</span>
              </button>
            </li>
          ))}</ul>
        </>
      )}
    </Panel>
  );
}
