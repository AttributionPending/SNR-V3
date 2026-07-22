/**
 * SearchView — the full-panel Intelligence Search workspace. Left: search +
 * entity-type filters + results (with annotation-count badges). Right: an entity
 * detail panel for the selected IOC/actor with cross-incident context, a comment
 * thread (EntityAnnotations), and actions — add to case (pivot), open pivot,
 * view graph, navigate. Complements the Cmd+K quick-jump palette.
 */
import { useState, useEffect, useRef, useCallback, useMemo } from 'react';
import {
  Search, Globe, Shield, Crosshair, Server, FileText, Loader2, ExternalLink,
  FolderPlus, Network, X, MessageSquare, ArrowRight,
} from 'lucide-react';
import { cn } from '@/lib/utils';
import { defangIoc } from '@/lib/defang';
import * as api from '@/lib/api';
import type { SearchHit, IocOccurrences, EntityRef, GraphData, IntelOverview } from '@/lib/api';
import EntityAnnotations from './EntityAnnotations';
import IOCPivot from './IOCPivot';
import AddToCaseDialog from './AddToCaseDialog';
import LinkGraph from './LinkGraph';
import { StatTiles, TopIndicators, TopActors, TopTechniques, RecentActivity } from './intel/HoldingsPanels';

type Cat = SearchHit['category'];
const CAT: Record<Cat, { label: string; icon: React.ElementType; color: string }> = {
  ioc: { label: 'IOC', icon: Globe, color: 'text-cyan-400' },
  threat_actor: { label: 'Actor', icon: Shield, color: 'text-red-400' },
  technique: { label: 'Technique', icon: Crosshair, color: 'text-orange-400' },
  session: { label: 'Session', icon: FileText, color: 'text-emerald-400' },
  asset: { label: 'Asset', icon: Server, color: 'text-violet-400' },
};
const FILTERS: Array<{ key: 'all' | Cat; label: string }> = [
  { key: 'all', label: 'All' }, { key: 'ioc', label: 'IOCs' }, { key: 'threat_actor', label: 'Actors' },
  { key: 'technique', label: 'Techniques' }, { key: 'session', label: 'Sessions' }, { key: 'asset', label: 'Assets' },
];

function hitToRef(h: SearchHit): EntityRef | null {
  if (h.category === 'ioc' && h.meta?.type) return { entity_type: 'ioc', ioc_type: h.meta.type, ioc_value: h.value, label: h.value };
  if (h.category === 'threat_actor' && h.meta?.actor_id) return { entity_type: 'actor', actor_id: h.meta.actor_id, label: h.value };
  return null;
}

interface Props {
  initialQuery?: string;
  onSelectSession: (id: string) => void;
  onSelectThreatActor: (id: string) => void;
  onShowToast?: (message: string, type?: 'success' | 'error' | 'info') => void;
  onCasesChanged?: () => void;
}

export default function SearchView({ initialQuery = '', onSelectSession, onSelectThreatActor, onShowToast, onCasesChanged }: Props) {
  const [query, setQuery] = useState(initialQuery);
  const [results, setResults] = useState<SearchHit[]>([]);
  const [loading, setLoading] = useState(false);
  const [filter, setFilter] = useState<'all' | Cat>('all');
  const [selected, setSelected] = useState<SearchHit | null>(null);
  const [counts, setCounts] = useState<Map<number, number>>(new Map());
  const inputRef = useRef<HTMLInputElement>(null);
  const debounceRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  // Detail state
  const [ioc, setIoc] = useState<IocOccurrences | null>(null);
  const [actor, setActor] = useState<Awaited<ReturnType<typeof api.fetchThreatActorDetail>> | null>(null);
  const [detailLoading, setDetailLoading] = useState(false);

  // Overlays
  const [pivot, setPivot] = useState<{ sessionIds: string[]; label: string } | null>(null);
  const [iocPivot, setIocPivot] = useState<{ type: string; value: string } | null>(null);
  const [graph, setGraph] = useState<{ title: string; data: GraphData } | null>(null);

  useEffect(() => { setTimeout(() => inputRef.current?.focus(), 30); }, []);

  // Holdings for the no-query browse state.
  const [browse, setBrowse] = useState<IntelOverview | null>(null);
  useEffect(() => { api.fetchIntelOverview().then(setBrowse).catch(() => setBrowse(null)); }, []);

  // Select a holdings item as a synthetic search hit so the detail panel + actions work.
  const selectIoc = (type: string, value: string) => setSelected({ category: 'ioc', value, context: '', session_id: '', session_name: '', meta: { type } });
  const selectActor = (id: string, name: string) => setSelected({ category: 'threat_actor', value: name, context: '', session_id: '', session_name: '', meta: { actor_id: id } });

  const doSearch = useCallback(async (q: string) => {
    if (q.trim().length < 2) { setResults([]); setCounts(new Map()); return; }
    setLoading(true);
    try {
      const data = await api.searchIntelligence(q.trim(), 100);
      setResults(data.results);
      // Badge IOC/actor rows with annotation counts (aligned request).
      const annIdx = data.results.map((h, i) => ({ h, i })).filter(({ h }) => hitToRef(h));
      const refs = annIdx.map(({ h }) => hitToRef(h)!);
      const arr = await api.fetchAnnotationCounts(refs);
      const m = new Map<number, number>();
      annIdx.forEach(({ i }, j) => m.set(i, arr[j] ?? 0));
      setCounts(m);
    } catch { setResults([]); setCounts(new Map()); } finally { setLoading(false); }
  }, []);

  useEffect(() => {
    if (debounceRef.current) clearTimeout(debounceRef.current);
    debounceRef.current = setTimeout(() => doSearch(query), 250);
    return () => { if (debounceRef.current) clearTimeout(debounceRef.current); };
  }, [query, doSearch]);

  // Load detail when a selectable entity is chosen.
  useEffect(() => {
    setIoc(null); setActor(null);
    if (!selected) return;
    if (selected.category === 'ioc' && selected.meta?.type) {
      setDetailLoading(true);
      api.fetchIocOccurrences(selected.meta.type, selected.value).then(setIoc).catch(() => setIoc(null)).finally(() => setDetailLoading(false));
    } else if (selected.category === 'threat_actor' && selected.meta?.actor_id) {
      setDetailLoading(true);
      api.fetchThreatActorDetail(selected.meta.actor_id).then(setActor).catch(() => setActor(null)).finally(() => setDetailLoading(false));
    }
  }, [selected]);

  const shown = useMemo(() => (filter === 'all' ? results : results.filter((h) => h.category === filter)), [results, filter]);

  const openGraph = async (seed: string, title: string) => {
    try { setGraph({ title, data: await api.fetchGraph(seed) }); }
    catch { onShowToast?.('Failed to load graph', 'error'); }
  };

  return (
    <main className="flex-1 flex h-full overflow-hidden bg-background">
      {/* Left: search + results */}
      <div className="w-[340px] flex-shrink-0 border-r border-border flex flex-col">
        <div className="p-3 border-b border-border">
          <div className="flex items-center gap-2 bg-secondary/40 border border-border rounded-md px-2.5 py-1.5">
            <Search className="w-4 h-4 text-muted-foreground/60 flex-shrink-0" />
            <input
              ref={inputRef} value={query} onChange={(e) => setQuery(e.target.value)}
              placeholder="Search IOCs, actors, techniques, sessions, assets…"
              className="flex-1 bg-transparent text-sm text-foreground placeholder:text-muted-foreground/40 focus:outline-none"
              autoComplete="off" spellCheck={false}
            />
            {loading && <Loader2 className="w-3.5 h-3.5 text-cyan-400 animate-spin flex-shrink-0" />}
          </div>
          <div className="flex flex-wrap gap-1 mt-2">
            {FILTERS.map((f) => (
              <button key={f.key} onClick={() => setFilter(f.key)}
                className={cn('text-[11px] px-2 py-0.5 rounded-full border transition-colors',
                  filter === f.key ? 'bg-primary/15 border-primary/40 text-foreground' : 'border-border text-muted-foreground hover:text-foreground')}>
                {f.label}
              </button>
            ))}
          </div>
        </div>

        <div className="flex-1 overflow-y-auto">
          {query.trim().length < 2 ? (
            <div className="px-4 py-8 text-center text-xs text-muted-foreground/50">Type to search, or browse your holdings on the right.</div>
          ) : shown.length === 0 && !loading ? (
            <div className="px-4 py-10 text-center text-xs text-muted-foreground/50">No results.</div>
          ) : (
            <ul>
              {shown.map((h) => {
                const idx = results.indexOf(h);
                const cfg = CAT[h.category];
                const Icon = cfg.icon;
                const n = counts.get(idx) ?? 0;
                const isSel = selected === h;
                return (
                  <li key={`${h.category}-${h.value}-${idx}`}>
                    <button onClick={() => setSelected(h)}
                      className={cn('w-full text-left px-3 py-2 border-b border-border/40 transition-colors flex items-start gap-2', isSel ? 'bg-primary/10' : 'hover:bg-secondary/40')}>
                      <Icon className={cn('w-3.5 h-3.5 mt-0.5 flex-shrink-0', cfg.color)} />
                      <div className="min-w-0 flex-1">
                        <div className="text-xs text-foreground truncate font-mono">{h.value}</div>
                        {h.context && <div className="text-[10px] text-muted-foreground truncate">{h.context}</div>}
                      </div>
                      <div className="flex items-center gap-1.5 flex-shrink-0">
                        {n > 0 && <span className="inline-flex items-center gap-0.5 text-[9px] text-muted-foreground"><MessageSquare className="w-2.5 h-2.5" />{n}</span>}
                        {h.sessions && h.sessions.length > 0 && <span className="text-[9px] text-muted-foreground/50">{h.sessions.length}</span>}
                      </div>
                    </button>
                  </li>
                );
              })}
            </ul>
          )}
        </div>
      </div>

      {/* Right: entity detail, or holdings browse when there's no query/selection */}
      <div className="flex-1 min-w-0 overflow-y-auto">
        {!selected && query.trim().length < 2 && browse ? (
          <div className="p-4 max-w-4xl">
            <StatTiles counts={browse.counts} />
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-3 mt-4">
              <div className="h-72"><TopIndicators items={browse.top_iocs} onSelectIoc={selectIoc} /></div>
              <div className="h-72"><TopActors items={browse.top_actors} onSelectActor={selectActor} /></div>
              <div className="h-72"><TopTechniques items={browse.top_techniques} onSelectTechnique={(id) => setQuery(id)} /></div>
              <div className="h-72"><RecentActivity iocs={browse.recent_iocs} sessions={browse.recent_sessions} onSelectIoc={selectIoc} onSelectSession={onSelectSession} /></div>
            </div>
          </div>
        ) : !selected ? (
          <div className="h-full flex items-center justify-center text-sm text-muted-foreground/50">Select a result to view details.</div>
        ) : (
          <div className="p-5 max-w-2xl">
            <EntityHeader hit={selected} />

            {(selected.category === 'ioc' || selected.category === 'threat_actor') ? (
              <>
                <div className="flex flex-wrap gap-2 my-4">
                  {selected.category === 'ioc' && (
                    <ActionBtn icon={Crosshair} label="Open pivot" onClick={() => setIocPivot({ type: selected.meta!.type, value: selected.value })} />
                  )}
                  {selected.category === 'threat_actor' && (
                    <ActionBtn icon={ExternalLink} label="Open actor" onClick={() => onSelectThreatActor(selected.meta!.actor_id)} />
                  )}
                  <ActionBtn icon={FolderPlus} label="Add to case"
                    onClick={() => {
                      const sessionIds = selected.category === 'ioc'
                        ? (ioc?.sessions.map((s) => s.id) ?? selected.sessions?.map((s) => s.id) ?? [])
                        : (actor?.sessions.map((s) => s.id) ?? selected.sessions?.map((s) => s.id) ?? []);
                      setPivot({ sessionIds, label: selected.value });
                    }} />
                  <ActionBtn icon={Network} label="View graph"
                    onClick={() => selected.category === 'ioc'
                      ? openGraph(`ioc:${selected.meta!.type}:${selected.value}`, selected.value)
                      : openGraph(`actor:${selected.meta!.actor_id}`, selected.value)} />
                </div>

                {detailLoading ? (
                  <div className="flex items-center gap-2 text-xs text-muted-foreground py-4"><Loader2 className="w-4 h-4 animate-spin" />Loading…</div>
                ) : (
                  <div className="space-y-5">
                    {selected.category === 'ioc' && ioc && <IocDetail data={ioc} onSelectSession={onSelectSession} onSelectActor={onSelectThreatActor} />}
                    {selected.category === 'threat_actor' && actor && <ActorDetail data={actor} onSelectSession={onSelectSession} />}

                    <div className="border-t border-border pt-4">
                      {selected.category === 'ioc'
                        ? <EntityAnnotations entityType="ioc" iocType={selected.meta!.type} iocValue={selected.value} label={selected.value} />
                        : <EntityAnnotations entityType="actor" actorId={selected.meta!.actor_id} label={selected.value} />}
                    </div>
                  </div>
                )}
              </>
            ) : (
              // Technique / session / asset → navigate only.
              <div className="mt-4">
                <div className="text-[10px] uppercase tracking-wide text-muted-foreground/70 mb-2">Appears in</div>
                <ul className="space-y-1">
                  {(selected.sessions ?? [{ id: selected.session_id, name: selected.session_name }]).map((s) => (
                    <li key={s.id}>
                      <button onClick={() => onSelectSession(s.id)} className="w-full flex items-center gap-2 text-left px-2 py-1.5 rounded hover:bg-secondary/40 text-xs group">
                        <ArrowRight className="w-3 h-3 text-muted-foreground/40 group-hover:text-cyan-400" />
                        <span className="flex-1 truncate text-foreground group-hover:text-cyan-300">{s.name}</span>
                      </button>
                    </li>
                  ))}
                </ul>
              </div>
            )}
          </div>
        )}
      </div>

      {/* Overlays */}
      {iocPivot && <IOCPivot type={iocPivot.type} value={iocPivot.value} onSelectSession={(id) => { setIocPivot(null); onSelectSession(id); }} onClose={() => setIocPivot(null)} />}
      {pivot && <AddToCaseDialog open sessionIds={pivot.sessionIds} label={pivot.label} onClose={() => setPivot(null)} onShowToast={onShowToast} onChanged={onCasesChanged} />}
      {graph && (
        <div className="fixed inset-0 z-[135] flex items-center justify-center p-6 bg-black/70 backdrop-blur-sm" onClick={() => setGraph(null)}>
          <div className="bg-navy-900 border border-border rounded-lg w-[90vw] h-[85vh] flex flex-col" onClick={(e) => e.stopPropagation()}>
            <div className="px-4 py-2.5 border-b border-border flex items-center justify-between">
              <span className="text-xs font-semibold text-foreground truncate">Graph — {graph.title}</span>
              <button onClick={() => setGraph(null)} className="text-muted-foreground hover:text-foreground"><X className="w-4 h-4" /></button>
            </div>
            <div className="flex-1 min-h-0">
              <LinkGraph data={graph.data} onSelectSession={(id) => { setGraph(null); onSelectSession(id); }} onSelectActor={(id) => { setGraph(null); onSelectThreatActor(id); }} onPivotIoc={(type, value) => { setGraph(null); setIocPivot({ type, value }); }} />
            </div>
          </div>
        </div>
      )}
    </main>
  );
}

function EntityHeader({ hit }: { hit: SearchHit }) {
  const cfg = CAT[hit.category];
  const Icon = cfg.icon;
  const display = hit.category === 'ioc' && hit.meta?.type ? defangIoc(hit.meta.type, hit.value) : hit.value;
  return (
    <div className="flex items-center gap-2.5">
      <div className="w-9 h-9 rounded-lg bg-secondary flex items-center justify-center flex-shrink-0"><Icon className={cn('w-4.5 h-4.5', cfg.color)} /></div>
      <div className="min-w-0">
        <div className="text-sm font-semibold text-foreground font-mono truncate">{display}</div>
        <div className="text-[11px] text-muted-foreground">{cfg.label}{hit.meta?.type ? ` · ${hit.meta.type}` : ''}{hit.context ? ` · ${hit.context}` : ''}</div>
      </div>
    </div>
  );
}

function ActionBtn({ icon: Icon, label, onClick }: { icon: React.ElementType; label: string; onClick: () => void }) {
  return (
    <button onClick={onClick} className="inline-flex items-center gap-1.5 text-xs px-2.5 py-1.5 rounded-md border border-border hover:bg-secondary/50 text-foreground transition-colors">
      <Icon className="w-3.5 h-3.5 text-muted-foreground" />{label}
    </button>
  );
}

function IocDetail({ data, onSelectSession, onSelectActor }: { data: IocOccurrences; onSelectSession: (id: string) => void; onSelectActor: (id: string) => void }) {
  return (
    <div className="space-y-4">
      {data.actors.length > 0 && (
        <div>
          <div className="text-[10px] uppercase tracking-wide text-muted-foreground/70 mb-1.5">Attributed actors</div>
          <div className="flex flex-wrap gap-1.5">
            {data.actors.map((a) => (
              <button key={a.id} onClick={() => onSelectActor(a.id)} className="inline-flex items-center gap-1 text-xs px-2 py-0.5 rounded-full bg-red-500/10 text-red-300 border border-red-500/20 hover:bg-red-500/20">
                <Shield className="w-3 h-3" />{a.name}
              </button>
            ))}
          </div>
        </div>
      )}
      <div>
        <div className="text-[10px] uppercase tracking-wide text-muted-foreground/70 mb-1.5">Seen in {data.sessions.length} incident{data.sessions.length !== 1 ? 's' : ''}</div>
        <ul className="space-y-0.5">
          {data.sessions.map((s) => (
            <li key={s.id}>
              <button onClick={() => onSelectSession(s.id)} className="w-full flex items-center gap-2 text-left px-2 py-1.5 rounded hover:bg-secondary/40 text-xs group">
                <FileText className="w-3.5 h-3.5 text-muted-foreground/50" />
                <span className="flex-1 truncate text-foreground group-hover:text-cyan-300">{s.name}</span>
                {s.severity && <span className="text-[10px] text-muted-foreground/60">{s.severity}</span>}
              </button>
            </li>
          ))}
        </ul>
      </div>
    </div>
  );
}

function ActorDetail({ data, onSelectSession }: { data: Awaited<ReturnType<typeof api.fetchThreatActorDetail>>; onSelectSession: (id: string) => void }) {
  return (
    <div className="space-y-4">
      <div className="flex flex-wrap gap-3 text-[11px] text-muted-foreground">
        <span>{data.sessions.length} incident{data.sessions.length !== 1 ? 's' : ''}</span>
        <span>{data.aggregated_ttps.length} technique{data.aggregated_ttps.length !== 1 ? 's' : ''}</span>
        <span>{data.aggregated_iocs.length} indicator{data.aggregated_iocs.length !== 1 ? 's' : ''}</span>
        {data.actor.attribution_confidence && <span>Attribution: {data.actor.attribution_confidence}</span>}
      </div>
      <div>
        <div className="text-[10px] uppercase tracking-wide text-muted-foreground/70 mb-1.5">Linked incidents</div>
        <ul className="space-y-0.5">
          {data.sessions.slice(0, 12).map((s) => (
            <li key={s.id}>
              <button onClick={() => onSelectSession(s.id)} className="w-full flex items-center gap-2 text-left px-2 py-1.5 rounded hover:bg-secondary/40 text-xs group">
                <FileText className="w-3.5 h-3.5 text-muted-foreground/50" />
                <span className="flex-1 truncate text-foreground group-hover:text-cyan-300">{s.name}</span>
              </button>
            </li>
          ))}
        </ul>
      </div>
    </div>
  );
}
