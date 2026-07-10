/**
 * CaseView — full-panel dossier for an investigation (Case). Mirrors
 * ThreatActorView: editable header (name/status/priority), an investigation log,
 * linked sessions (link/unlink), aggregated TTPs/IOCs, derived actors, and a
 * link-analysis Graph tab. Actors/IOCs are derived server-side from linked
 * sessions. Navigation is delegated to the parent via callbacks.
 */
import { useState, useEffect, useCallback } from 'react';
import {
  Folder, Trash2, Pencil, Check, X, Plus, Search, Link2, Unlink, Clock,
  Crosshair, Shield, ExternalLink, Loader2, Send,
} from 'lucide-react';
import { Button } from './ui/button';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from './ui/select';
import { Tabs, TabsList, TabsTrigger, TabsContent } from './ui/tabs';
import ConfirmDialog from './ConfirmDialog';
import IOCPivot from './IOCPivot';
import LinkGraph from './LinkGraph';
import { cn, formatTimestamp, severityDot } from '@/lib/utils';
import { defangIoc } from '@/lib/defang';
import * as api from '@/lib/api';
import type { CaseDetail, CaseStatus, CasePriority, GraphData } from '@/lib/api';

interface Props {
  caseId: string;
  onSelectSession: (id: string) => void;
  onSelectThreatActor: (id: string) => void;
  onCaseDeleted: () => void;
  onCaseUpdated: () => void;
}

const STATUS_COLOR: Record<CaseStatus, string> = {
  open: 'text-emerald-400', monitoring: 'text-yellow-400', closed: 'text-muted-foreground',
};
const PRIORITY_COLOR: Record<CasePriority, string> = {
  critical: 'text-red-400', high: 'text-orange-400', medium: 'text-yellow-400', low: 'text-emerald-400',
};

export default function CaseView({ caseId, onSelectSession, onSelectThreatActor, onCaseDeleted, onCaseUpdated }: Props) {
  const [detail, setDetail] = useState<CaseDetail | null>(null);
  const [loading, setLoading] = useState(true);
  const [editingName, setEditingName] = useState(false);
  const [nameDraft, setNameDraft] = useState('');
  const [noteDraft, setNoteDraft] = useState('');
  const [confirmDelete, setConfirmDelete] = useState(false);
  const [showLinkSearch, setShowLinkSearch] = useState(false);
  const [linkQuery, setLinkQuery] = useState('');
  const [available, setAvailable] = useState<Array<{ id: string; name: string; severity: string | null; created_at: number }>>([]);
  const [pivotIoc, setPivotIoc] = useState<{ type: string; value: string } | null>(null);
  const [graph, setGraph] = useState<GraphData | null>(null);
  const [graphLoading, setGraphLoading] = useState(false);

  const load = useCallback(async () => {
    setLoading(true);
    try { setDetail(await api.fetchCaseDetail(caseId)); } catch { setDetail(null); } finally { setLoading(false); }
  }, [caseId]);

  useEffect(() => { void load(); }, [load]);

  // Debounced available-session search when the picker is open.
  useEffect(() => {
    if (!showLinkSearch) return;
    const t = setTimeout(async () => {
      try { setAvailable(await api.fetchCaseAvailableSessions(caseId, linkQuery.trim())); } catch { setAvailable([]); }
    }, 250);
    return () => clearTimeout(t);
  }, [showLinkSearch, linkQuery, caseId]);

  const loadGraph = useCallback(async () => {
    setGraphLoading(true);
    try { setGraph(await api.fetchCaseGraph(caseId)); } catch { setGraph({ nodes: [], edges: [] }); } finally { setGraphLoading(false); }
  }, [caseId]);

  const patch = async (data: Parameters<typeof api.updateCase>[1]) => {
    await api.updateCase(caseId, data);
    await load();
    onCaseUpdated();
  };

  const addSessions = async (ids: string[]) => {
    if (ids.length === 0) return;
    await api.linkCaseSessions(caseId, ids);
    setShowLinkSearch(false);
    setLinkQuery('');
    await load();
    onCaseUpdated();
  };

  const addNote = async () => {
    if (!noteDraft.trim()) return;
    await api.addCaseLog(caseId, noteDraft.trim());
    setNoteDraft('');
    await load();
  };

  if (loading) return <div className="flex-1 flex items-center justify-center text-sm text-muted-foreground"><Loader2 className="w-4 h-4 animate-spin mr-2" />Loading case…</div>;
  if (!detail) return <div className="flex-1 flex items-center justify-center text-sm text-muted-foreground">Case not found.</div>;

  const c = detail.case;

  return (
    <main className="flex-1 flex flex-col h-full overflow-hidden bg-background">
      {/* Header */}
      <div className="px-5 py-4 border-b border-border flex items-start gap-3">
        <div className="w-9 h-9 rounded-lg bg-violet-500/15 flex items-center justify-center flex-shrink-0">
          <Folder className="w-4.5 h-4.5 text-violet-400" />
        </div>
        <div className="flex-1 min-w-0">
          {editingName ? (
            <div className="flex items-center gap-1">
              <input
                autoFocus value={nameDraft} onChange={(e) => setNameDraft(e.target.value)}
                onKeyDown={(e) => { if (e.key === 'Enter') { void patch({ name: nameDraft }); setEditingName(false); } if (e.key === 'Escape') setEditingName(false); }}
                className="bg-secondary/50 border border-border rounded px-2 py-0.5 text-sm text-foreground focus:outline-none focus:ring-1 focus:ring-cyan-500/40"
              />
              <button onClick={() => { void patch({ name: nameDraft }); setEditingName(false); }} className="text-emerald-400 p-1"><Check className="w-3.5 h-3.5" /></button>
              <button onClick={() => setEditingName(false)} className="text-muted-foreground p-1"><X className="w-3.5 h-3.5" /></button>
            </div>
          ) : (
            <div className="flex items-center gap-2">
              <h2 className="text-sm font-semibold text-foreground truncate">{c.name}</h2>
              <button onClick={() => { setNameDraft(c.name); setEditingName(true); }} className="text-muted-foreground/50 hover:text-muted-foreground"><Pencil className="w-3 h-3" /></button>
            </div>
          )}
          <div className="flex items-center gap-3 mt-1.5">
            <Select value={c.status} onValueChange={(v) => void patch({ status: v as CaseStatus })}>
              <SelectTrigger className={cn('h-6 text-[11px] w-32', STATUS_COLOR[c.status])}><SelectValue /></SelectTrigger>
              <SelectContent>
                <SelectItem value="open">Open</SelectItem>
                <SelectItem value="monitoring">Monitoring</SelectItem>
                <SelectItem value="closed">Closed</SelectItem>
              </SelectContent>
            </Select>
            <Select value={c.priority} onValueChange={(v) => void patch({ priority: v as CasePriority })}>
              <SelectTrigger className={cn('h-6 text-[11px] w-28', PRIORITY_COLOR[c.priority])}><SelectValue /></SelectTrigger>
              <SelectContent>
                <SelectItem value="critical">Critical</SelectItem>
                <SelectItem value="high">High</SelectItem>
                <SelectItem value="medium">Medium</SelectItem>
                <SelectItem value="low">Low</SelectItem>
              </SelectContent>
            </Select>
            <span className="text-[11px] text-muted-foreground">{c.session_count} session{c.session_count !== 1 ? 's' : ''}</span>
          </div>
        </div>
        <Button variant="ghost" size="sm" className="text-xs text-red-400/80 hover:text-red-300 gap-1.5" onClick={() => setConfirmDelete(true)}>
          <Trash2 className="w-3.5 h-3.5" /> Delete
        </Button>
      </div>

      {/* Tabs */}
      <Tabs defaultValue="overview" className="flex-1 flex flex-col min-h-0" onValueChange={(v) => { if (v === 'graph' && !graph) void loadGraph(); }}>
        <div className="px-5 pt-3">
          <TabsList className="bg-secondary/50 w-auto">
            <TabsTrigger value="overview" className="text-xs">Overview</TabsTrigger>
            <TabsTrigger value="sessions" className="text-xs">Sessions ({detail.sessions.length})</TabsTrigger>
            <TabsTrigger value="ttps" className="text-xs">TTPs ({detail.aggregated_ttps.length})</TabsTrigger>
            <TabsTrigger value="iocs" className="text-xs">IOCs ({detail.aggregated_iocs.length})</TabsTrigger>
            <TabsTrigger value="actors" className="text-xs">Actors ({detail.actors.length})</TabsTrigger>
            <TabsTrigger value="graph" className="text-xs gap-1"><Crosshair className="w-3 h-3" />Graph</TabsTrigger>
          </TabsList>
        </div>

        {/* Overview: summary + investigation log */}
        <TabsContent value="overview" className="flex-1 overflow-y-auto px-5 py-4 mt-0 data-[state=inactive]:hidden">
          <label className="text-[10px] uppercase tracking-wide text-muted-foreground/70">Summary</label>
          <textarea
            defaultValue={c.summary} placeholder="What is this investigation about?"
            onBlur={(e) => { if (e.target.value !== c.summary) void patch({ summary: e.target.value }); }}
            className="w-full mt-1 mb-4 bg-secondary/40 border border-border rounded-md px-3 py-2 text-xs text-foreground min-h-[60px] focus:outline-none focus:ring-1 focus:ring-cyan-500/40"
          />
          <label className="text-[10px] uppercase tracking-wide text-muted-foreground/70">Investigation log</label>
          <div className="flex gap-2 mt-1 mb-3">
            <input
              value={noteDraft} onChange={(e) => setNoteDraft(e.target.value)}
              onKeyDown={(e) => { if (e.key === 'Enter') void addNote(); }}
              placeholder="Add a note…"
              className="flex-1 bg-secondary/40 border border-border rounded-md px-3 py-1.5 text-xs text-foreground focus:outline-none focus:ring-1 focus:ring-cyan-500/40"
            />
            <Button size="sm" className="text-xs gap-1" onClick={() => void addNote()} disabled={!noteDraft.trim()}><Send className="w-3 h-3" />Add</Button>
          </div>
          <ul className="space-y-2">
            {detail.log.map((e) => (
              <li key={e.id} className="flex gap-2 text-xs">
                <Clock className="w-3 h-3 text-muted-foreground/50 flex-shrink-0 mt-0.5" />
                <div className="min-w-0">
                  <div className="text-foreground/90 whitespace-pre-wrap break-words">
                    {e.entry_type !== 'note' && <span className="text-cyan-400/80 mr-1">[{e.entry_type.replace('_', ' ')}]</span>}
                    {e.content}
                  </div>
                  <div className="text-[10px] text-muted-foreground/50">{e.author_name} · {formatTimestamp(e.created_at)}</div>
                </div>
              </li>
            ))}
            {detail.log.length === 0 && <li className="text-xs text-muted-foreground">No log entries yet.</li>}
          </ul>
        </TabsContent>

        {/* Sessions */}
        <TabsContent value="sessions" className="flex-1 overflow-y-auto px-5 py-4 mt-0 data-[state=inactive]:hidden">
          <div className="flex items-center justify-between mb-2">
            <span className="text-[10px] uppercase tracking-wide text-muted-foreground/70">Linked sessions</span>
            <Button size="sm" variant="outline" className="text-xs h-7 gap-1" onClick={() => setShowLinkSearch((v) => !v)}><Plus className="w-3 h-3" />Add sessions</Button>
          </div>
          {showLinkSearch && (
            <div className="mb-3 border border-border rounded-md p-2 bg-secondary/20">
              <div className="relative mb-2">
                <Search className="absolute left-2 top-1/2 -translate-y-1/2 w-3 h-3 text-muted-foreground/50" />
                <input value={linkQuery} onChange={(e) => setLinkQuery(e.target.value)} placeholder="Search sessions…" className="w-full bg-secondary/40 border border-border rounded pl-7 pr-2 py-1 text-xs focus:outline-none" />
              </div>
              <ul className="max-h-48 overflow-y-auto space-y-0.5">
                {available.map((s) => (
                  <li key={s.id}>
                    <button onClick={() => void addSessions([s.id])} className="w-full flex items-center gap-2 text-left px-2 py-1 rounded hover:bg-secondary/60 text-xs">
                      <Link2 className="w-3 h-3 text-muted-foreground/50" />
                      <span className="flex-1 truncate">{s.name}</span>
                      {s.severity && <span className={cn('w-1.5 h-1.5 rounded-full', severityDot(s.severity))} />}
                    </button>
                  </li>
                ))}
                {available.length === 0 && <li className="text-xs text-muted-foreground px-2 py-1">No candidate sessions.</li>}
              </ul>
            </div>
          )}
          <ul className="space-y-1">
            {detail.sessions.map((s) => (
              <li key={s.id} className="flex items-center gap-2 group">
                <button onClick={() => onSelectSession(s.id)} className="flex-1 flex items-center gap-2 text-left px-2 py-1.5 rounded hover:bg-secondary/40 text-xs min-w-0">
                  <span className={cn('w-1.5 h-1.5 rounded-full flex-shrink-0', severityDot(s.severity ?? ''))} />
                  <span className="flex-1 truncate text-foreground group-hover:text-cyan-300">{s.name}</span>
                  <span className="text-[10px] text-muted-foreground/50">{formatTimestamp(s.created_at)}</span>
                </button>
                <button onClick={() => { void api.unlinkCaseSession(caseId, s.id).then(load).then(onCaseUpdated); }} className="text-muted-foreground/40 hover:text-red-400 p-1" title="Unlink"><Unlink className="w-3 h-3" /></button>
              </li>
            ))}
            {detail.sessions.length === 0 && <li className="text-xs text-muted-foreground">No sessions linked yet.</li>}
          </ul>
        </TabsContent>

        {/* TTPs */}
        <TabsContent value="ttps" className="flex-1 overflow-y-auto px-5 py-4 mt-0 data-[state=inactive]:hidden">
          <table className="w-full text-xs">
            <thead><tr className="text-left text-[10px] uppercase tracking-wide text-muted-foreground border-b border-border"><th className="py-1.5 pr-2">Technique</th><th className="py-1.5 pr-2">Tactic</th><th className="py-1.5 text-right">Sessions</th></tr></thead>
            <tbody>
              {detail.aggregated_ttps.map((t) => (
                <tr key={t.technique_id} className="border-b border-border/40">
                  <td className="py-1.5 pr-2"><span className="font-mono text-cyan-400">{t.technique_id}</span> <span className="text-foreground/80">{t.technique_name}</span></td>
                  <td className="py-1.5 pr-2 text-muted-foreground">{t.tactic}</td>
                  <td className="py-1.5 text-right text-muted-foreground">{t.session_count}</td>
                </tr>
              ))}
              {detail.aggregated_ttps.length === 0 && <tr><td colSpan={3} className="py-3 text-muted-foreground">No techniques across linked sessions.</td></tr>}
            </tbody>
          </table>
        </TabsContent>

        {/* IOCs */}
        <TabsContent value="iocs" className="flex-1 overflow-y-auto px-5 py-4 mt-0 data-[state=inactive]:hidden">
          <table className="w-full text-xs">
            <thead><tr className="text-left text-[10px] uppercase tracking-wide text-muted-foreground border-b border-border"><th className="py-1.5 pr-2 w-20">Type</th><th className="py-1.5 pr-2">Indicator</th><th className="py-1.5 text-right w-20">Sessions</th></tr></thead>
            <tbody>
              {detail.aggregated_iocs.map((i) => (
                <tr key={`${i.type}:${i.norm}`} className={cn('border-b border-border/40 hover:bg-secondary/30 cursor-pointer', i.any_false_positive && 'opacity-50')} onClick={() => setPivotIoc({ type: i.type, value: i.value })}>
                  <td className="py-1.5 pr-2 font-mono text-orange-400">{i.type.toUpperCase()}</td>
                  <td className="py-1.5 pr-2 font-mono text-foreground/90 truncate max-w-[320px]">{defangIoc(i.type, i.value)}</td>
                  <td className="py-1.5 text-right"><span className="inline-flex items-center gap-1 text-cyan-300"><Crosshair className="w-2.5 h-2.5" />{i.session_count}</span></td>
                </tr>
              ))}
              {detail.aggregated_iocs.length === 0 && <tr><td colSpan={3} className="py-3 text-muted-foreground">No indicators across linked sessions.</td></tr>}
            </tbody>
          </table>
        </TabsContent>

        {/* Actors */}
        <TabsContent value="actors" className="flex-1 overflow-y-auto px-5 py-4 mt-0 data-[state=inactive]:hidden">
          <ul className="space-y-1">
            {detail.actors.map((a) => (
              <li key={a.id}>
                <button onClick={() => onSelectThreatActor(a.id)} className="w-full flex items-center gap-2 text-left px-2 py-1.5 rounded hover:bg-secondary/40 text-xs">
                  <Shield className="w-3.5 h-3.5 text-red-400/80" />
                  <span className="flex-1 truncate text-foreground hover:text-red-300">{a.name}</span>
                  <span className="text-[10px] text-muted-foreground/60">{a.session_count} session{a.session_count !== 1 ? 's' : ''}</span>
                  <ExternalLink className="w-3 h-3 text-muted-foreground/40" />
                </button>
              </li>
            ))}
            {detail.actors.length === 0 && <li className="text-xs text-muted-foreground">No attributed actors across linked sessions.</li>}
          </ul>
        </TabsContent>

        {/* Graph */}
        <TabsContent value="graph" className="flex-1 mt-0 data-[state=inactive]:hidden min-h-0">
          {graphLoading || !graph
            ? <div className="w-full h-full flex items-center justify-center text-xs text-muted-foreground"><Loader2 className="w-4 h-4 animate-spin mr-2" />Building graph…</div>
            : <LinkGraph data={graph} onSelectSession={onSelectSession} onSelectActor={onSelectThreatActor} onPivotIoc={(type, value) => setPivotIoc({ type, value })} />}
        </TabsContent>
      </Tabs>

      {pivotIoc && <IOCPivot type={pivotIoc.type} value={pivotIoc.value} onSelectSession={onSelectSession} onClose={() => setPivotIoc(null)} />}
      <ConfirmDialog
        open={confirmDelete} title="Delete case?"
        message={`"${c.name}" will be deleted. Linked sessions are NOT deleted — only their association with this case.`}
        confirmLabel="Delete" danger
        onConfirm={() => { void api.deleteCase(caseId).then(onCaseDeleted); setConfirmDelete(false); }}
        onCancel={() => setConfirmDelete(false)}
      />
    </main>
  );
}
