/**
 * ThreatActorView — full-panel detail view for a canonical threat actor record.
 * Shows: metadata, linked sessions, aggregated TTPs, aggregated IOCs.
 */
import { useState, useEffect, useCallback, useMemo } from 'react';
import {
  Shield, Link2, Unlink, Search, ChevronDown, ChevronRight,
  Pencil, Check, X, Trash2, Merge, AlertTriangle, Clock, ExternalLink,
} from 'lucide-react';
import { Button } from './ui/button';
import { Badge } from './ui/badge';
import { Tooltip, TooltipContent, TooltipTrigger } from './ui/tooltip';
import ConfirmDialog from './ConfirmDialog';
import { cn, formatTimestamp, severityDot } from '@/lib/utils';
import * as api from '@/lib/api';
import type { ThreatActorDetail, ThreatActorSummary, AggregatedTTP } from '@/types';

interface ThreatActorViewProps {
  actorId: string;
  onSelectSession: (sessionId: string) => void;
  onActorDeleted: () => void;
  onActorUpdated: () => void;
  allActors: ThreatActorSummary[];
}

export default function ThreatActorView({ actorId, onSelectSession, onActorDeleted, onActorUpdated, allActors }: ThreatActorViewProps) {
  const [detail, setDetail] = useState<ThreatActorDetail | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Edit state
  const [editing, setEditing] = useState(false);
  const [editName, setEditName] = useState('');
  const [editDescription, setEditDescription] = useState('');

  // Link session
  const [showLinkSearch, setShowLinkSearch] = useState(false);
  const [linkSearchQuery, setLinkSearchQuery] = useState('');
  const [availableSessions, setAvailableSessions] = useState<Array<{ id: string; name: string; severity: string | null; audience: string | null; created_at: number }>>([]);
  const [selectedLinkSessions, setSelectedLinkSessions] = useState<Set<string>>(new Set());

  // Merge
  const [showMergeModal, setShowMergeModal] = useState(false);

  // Expanded TTP rows
  const [expandedTtps, setExpandedTtps] = useState<Set<string>>(new Set());

  const loadDetail = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await api.fetchThreatActorDetail(actorId);
      setDetail({ ...data.actor, sessions: data.sessions, aggregated_ttps: data.aggregated_ttps, aggregated_iocs: data.aggregated_iocs });
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Failed to load');
    } finally {
      setLoading(false);
    }
  }, [actorId]);

  useEffect(() => { loadDetail(); }, [loadDetail]);

  // Search available sessions for linking
  useEffect(() => {
    if (!showLinkSearch) return;
    const timer = setTimeout(async () => {
      try {
        const sessions = await api.fetchAvailableSessions(actorId, linkSearchQuery || undefined);
        setAvailableSessions(sessions);
      } catch { /* ignore */ }
    }, 300);
    return () => clearTimeout(timer);
  }, [showLinkSearch, linkSearchQuery, actorId]);

  const handleSaveEdit = async () => {
    if (!detail) return;
    try {
      await api.updateThreatActor(actorId, { name: editName.trim() || detail.name, description: editDescription });
      setEditing(false);
      loadDetail();
      onActorUpdated();
    } catch { /* ignore */ }
  };

  const handleUnlink = async (sessionId: string) => {
    try {
      await api.unlinkSessionFromActor(actorId, sessionId);
      loadDetail();
      onActorUpdated();
    } catch { /* ignore */ }
  };

  const handleLink = async (sessionId: string) => {
    try {
      await api.linkSessionToActor(actorId, sessionId);
      setShowLinkSearch(false);
      setLinkSearchQuery('');
      setSelectedLinkSessions(new Set());
      loadDetail();
      onActorUpdated();
    } catch { /* ignore */ }
  };

  const handleBulkLink = async () => {
    if (selectedLinkSessions.size === 0) return;
    try {
      await api.bulkLinkSessions(actorId, Array.from(selectedLinkSessions), true);
      setShowLinkSearch(false);
      setLinkSearchQuery('');
      setSelectedLinkSessions(new Set());
      loadDetail();
      onActorUpdated();
    } catch { /* ignore */ }
  };

  const toggleLinkSession = (id: string) => {
    setSelectedLinkSessions((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  // Styled confirmations replacing window.confirm
  const [confirmAction, setConfirmAction] = useState<{ type: 'merge'; targetId: string } | { type: 'delete' } | null>(null);

  const handleMerge = async (targetId: string) => {
    if (!detail) return;
    try {
      await api.mergeThreatActors(actorId, targetId);
      setShowMergeModal(false);
      onActorDeleted();
    } catch { /* ignore */ }
  };

  const handleDelete = async () => {
    if (!detail) return;
    try {
      await api.deleteThreatActor(actorId);
      onActorDeleted();
    } catch { /* ignore */ }
  };

  const toggleTtp = (key: string) => {
    setExpandedTtps((prev) => {
      const next = new Set(prev);
      if (next.has(key)) next.delete(key); else next.add(key);
      return next;
    });
  };

  // Confidence badge color
  const confColor = (conf: string | null) => {
    switch (conf) {
      case 'High': return 'bg-red-500/20 text-red-400 border-red-500/30';
      case 'Medium': return 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30';
      case 'Low': return 'bg-green-500/20 text-green-400 border-green-500/30';
      default: return 'bg-gray-500/20 text-gray-400 border-gray-500/30';
    }
  };

  // Group IOCs by type for display
  type AggIOC = ThreatActorDetail['aggregated_iocs'][number];
  const iocsByType = useMemo(() => {
    if (!detail) return new Map<string, AggIOC[]>();
    const map = new Map<string, AggIOC[]>();
    for (const ioc of detail.aggregated_iocs) {
      const list = map.get(ioc.type) || [];
      list.push(ioc);
      map.set(ioc.type, list);
    }
    return map;
  }, [detail]);

  if (loading) {
    return (
      <div className="flex-1 flex items-center justify-center">
        <div className="text-muted-foreground text-sm animate-pulse">Loading threat actor...</div>
      </div>
    );
  }

  if (error || !detail) {
    return (
      <div className="flex-1 flex items-center justify-center">
        <div className="text-red-400 text-sm">{error || 'Threat actor not found'}</div>
      </div>
    );
  }

  const isUnattributed = detail.name === 'Unattributed';
  const mergeTargets = allActors.filter((a) => a.id !== actorId && a.name !== 'Unattributed');

  return (
    <div className="flex-1 flex flex-col h-full overflow-hidden bg-background">
      {/* Header */}
      <div className="border-b border-border px-6 py-4 flex-shrink-0">
        <div className="flex items-start justify-between gap-4">
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-2 mb-1">
              <Shield className={cn('w-5 h-5 flex-shrink-0', isUnattributed ? 'text-muted-foreground/50' : 'text-red-400')} />
              {editing ? (
                <input
                  value={editName}
                  onChange={(e) => setEditName(e.target.value)}
                  className="bg-navy-950 border border-cyan-500/50 rounded px-2 py-1 text-lg font-bold text-foreground focus:outline-none focus:ring-1 focus:ring-cyan-500 flex-1"
                  autoFocus
                  onKeyDown={(e) => { if (e.key === 'Enter') handleSaveEdit(); if (e.key === 'Escape') setEditing(false); }}
                />
              ) : (
                <h1 className="text-lg font-bold text-foreground truncate">{detail.name}</h1>
              )}
              {!editing && !isUnattributed && (
                <button
                  onClick={() => { setEditing(true); setEditName(detail.name); setEditDescription(detail.description); }}
                  className="text-muted-foreground/50 hover:text-foreground transition-colors p-1"
                  title="Edit actor"
                >
                  <Pencil className="w-3.5 h-3.5" />
                </button>
              )}
              {editing && (
                <div className="flex gap-1">
                  <button onClick={handleSaveEdit} className="text-green-400 hover:text-green-300 p-1"><Check className="w-4 h-4" /></button>
                  <button onClick={() => setEditing(false)} className="text-muted-foreground hover:text-foreground p-1"><X className="w-4 h-4" /></button>
                </div>
              )}
            </div>

            {/* Aliases */}
            {detail.aliases.length > 0 && (
              <div className="flex items-center gap-1.5 flex-wrap mb-2">
                <span className="text-[10px] text-muted-foreground uppercase">aka</span>
                {detail.aliases.map((alias, i) => (
                  <Badge key={i} variant="secondary" className="text-[10px] px-1.5 py-0 h-4">{alias}</Badge>
                ))}
              </div>
            )}

            {/* Metadata row */}
            <div className="flex items-center gap-3 flex-wrap text-xs">
              {detail.attribution_confidence && (
                <span className={cn('px-2 py-0.5 rounded border text-[10px] font-medium', confColor(detail.attribution_confidence))}>
                  {detail.attribution_confidence} Attribution
                </span>
              )}
              {detail.motivation && (
                <span className="text-muted-foreground">
                  Motivation: <span className="text-foreground">{detail.motivation}</span>
                </span>
              )}
              {detail.intrusion_set && (
                <span className="text-muted-foreground">
                  Intrusion Set: <span className="text-cyan-400">{detail.intrusion_set}</span>
                </span>
              )}
              {detail.campaign_name && (
                <span className="text-muted-foreground">
                  Campaign: <span className="text-yellow-400">{detail.campaign_name}</span>
                </span>
              )}
            </div>

            {/* Malware families */}
            {detail.malware_families.length > 0 && (
              <div className="flex items-center gap-1.5 flex-wrap mt-1.5">
                <span className="text-[10px] text-muted-foreground uppercase">Malware</span>
                {detail.malware_families.map((mf, i) => (
                  <Badge key={i} variant="secondary" className="text-[10px] px-1.5 py-0 h-4 bg-orange-500/10 text-orange-400 border-orange-500/20">{mf}</Badge>
                ))}
              </div>
            )}

            {/* Description (editable) */}
            {editing ? (
              <textarea
                value={editDescription}
                onChange={(e) => setEditDescription(e.target.value)}
                placeholder="Add a description..."
                rows={2}
                className="mt-2 w-full bg-navy-950 border border-border rounded px-2 py-1 text-xs text-foreground placeholder:text-muted-foreground/40 focus:outline-none focus:ring-1 focus:ring-cyan-500/50 resize-none"
              />
            ) : detail.description ? (
              <p className="mt-1.5 text-xs text-muted-foreground">{detail.description}</p>
            ) : null}
          </div>

          {/* Actions */}
          <div className="flex items-center gap-2 flex-shrink-0">
            {!isUnattributed && mergeTargets.length > 0 && (
              <Tooltip>
                <TooltipTrigger asChild>
                  <Button variant="ghost" size="sm" className="h-7 px-2 text-xs" onClick={() => setShowMergeModal(true)}>
                    <Merge className="w-3.5 h-3.5 mr-1" />
                    Merge
                  </Button>
                </TooltipTrigger>
                <TooltipContent>Merge into another actor</TooltipContent>
              </Tooltip>
            )}
            {!isUnattributed && (
            <Tooltip>
              <TooltipTrigger asChild>
                <Button variant="ghost" size="sm" className="h-7 px-2 text-xs text-red-400/70 hover:text-red-400" onClick={() => setConfirmAction({ type: 'delete' })}>
                  <Trash2 className="w-3.5 h-3.5" />
                </Button>
              </TooltipTrigger>
              <TooltipContent>Delete actor</TooltipContent>
            </Tooltip>
            )}
          </div>
        </div>
      </div>

      {/* Content */}
      <div className="flex-1 overflow-y-auto px-6 py-4 space-y-6">
        {/* Linked Sessions */}
        <section>
          <div className="flex items-center justify-between mb-3">
            <h2 className="text-sm font-semibold text-foreground flex items-center gap-2">
              <Link2 className="w-4 h-4 text-muted-foreground" />
              Linked Sessions ({detail.sessions.length})
            </h2>
            <Button
              variant="ghost"
              size="sm"
              className="h-7 px-2 text-xs text-cyan-400 hover:text-cyan-300"
              onClick={() => { setShowLinkSearch(!showLinkSearch); setLinkSearchQuery(''); setSelectedLinkSessions(new Set()); }}
            >
              {showLinkSearch ? <X className="w-3.5 h-3.5 mr-1" /> : <Link2 className="w-3.5 h-3.5 mr-1" />}
              {showLinkSearch ? 'Cancel' : 'Link Sessions'}
            </Button>
          </div>

          {/* Link search dropdown */}
          {showLinkSearch && (
            <div className="mb-3 bg-navy-900 border border-border rounded-lg p-3">
              <div className="relative mb-2">
                <Search className="absolute left-2 top-1/2 -translate-y-1/2 w-3 h-3 text-muted-foreground/50" />
                <input
                  type="text"
                  value={linkSearchQuery}
                  onChange={(e) => setLinkSearchQuery(e.target.value)}
                  placeholder="Search sessions to link..."
                  className="w-full bg-secondary/50 border border-border rounded-md pl-7 pr-3 py-1.5 text-xs text-foreground placeholder:text-muted-foreground/40 focus:outline-none focus:ring-1 focus:ring-cyan-500/50"
                  autoFocus
                />
              </div>
              {availableSessions.length === 0 ? (
                <p className="text-[10px] text-muted-foreground/60 text-center py-2">No available sessions found</p>
              ) : (
                <>
                  <div className="space-y-1 max-h-40 overflow-y-auto">
                    {availableSessions.map((s) => (
                      <button
                        key={s.id}
                        onClick={() => toggleLinkSession(s.id)}
                        className={cn(
                          'w-full text-left px-2 py-1.5 rounded transition-colors flex items-center gap-2',
                          selectedLinkSessions.has(s.id) ? 'bg-cyan-500/10' : 'hover:bg-secondary/50',
                        )}
                      >
                        <div className={cn(
                          'w-3.5 h-3.5 rounded border flex-shrink-0 flex items-center justify-center transition-colors',
                          selectedLinkSessions.has(s.id) ? 'bg-cyan-500 border-cyan-500' : 'border-border',
                        )}>
                          {selectedLinkSessions.has(s.id) && <span className="text-[8px] text-white font-bold">✓</span>}
                        </div>
                        <span className="text-xs text-foreground truncate flex-1">{s.name}</span>
                        <span className="text-[10px] text-muted-foreground flex-shrink-0">{formatTimestamp(s.created_at)}</span>
                      </button>
                    ))}
                  </div>
                  {selectedLinkSessions.size > 0 && (
                    <div className="mt-2 flex items-center justify-between">
                      <span className="text-[10px] text-muted-foreground">{selectedLinkSessions.size} selected</span>
                      <Button
                        size="sm"
                        className="h-6 px-2 text-[10px] bg-cyan-500/20 text-cyan-300 hover:bg-cyan-500/30 border border-cyan-500/30"
                        onClick={handleBulkLink}
                      >
                        <Link2 className="w-3 h-3 mr-1" />
                        Link Selected ({selectedLinkSessions.size})
                      </Button>
                    </div>
                  )}
                </>
              )}
            </div>
          )}

          {detail.sessions.length === 0 ? (
            <p className="text-xs text-muted-foreground/60 text-center py-4">No sessions linked yet</p>
          ) : (
            <div className="space-y-1">
              {detail.sessions.map((s) => (
                <div
                  key={s.id}
                  className="flex items-center gap-3 px-3 py-2 rounded-md hover:bg-secondary/50 transition-colors group border border-transparent hover:border-border"
                >
                  <button
                    onClick={() => onSelectSession(s.id)}
                    className="flex-1 min-w-0 text-left flex items-center gap-2"
                  >
                    <ExternalLink className="w-3 h-3 text-muted-foreground/40 flex-shrink-0" />
                    <span className="text-xs font-medium text-foreground truncate">{s.name}</span>
                    {s.severity && (
                      <div className="flex items-center gap-1 flex-shrink-0">
                        <div className={cn('w-1.5 h-1.5 rounded-full', severityDot(s.severity))} />
                        <span className="text-[9px] text-muted-foreground uppercase">{s.severity}</span>
                      </div>
                    )}
                  </button>
                  <span className="text-[10px] text-muted-foreground flex-shrink-0 flex items-center gap-1">
                    <Clock className="w-3 h-3" />
                    {formatTimestamp(s.created_at)}
                  </span>
                  <Badge variant="secondary" className="text-[9px] px-1 py-0 h-4 flex-shrink-0">
                    {s.link_type}
                  </Badge>
                  <button
                    onClick={() => handleUnlink(s.id)}
                    className="text-muted-foreground/0 group-hover:text-muted-foreground/50 hover:!text-red-400 transition-all p-1 flex-shrink-0"
                    title="Unlink session"
                  >
                    <Unlink className="w-3 h-3" />
                  </button>
                </div>
              ))}
            </div>
          )}
        </section>

        {/* Aggregated TTPs */}
        {detail.aggregated_ttps.length > 0 && (
          <section>
            <h2 className="text-sm font-semibold text-foreground mb-3 flex items-center gap-2">
              <AlertTriangle className="w-4 h-4 text-orange-400" />
              Aggregated TTPs ({detail.aggregated_ttps.length})
            </h2>
            <div className="border border-border rounded-lg overflow-hidden">
              <table className="w-full text-xs">
                <thead>
                  <tr className="bg-secondary/30 border-b border-border">
                    <th className="text-left px-3 py-2 text-muted-foreground font-medium w-8"></th>
                    <th className="text-left px-3 py-2 text-muted-foreground font-medium">Technique</th>
                    <th className="text-left px-3 py-2 text-muted-foreground font-medium">Tactic</th>
                    <th className="text-center px-3 py-2 text-muted-foreground font-medium">Sessions</th>
                  </tr>
                </thead>
                <tbody>
                  {detail.aggregated_ttps.map((ttp: AggregatedTTP) => (
                    <TTPRow
                      key={ttp.technique_id}
                      ttp={ttp}
                      expanded={expandedTtps.has(ttp.technique_id)}
                      onToggle={() => toggleTtp(ttp.technique_id)}
                      onSelectSession={onSelectSession}
                    />
                  ))}
                </tbody>
              </table>
            </div>
          </section>
        )}

        {/* Aggregated IOCs */}
        {detail.aggregated_iocs.length > 0 && (
          <section>
            <h2 className="text-sm font-semibold text-foreground mb-3 flex items-center gap-2">
              <Shield className="w-4 h-4 text-muted-foreground" />
              Aggregated IOCs ({detail.aggregated_iocs.length})
            </h2>
            <div className="space-y-4">
              {Array.from(iocsByType.entries()).map(([type, iocs]: [string, AggIOC[]]) => (
                <div key={type}>
                  <h3 className="text-[10px] text-muted-foreground uppercase tracking-widest mb-1.5 font-semibold">
                    {type.toUpperCase()} ({iocs.length})
                  </h3>
                  <div className="border border-border rounded-lg overflow-hidden">
                    <table className="w-full text-xs">
                      <thead>
                        <tr className="bg-secondary/30 border-b border-border">
                          <th className="text-left px-3 py-1.5 text-muted-foreground font-medium">Value</th>
                          <th className="text-left px-3 py-1.5 text-muted-foreground font-medium">Context</th>
                          <th className="text-center px-3 py-1.5 text-muted-foreground font-medium">Confidence</th>
                          <th className="text-center px-3 py-1.5 text-muted-foreground font-medium">Sessions</th>
                          <th className="text-left px-3 py-1.5 text-muted-foreground font-medium">First Seen</th>
                          <th className="text-left px-3 py-1.5 text-muted-foreground font-medium">Last Seen</th>
                        </tr>
                      </thead>
                      <tbody>
                        {iocs.map((ioc, idx) => (
                          <tr key={idx} className="border-b border-border/50 last:border-b-0">
                            <td className="px-3 py-1.5 font-mono text-foreground break-all">{ioc.value}</td>
                            <td className="px-3 py-1.5 text-muted-foreground max-w-[200px] truncate">{ioc.context}</td>
                            <td className="px-3 py-1.5 text-center">
                              <span className={cn('px-1.5 py-0.5 rounded text-[10px]', confColor(ioc.confidence))}>
                                {ioc.confidence}
                              </span>
                            </td>
                            <td className="px-3 py-1.5 text-center">
                              <Badge variant="secondary" className="text-[10px] px-1.5 py-0 h-4">{ioc.session_count}</Badge>
                            </td>
                            <td className="px-3 py-1.5 text-muted-foreground">{formatTimestamp(ioc.first_seen)}</td>
                            <td className="px-3 py-1.5 text-muted-foreground">{ioc.first_seen !== ioc.last_seen ? formatTimestamp(ioc.last_seen) : '—'}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
              ))}
            </div>
          </section>
        )}

        {/* Empty state */}
        {detail.aggregated_ttps.length === 0 && detail.aggregated_iocs.length === 0 && detail.sessions.length === 0 && (
          <div className="text-center py-12">
            <Shield className="w-12 h-12 text-muted-foreground/20 mx-auto mb-3" />
            <p className="text-sm text-muted-foreground">No sessions linked to this threat actor yet.</p>
            <p className="text-xs text-muted-foreground/60 mt-1">Link sessions manually, or run an analysis that attributes this actor.</p>
          </div>
        )}
      </div>

      {/* Merge Modal */}
      {showMergeModal && (
        <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50" onClick={() => setShowMergeModal(false)}>
          <div className="bg-navy-900 border border-border rounded-lg shadow-xl w-96 max-h-[60vh] overflow-hidden" onClick={(e) => e.stopPropagation()}>
            <div className="px-4 py-3 border-b border-border">
              <h3 className="text-sm font-semibold text-foreground">Merge "{detail.name}" into...</h3>
              <p className="text-[10px] text-muted-foreground mt-0.5">All linked sessions and aliases will be transferred to the target actor.</p>
            </div>
            <div className="p-3 space-y-1 max-h-80 overflow-y-auto">
              {mergeTargets.map((target) => (
                <button
                  key={target.id}
                  onClick={() => setConfirmAction({ type: 'merge', targetId: target.id })}
                  className="w-full text-left px-3 py-2 rounded hover:bg-secondary/50 transition-colors flex items-center justify-between"
                >
                  <div className="min-w-0">
                    <div className="text-xs font-medium text-foreground truncate">{target.name}</div>
                    <div className="text-[10px] text-muted-foreground">{target.session_count} session{target.session_count !== 1 ? 's' : ''}</div>
                  </div>
                  <Merge className="w-3.5 h-3.5 text-muted-foreground/40 flex-shrink-0" />
                </button>
              ))}
              {mergeTargets.length === 0 && (
                <p className="text-xs text-muted-foreground/60 text-center py-4">No other actors to merge with</p>
              )}
            </div>
            <div className="px-4 py-3 border-t border-border flex justify-end">
              <Button variant="ghost" size="sm" className="h-7 text-xs" onClick={() => setShowMergeModal(false)}>Cancel</Button>
            </div>
          </div>
        </div>
      )}

      {/* Destructive action confirmations */}
      <ConfirmDialog
        open={!!confirmAction}
        title={confirmAction?.type === 'merge' ? 'Merge threat actors?' : 'Delete threat actor?'}
        message={confirmAction?.type === 'merge'
          ? `"${detail?.name ?? ''}" will be merged into the selected actor. Its sessions, aliases, and malware families move to the target, then this actor is removed. This cannot be undone.`
          : `Delete threat actor "${detail?.name ?? ''}"? All session links will be removed. This cannot be undone.`}
        confirmLabel={confirmAction?.type === 'merge' ? 'Merge' : 'Delete'}
        danger
        onConfirm={() => {
          if (confirmAction?.type === 'merge') handleMerge(confirmAction.targetId);
          else if (confirmAction?.type === 'delete') handleDelete();
          setConfirmAction(null);
        }}
        onCancel={() => setConfirmAction(null)}
      />
    </div>
  );
}

// ── TTP expandable row ──────────────────────────────────────────────────────

function TTPRow({ ttp, expanded, onToggle, onSelectSession }: {
  ttp: AggregatedTTP;
  expanded: boolean;
  onToggle: () => void;
  onSelectSession: (id: string) => void;
}) {
  return (
    <>
      <tr className="border-b border-border/50 hover:bg-secondary/30 transition-colors cursor-pointer" onClick={onToggle}>
        <td className="px-3 py-2 text-muted-foreground">
          {expanded ? <ChevronDown className="w-3 h-3" /> : <ChevronRight className="w-3 h-3" />}
        </td>
        <td className="px-3 py-2">
          <span className="font-mono text-cyan-400">{ttp.technique_id}</span>
          <span className="text-foreground ml-2">{ttp.technique_name}</span>
        </td>
        <td className="px-3 py-2 text-muted-foreground">{ttp.tactic}</td>
        <td className="px-3 py-2 text-center">
          <Badge variant="secondary" className="text-[10px] px-1.5 py-0 h-4">{ttp.session_count}</Badge>
        </td>
      </tr>
      {expanded && ttp.sessions.map((s) => (
        <tr key={s.id} className="bg-secondary/10 border-b border-border/30">
          <td></td>
          <td colSpan={3} className="px-3 py-1.5">
            <button
              onClick={(e) => { e.stopPropagation(); onSelectSession(s.id); }}
              className="text-xs text-cyan-400/80 hover:text-cyan-400 hover:underline transition-colors flex items-center gap-1"
            >
              <ExternalLink className="w-3 h-3" />
              {s.name}
            </button>
          </td>
        </tr>
      ))}
    </>
  );
}
