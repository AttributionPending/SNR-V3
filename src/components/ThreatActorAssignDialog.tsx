/**
 * ThreatActorAssignDialog — reusable modal for assigning a threat actor to session(s).
 * Supports: picking an existing actor, creating a new one, single or bulk assignment.
 */
import { useState, useEffect, useCallback, useRef } from 'react';
import {
  X, Search, Shield, Plus, ChevronDown, ChevronRight, AlertTriangle,
} from 'lucide-react';
import { Button } from './ui/button';
import { Badge } from './ui/badge';
import { cn } from '@/lib/utils';
import * as api from '@/lib/api';
import type { ThreatActorSummary } from '@/types';

interface ThreatActorAssignDialogProps {
  open: boolean;
  onClose: () => void;
  /** Session IDs to assign. Empty = create-only mode. */
  sessionIds: string[];
  actors: ThreatActorSummary[];
  /** Called after a successful assign/create. Parent should refresh actors + sessions. */
  onAssigned: () => void;
  /** 'assign' for single session, 'bulk' for multi, 'create' for actor creation only */
  mode: 'assign' | 'bulk' | 'create';
}

const CONFIDENCE_OPTIONS = ['High', 'Medium', 'Low'] as const;
const MOTIVATION_OPTIONS = [
  'Financial', 'Espionage', 'Hacktivism', 'Sabotage / Destruction',
  'State-Sponsored', 'Cyber Crime', 'Insider Threat', 'Unknown',
] as const;

export default function ThreatActorAssignDialog({
  open, onClose, sessionIds, actors, onAssigned, mode,
}: ThreatActorAssignDialogProps) {
  // Selection state
  const [selectedActorId, setSelectedActorId] = useState<string | null>(null);
  const [searchQuery, setSearchQuery] = useState('');

  // Create new state
  const [showCreate, setShowCreate] = useState(mode === 'create');
  const [newName, setNewName] = useState('');
  const [newAliases, setNewAliases] = useState('');
  const [newMotivation, setNewMotivation] = useState('');
  const [newConfidence, setNewConfidence] = useState('');
  const [newIntrusionSet, setNewIntrusionSet] = useState('');
  const [newCampaign, setNewCampaign] = useState('');
  const [newMalware, setNewMalware] = useState('');
  const [newDescription, setNewDescription] = useState('');

  // UI state
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const searchRef = useRef<HTMLInputElement>(null);

  // Reset state when dialog opens
  useEffect(() => {
    if (open) {
      setSelectedActorId(null);
      setSearchQuery('');
      setShowCreate(mode === 'create');
      setNewName('');
      setNewAliases('');
      setNewMotivation('');
      setNewConfidence('');
      setNewIntrusionSet('');
      setNewCampaign('');
      setNewMalware('');
      setNewDescription('');
      setError(null);
      setSubmitting(false);
      setTimeout(() => searchRef.current?.focus(), 100);
    }
  }, [open, mode]);

  // Filter actors by search
  const filteredActors = actors.filter((a) => {
    if (a.name === 'Unattributed') return false;
    if (!searchQuery.trim()) return true;
    const q = searchQuery.trim().toLowerCase();
    return (
      a.name.toLowerCase().includes(q) ||
      a.aliases.some((al) => al.toLowerCase().includes(q)) ||
      (a.intrusion_set && a.intrusion_set.toLowerCase().includes(q))
    );
  });

  const handleSelectActor = useCallback((actorId: string) => {
    setSelectedActorId((prev) => (prev === actorId ? null : actorId));
    setShowCreate(false);
    setError(null);
  }, []);

  const handleToggleCreate = useCallback(() => {
    setShowCreate((prev) => !prev);
    setSelectedActorId(null);
    setError(null);
  }, []);

  const handleSubmit = useCallback(async () => {
    setError(null);
    setSubmitting(true);

    try {
      let actorId = selectedActorId;

      // If creating a new actor
      if (showCreate) {
        if (!newName.trim()) {
          setError('Actor name is required');
          setSubmitting(false);
          return;
        }

        const aliases = newAliases.split(',').map((a) => a.trim()).filter(Boolean);
        const malware = newMalware.split(',').map((m) => m.trim()).filter(Boolean);

        const { actor } = await api.createThreatActor({
          name: newName.trim(),
          aliases: aliases.length > 0 ? aliases : undefined,
          motivation: newMotivation || null,
          attribution_confidence: newConfidence || null,
          intrusion_set: newIntrusionSet.trim() || null,
          campaign_name: newCampaign.trim() || null,
          malware_families: malware.length > 0 ? malware : undefined,
          description: newDescription.trim() || undefined,
        });

        actorId = actor.id;
      }

      // If we have sessions to assign
      if (sessionIds.length > 0 && actorId) {
        if (mode === 'assign' && sessionIds.length === 1) {
          // Single session assignment — use dedicated endpoint (handles reassignment)
          await api.assignSessionThreatActor(sessionIds[0], actorId);
        } else {
          // Bulk link — remove existing assignments so sessions move to new actor
          await api.bulkLinkSessions(actorId, sessionIds, true);
        }
      }

      onAssigned();
      onClose();
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Operation failed');
    } finally {
      setSubmitting(false);
    }
  }, [selectedActorId, showCreate, newName, newAliases, newMotivation, newConfidence, newIntrusionSet, newCampaign, newMalware, newDescription, sessionIds, mode, onAssigned, onClose]);

  const handleUnassign = useCallback(async () => {
    if (sessionIds.length !== 1) return;
    setError(null);
    setSubmitting(true);
    try {
      await api.assignSessionThreatActor(sessionIds[0], null);
      onAssigned();
      onClose();
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Failed to unassign');
    } finally {
      setSubmitting(false);
    }
  }, [sessionIds, onAssigned, onClose]);

  if (!open) return null;

  const canSubmit = showCreate ? newName.trim().length > 0 : selectedActorId !== null;
  const submitLabel = showCreate
    ? sessionIds.length > 0 ? `Create & Assign (${sessionIds.length})` : 'Create Actor'
    : sessionIds.length > 1 ? `Assign to ${sessionIds.length} Sessions` : 'Assign';

  const confidenceColor = (c: string) =>
    c === 'High' ? 'text-red-400 bg-red-500/10 border-red-500/20'
    : c === 'Medium' ? 'text-yellow-400 bg-yellow-500/10 border-yellow-500/20'
    : 'text-green-400 bg-green-500/10 border-green-500/20';

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/70 backdrop-blur-sm"
      onClick={onClose}
    >
      <div
        className="bg-navy-950 border border-border rounded-lg shadow-2xl w-full max-w-lg max-h-[80vh] flex flex-col"
        onClick={(e) => e.stopPropagation()}
      >
        {/* Header */}
        <div className="flex items-center justify-between px-5 py-3 border-b border-border flex-shrink-0">
          <div className="flex items-center gap-2">
            <Shield className="w-4 h-4 text-red-400" />
            <h2 className="text-sm font-semibold text-foreground">
              {mode === 'create' ? 'Create Threat Actor' : 'Assign Threat Actor'}
            </h2>
            {sessionIds.length > 1 && (
              <Badge variant="secondary" className="text-[10px]">{sessionIds.length} sessions</Badge>
            )}
          </div>
          <button onClick={onClose} className="text-muted-foreground/50 hover:text-foreground transition-colors">
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Body */}
        <div className="flex-1 overflow-y-auto px-5 py-3 space-y-3 min-h-0">
          {/* Search existing actors */}
          {mode !== 'create' && (
            <>
              <div className="relative">
                <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-muted-foreground/50" />
                <input
                  ref={searchRef}
                  type="text"
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  placeholder="Search existing actors..."
                  className="w-full bg-secondary/50 border border-border rounded-md pl-8 pr-3 py-1.5 text-xs text-foreground placeholder:text-muted-foreground/40 focus:outline-none focus:ring-1 focus:ring-cyan-500/50"
                />
              </div>

              {/* Actors list */}
              <div className="max-h-44 overflow-y-auto border border-border rounded-md divide-y divide-border">
                {filteredActors.length === 0 ? (
                  <div className="px-3 py-4 text-xs text-muted-foreground/60 text-center">
                    {searchQuery ? 'No matching actors' : 'No threat actors yet'}
                  </div>
                ) : (
                  filteredActors.map((actor) => (
                    <button
                      key={actor.id}
                      onClick={() => handleSelectActor(actor.id)}
                      className={cn(
                        'w-full flex items-center gap-3 px-3 py-2 text-left transition-colors',
                        selectedActorId === actor.id
                          ? 'bg-red-500/10 border-l-2 border-l-red-400'
                          : 'hover:bg-secondary/50 border-l-2 border-l-transparent',
                      )}
                    >
                      <div className={cn(
                        'w-3.5 h-3.5 rounded-full border-2 flex-shrink-0 transition-colors',
                        selectedActorId === actor.id
                          ? 'border-red-400 bg-red-400'
                          : 'border-muted-foreground/30',
                      )} />
                      <div className="flex-1 min-w-0">
                        <div className="text-xs font-medium text-foreground truncate">{actor.name}</div>
                        <div className="text-[10px] text-muted-foreground/60 truncate">
                          {actor.session_count} session{actor.session_count !== 1 ? 's' : ''}
                          {actor.intrusion_set && <> &middot; {actor.intrusion_set}</>}
                        </div>
                      </div>
                      {actor.attribution_confidence && (
                        <span className={cn(
                          'text-[9px] px-1.5 py-0.5 rounded border flex-shrink-0',
                          confidenceColor(actor.attribution_confidence),
                        )}>
                          {actor.attribution_confidence}
                        </span>
                      )}
                    </button>
                  ))
                )}
              </div>

              {/* Divider */}
              <div className="flex items-center gap-2">
                <div className="flex-1 border-t border-border" />
                <span className="text-[10px] text-muted-foreground/40 uppercase tracking-wider">or</span>
                <div className="flex-1 border-t border-border" />
              </div>
            </>
          )}

          {/* Create new section */}
          <button
            onClick={handleToggleCreate}
            className={cn(
              'w-full flex items-center gap-2 px-3 py-2 rounded-md border transition-colors text-left',
              showCreate
                ? 'bg-cyan-500/10 border-cyan-500/30 text-cyan-400'
                : 'border-dashed border-border text-muted-foreground hover:text-foreground hover:border-border/80',
            )}
          >
            {showCreate ? <ChevronDown className="w-3.5 h-3.5" /> : <ChevronRight className="w-3.5 h-3.5" />}
            <Plus className="w-3.5 h-3.5" />
            <span className="text-xs font-medium">Create New Threat Actor</span>
          </button>

          {showCreate && (
            <div className="space-y-2.5 pl-1 border-l-2 border-cyan-500/20 ml-2">
              {/* Name */}
              <div>
                <label className="text-[10px] text-muted-foreground/60 uppercase tracking-wider mb-1 block">Name *</label>
                <input
                  type="text"
                  value={newName}
                  onChange={(e) => setNewName(e.target.value)}
                  placeholder="e.g. APT29, Lazarus Group..."
                  className="w-full bg-secondary/50 border border-border rounded px-2.5 py-1.5 text-xs text-foreground placeholder:text-muted-foreground/30 focus:outline-none focus:ring-1 focus:ring-cyan-500/50"
                  maxLength={100}
                  autoFocus={mode === 'create'}
                />
              </div>

              {/* Aliases */}
              <div>
                <label className="text-[10px] text-muted-foreground/60 uppercase tracking-wider mb-1 block">Aliases (comma-separated)</label>
                <input
                  type="text"
                  value={newAliases}
                  onChange={(e) => setNewAliases(e.target.value)}
                  placeholder="e.g. Cozy Bear, The Dukes..."
                  className="w-full bg-secondary/50 border border-border rounded px-2.5 py-1.5 text-xs text-foreground placeholder:text-muted-foreground/30 focus:outline-none focus:ring-1 focus:ring-cyan-500/50"
                />
              </div>

              {/* Motivation + Confidence row */}
              <div className="grid grid-cols-2 gap-2">
                <div>
                  <label className="text-[10px] text-muted-foreground/60 uppercase tracking-wider mb-1 block">Motivation</label>
                  <select
                    value={newMotivation}
                    onChange={(e) => setNewMotivation(e.target.value)}
                    className="w-full bg-secondary/50 border border-border rounded px-2 py-1.5 text-xs text-foreground focus:outline-none focus:ring-1 focus:ring-cyan-500/50"
                  >
                    <option value="">Select...</option>
                    {MOTIVATION_OPTIONS.map((m) => <option key={m} value={m}>{m}</option>)}
                  </select>
                </div>
                <div>
                  <label className="text-[10px] text-muted-foreground/60 uppercase tracking-wider mb-1 block">Confidence</label>
                  <select
                    value={newConfidence}
                    onChange={(e) => setNewConfidence(e.target.value)}
                    className="w-full bg-secondary/50 border border-border rounded px-2 py-1.5 text-xs text-foreground focus:outline-none focus:ring-1 focus:ring-cyan-500/50"
                  >
                    <option value="">Select...</option>
                    {CONFIDENCE_OPTIONS.map((c) => <option key={c} value={c}>{c}</option>)}
                  </select>
                </div>
              </div>

              {/* Intrusion Set + Campaign row */}
              <div className="grid grid-cols-2 gap-2">
                <div>
                  <label className="text-[10px] text-muted-foreground/60 uppercase tracking-wider mb-1 block">Intrusion Set</label>
                  <input
                    type="text"
                    value={newIntrusionSet}
                    onChange={(e) => setNewIntrusionSet(e.target.value)}
                    placeholder="e.g. APT29"
                    className="w-full bg-secondary/50 border border-border rounded px-2.5 py-1.5 text-xs text-foreground placeholder:text-muted-foreground/30 focus:outline-none focus:ring-1 focus:ring-cyan-500/50"
                  />
                </div>
                <div>
                  <label className="text-[10px] text-muted-foreground/60 uppercase tracking-wider mb-1 block">Campaign</label>
                  <input
                    type="text"
                    value={newCampaign}
                    onChange={(e) => setNewCampaign(e.target.value)}
                    placeholder="e.g. SolarWinds"
                    className="w-full bg-secondary/50 border border-border rounded px-2.5 py-1.5 text-xs text-foreground placeholder:text-muted-foreground/30 focus:outline-none focus:ring-1 focus:ring-cyan-500/50"
                  />
                </div>
              </div>

              {/* Malware families */}
              <div>
                <label className="text-[10px] text-muted-foreground/60 uppercase tracking-wider mb-1 block">Malware Families (comma-separated)</label>
                <input
                  type="text"
                  value={newMalware}
                  onChange={(e) => setNewMalware(e.target.value)}
                  placeholder="e.g. Cobalt Strike, Mimikatz..."
                  className="w-full bg-secondary/50 border border-border rounded px-2.5 py-1.5 text-xs text-foreground placeholder:text-muted-foreground/30 focus:outline-none focus:ring-1 focus:ring-cyan-500/50"
                />
              </div>

              {/* Description */}
              <div>
                <label className="text-[10px] text-muted-foreground/60 uppercase tracking-wider mb-1 block">Description</label>
                <textarea
                  value={newDescription}
                  onChange={(e) => setNewDescription(e.target.value)}
                  placeholder="Analyst notes about this threat actor..."
                  rows={2}
                  className="w-full bg-secondary/50 border border-border rounded px-2.5 py-1.5 text-xs text-foreground placeholder:text-muted-foreground/30 focus:outline-none focus:ring-1 focus:ring-cyan-500/50 resize-none"
                />
              </div>
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="px-5 py-3 border-t border-border flex items-center justify-between flex-shrink-0">
          <div className="flex items-center gap-2">
            {error && (
              <div className="flex items-center gap-1 text-[10px] text-red-400">
                <AlertTriangle className="w-3 h-3" />
                {error}
              </div>
            )}
          </div>
          <div className="flex items-center gap-2">
            {mode === 'assign' && sessionIds.length === 1 && (
              <Button
                variant="ghost"
                size="sm"
                onClick={handleUnassign}
                disabled={submitting}
                className="text-xs text-muted-foreground/60 hover:text-muted-foreground"
              >
                Unassign
              </Button>
            )}
            <Button
              variant="ghost"
              size="sm"
              onClick={onClose}
              disabled={submitting}
              className="text-xs"
            >
              Cancel
            </Button>
            <Button
              size="sm"
              onClick={handleSubmit}
              disabled={submitting || !canSubmit}
              className="text-xs bg-red-500/20 text-red-300 hover:bg-red-500/30 border border-red-500/30"
            >
              {submitting ? 'Working...' : submitLabel}
            </Button>
          </div>
        </div>
      </div>
    </div>
  );
}
