import { useState, useRef, useEffect, useCallback } from 'react'
import { Plus, Clock, Settings, Search, X, BarChart2, Trash2, ChevronLeft, ChevronRight, HelpCircle, LogOut, User, ChevronDown, Key, Users, Shield, Tag, Pencil, CheckSquare, Square } from 'lucide-react'
import { Button } from './ui/button'
import { Badge } from './ui/badge'
import { Tooltip, TooltipContent, TooltipTrigger } from './ui/tooltip'
import { cn, formatTimestamp, severityDot, truncate } from '@/lib/utils'
import { useAuth } from '@/contexts/AuthContext'
import ThreatActorAssignDialog from './ThreatActorAssignDialog'
import ConfirmDialog from './ConfirmDialog'
import type { Session, ThreatActorSummary } from '@/types'

function WaveformIcon({ className }: { className?: string }) {
  return (
    <svg viewBox="0 0 512 512" className={className}>
      <defs>
        <linearGradient id="sidebarWaveGrad" x1="0%" y1="50%" x2="100%" y2="50%">
          <stop offset="0%" stopColor="#2563eb"/>
          <stop offset="40%" stopColor="#06b6d4"/>
          <stop offset="100%" stopColor="#34d399"/>
        </linearGradient>
      </defs>
      <path d="M 60 256 Q 100 256 130 200 Q 160 140 190 180 Q 210 210 230 100 L 260 380 Q 280 440 300 300 Q 320 200 350 230 Q 380 260 410 240 L 452 256" fill="none" stroke="url(#sidebarWaveGrad)" strokeWidth="32" strokeLinecap="round" strokeLinejoin="round"/>
    </svg>
  );
}

interface SidebarProps {
  sessions: Session[];
  activeSessionId: string | null;
  onSelectSession: (id: string) => void;
  onNewSession: () => void;
  onOpenSettings: () => void;
  onOpenReports: () => void;
  onOpenHelp: () => void;
  onDeleteSession: (id: string) => void;
  onRenameSession: (id: string, name: string) => void;
  loading: boolean;
  collapsed: boolean;
  onToggleCollapse: () => void;
  onOpenChangePassword: () => void;
  onOpenAdmin: () => void;
  onSearchSessions: (filters: { search?: string; severity?: string; audience?: string; tags?: string }) => void;
  onBulkDelete?: (ids: string[]) => void;
  allTags: string[];
  activeTagFilters: string[];
  onUpdateSessionTags: (sessionId: string, tags: string[]) => void;
  threatActors: ThreatActorSummary[];
  activeThreatActorId: string | null;
  onSelectThreatActor: (id: string) => void;
  onClearThreatActor: () => void;
  onOpenSearch?: () => void;
  onActorAssigned?: () => void;
}

const severityVariant = (s: string | null): 'critical' | 'high' | 'medium' | 'low' | 'info' | 'secondary' => {
  const map: Record<string, 'critical' | 'high' | 'medium' | 'low' | 'info'> = {
    Critical: 'critical', High: 'high', Medium: 'medium', Low: 'low', Informational: 'info',
  };
  return map[s ?? ''] ?? 'secondary';
};

export default function Sidebar({ sessions, activeSessionId, onSelectSession, onNewSession, onOpenSettings, onOpenReports, onOpenHelp, onDeleteSession, onRenameSession, loading, collapsed, onToggleCollapse, onOpenChangePassword, onOpenAdmin, onSearchSessions, onBulkDelete, allTags, activeTagFilters, onUpdateSessionTags, threatActors, activeThreatActorId, onSelectThreatActor, onClearThreatActor, onOpenSearch, onActorAssigned }: SidebarProps) {
  const { user, teams, activeTeamId, switchTeam, logout, isAdmin } = useAuth();
  const [viewMode, setViewMode] = useState<'sessions' | 'actors'>('sessions');

  // Sync viewMode when parent changes active selection
  useEffect(() => {
    if (activeThreatActorId) setViewMode('actors');
  }, [activeThreatActorId]);
  useEffect(() => {
    if (activeSessionId) setViewMode('sessions');
  }, [activeSessionId]);

  const [searchQuery, setSearchQuery] = useState('');
  const [severityFilter, setSeverityFilter] = useState('');
  const [audienceFilter, setAudienceFilter] = useState('');
  const [tagFilter, setTagFilter] = useState<string[]>([]);
  const [tagDropdownOpen, setTagDropdownOpen] = useState(false);
  const tagDropdownRef = useRef<HTMLDivElement>(null);
  // Tag popover (hover icon) and context menu
  const [tagPopoverId, setTagPopoverId] = useState<string | null>(null);
  const [tagPopoverInput, setTagPopoverInput] = useState('');
  const tagPopoverRef = useRef<HTMLDivElement>(null);
  const [contextMenu, setContextMenu] = useState<{ sessionId: string; x: number; y: number } | null>(null);
  const contextMenuRef = useRef<HTMLDivElement>(null);
  const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set());
  const [selectMode, setSelectMode] = useState(false);
  const [editingId, setEditingId] = useState<string | null>(null);
  const [editingName, setEditingName] = useState('');
  const [userMenuOpen, setUserMenuOpen] = useState(false);
  const editInputRef = useRef<HTMLInputElement>(null);
  // Ref always holds the latest value — safe to read in blur handler
  const editingNameRef = useRef('');
  const editingIdRef = useRef<string | null>(null);
  const userMenuRef = useRef<HTMLDivElement>(null);
  const debounceTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  // Delete confirmation dialog — single or bulk
  const [confirmDelete, setConfirmDelete] = useState<{ ids: string[]; name: string } | null>(null);

  // Threat actor assignment dialogs
  const [actorAssignSessionId, setActorAssignSessionId] = useState<string | null>(null);
  const [showBulkActorAssign, setShowBulkActorAssign] = useState(false);
  const [showCreateActor, setShowCreateActor] = useState(false);

  const handleActorAssignedLocal = useCallback(() => {
    setActorAssignSessionId(null);
    setShowBulkActorAssign(false);
    setShowCreateActor(false);
    setSelectedIds(new Set());
    setSelectMode(false);
    onActorAssigned?.();
  }, [onActorAssigned]);

  // Close tag popover on outside click
  useEffect(() => {
    if (!tagPopoverId) return;
    const handler = (e: MouseEvent) => {
      if (tagPopoverRef.current && !tagPopoverRef.current.contains(e.target as Node)) {
        setTagPopoverId(null);
        setTagPopoverInput('');
      }
    };
    document.addEventListener('mousedown', handler);
    return () => document.removeEventListener('mousedown', handler);
  }, [tagPopoverId]);

  // Close context menu on outside click or scroll
  useEffect(() => {
    if (!contextMenu) return;
    const handler = (e: MouseEvent) => {
      if (contextMenuRef.current && !contextMenuRef.current.contains(e.target as Node)) setContextMenu(null);
    };
    const scrollHandler = () => setContextMenu(null);
    document.addEventListener('mousedown', handler);
    document.addEventListener('scroll', scrollHandler, true);
    return () => {
      document.removeEventListener('mousedown', handler);
      document.removeEventListener('scroll', scrollHandler, true);
    };
  }, [contextMenu]);

  // Close tag dropdown on outside click
  useEffect(() => {
    if (!tagDropdownOpen) return;
    const handler = (e: MouseEvent) => {
      if (tagDropdownRef.current && !tagDropdownRef.current.contains(e.target as Node)) setTagDropdownOpen(false);
    };
    document.addEventListener('mousedown', handler);
    return () => document.removeEventListener('mousedown', handler);
  }, [tagDropdownOpen]);

  // Close user menu on outside click
  useEffect(() => {
    if (!userMenuOpen) return;
    const handler = (e: MouseEvent) => {
      if (userMenuRef.current && !userMenuRef.current.contains(e.target as Node)) setUserMenuOpen(false);
    };
    document.addEventListener('mousedown', handler);
    return () => document.removeEventListener('mousedown', handler);
  }, [userMenuOpen]);

  useEffect(() => {
    if (editingId) editInputRef.current?.select();
  }, [editingId]);

  function startEdit(session: Session, e: React.MouseEvent) {
    e.stopPropagation();
    editingIdRef.current = session.id;
    editingNameRef.current = session.name;
    setEditingId(session.id);
    setEditingName(session.name);
  }

  function commitEdit() {
    const id = editingIdRef.current;
    const name = editingNameRef.current.trim();
    setEditingId(null);
    editingIdRef.current = null;
    if (id && name) {
      onRenameSession(id, name);
    }
  }

  function cancelEdit() {
    editingIdRef.current = null;
    setEditingId(null);
  }

  function toggleSessionTag(sessionId: string, tag: string) {
    const session = sessions.find((s) => s.id === sessionId);
    if (!session) return;
    const current = session.tags ?? [];
    const next = current.includes(tag) ? current.filter((t) => t !== tag) : [...current, tag];
    onUpdateSessionTags(sessionId, next);
  }

  function addNewTagToSession(sessionId: string, raw: string) {
    const tag = raw.trim().toLowerCase();
    if (!tag || tag.length > 30) return;
    const session = sessions.find((s) => s.id === sessionId);
    if (!session) return;
    const current = session.tags ?? [];
    if (current.includes(tag)) return;
    onUpdateSessionTags(sessionId, [...current, tag]);
  }

  function handleContextMenu(e: React.MouseEvent, sessionId: string) {
    e.preventDefault();
    setContextMenu({ sessionId, x: e.clientX, y: e.clientY });
  }

  // Debounced server-side search
  useEffect(() => {
    if (debounceTimerRef.current) clearTimeout(debounceTimerRef.current);
    debounceTimerRef.current = setTimeout(() => {
      onSearchSessions({
        search: searchQuery.trim() || undefined,
        severity: severityFilter || undefined,
        audience: audienceFilter || undefined,
        tags: tagFilter.length > 0 ? tagFilter.join(',') : undefined,
      });
    }, 300);
    return () => {
      if (debounceTimerRef.current) clearTimeout(debounceTimerRef.current);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [searchQuery, severityFilter, audienceFilter, tagFilter]);

  function toggleSelect(id: string) {
    setSelectedIds(prev => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  }

  function toggleSelectAll() {
    if (selectedIds.size === filteredSessions.length) {
      setSelectedIds(new Set());
    } else {
      setSelectedIds(new Set(filteredSessions.map(s => s.id)));
    }
  }

  function handleBulkDelete() {
    if (selectedIds.size === 0) return;
    setConfirmDelete({ ids: Array.from(selectedIds), name: '' });
  }

  const filteredSessions = sessions;

  // ── Collapsed icon strip ────────────────────────────────────────────────
  if (collapsed) {
    return (
      <aside className="w-10 flex-shrink-0 bg-navy-900 border-r border-border flex flex-col h-full items-center py-2 gap-1">
        <div className="w-7 h-7 rounded-lg bg-cyan-500/10 border border-cyan-500/30 flex items-center justify-center flex-shrink-0 mb-1">
          <WaveformIcon className="w-4 h-4" />
        </div>
        <Tooltip>
          <TooltipTrigger asChild>
            <button
              onClick={onNewSession}
              disabled={loading}
              className="w-7 h-7 rounded-md bg-cyan-500/10 border border-cyan-500/30 flex items-center justify-center text-cyan-400 hover:bg-cyan-500/20 transition-colors disabled:opacity-40"
              aria-label="New Analysis"
            >
              <Plus className="w-3.5 h-3.5" />
            </button>
          </TooltipTrigger>
          <TooltipContent side="right">New Analysis</TooltipContent>
        </Tooltip>

        {/* Active session dot */}
        {activeSessionId && (
          <div className="w-1.5 h-1.5 rounded-full bg-cyan-400 mt-1" />
        )}

        <div className="flex-1" />

        <Tooltip>
          <TooltipTrigger asChild>
            <button onClick={onOpenReports} className="w-7 h-7 rounded-md flex items-center justify-center text-muted-foreground hover:text-foreground hover:bg-secondary/50 transition-colors" aria-label="Activity Log">
              <BarChart2 className="w-3.5 h-3.5" />
            </button>
          </TooltipTrigger>
          <TooltipContent side="right">Activity Log</TooltipContent>
        </Tooltip>
        {isAdmin && (
          <Tooltip>
            <TooltipTrigger asChild>
              <button onClick={onOpenAdmin} className="w-7 h-7 rounded-md flex items-center justify-center text-muted-foreground hover:text-foreground hover:bg-secondary/50 transition-colors" aria-label="Admin Panel">
                <Users className="w-3.5 h-3.5" />
              </button>
            </TooltipTrigger>
            <TooltipContent side="right">Admin Panel</TooltipContent>
          </Tooltip>
        )}
        <Tooltip>
          <TooltipTrigger asChild>
            <button onClick={onOpenHelp} className="w-7 h-7 rounded-md flex items-center justify-center text-muted-foreground hover:text-foreground hover:bg-secondary/50 transition-colors" aria-label="Help">
              <HelpCircle className="w-3.5 h-3.5" />
            </button>
          </TooltipTrigger>
          <TooltipContent side="right">Help</TooltipContent>
        </Tooltip>
        <Tooltip>
          <TooltipTrigger asChild>
            <button onClick={onOpenSettings} className="w-7 h-7 rounded-md flex items-center justify-center text-muted-foreground hover:text-foreground hover:bg-secondary/50 transition-colors" aria-label="Settings">
              <Settings className="w-3.5 h-3.5" />
            </button>
          </TooltipTrigger>
          <TooltipContent side="right">Settings</TooltipContent>
        </Tooltip>
        <Tooltip>
          <TooltipTrigger asChild>
            <button onClick={logout} className="w-7 h-7 rounded-md flex items-center justify-center text-muted-foreground hover:text-red-400 hover:bg-red-500/10 transition-colors" aria-label="Sign Out">
              <LogOut className="w-3.5 h-3.5" />
            </button>
          </TooltipTrigger>
          <TooltipContent side="right">Sign Out</TooltipContent>
        </Tooltip>
        <Tooltip>
          <TooltipTrigger asChild>
            <button onClick={onToggleCollapse} className="w-7 h-7 rounded-md flex items-center justify-center text-muted-foreground hover:text-foreground hover:bg-secondary/50 transition-colors mt-1" aria-label="Expand sidebar">
              <ChevronRight className="w-3.5 h-3.5" />
            </button>
          </TooltipTrigger>
          <TooltipContent side="right">Expand sidebar</TooltipContent>
        </Tooltip>
      </aside>
    );
  }

  return (
    <aside className="w-64 flex-shrink-0 bg-navy-900 border-r border-border flex flex-col h-full">
      {/* Logo */}
      <div className="p-4 border-b border-border">
        <div className="flex items-center justify-between gap-2">
          <div className="flex items-center gap-2 min-w-0">
            <div className="w-8 h-8 rounded-lg bg-cyan-500/10 border border-cyan-500/30 flex items-center justify-center flex-shrink-0">
              <WaveformIcon className="w-5 h-5" />
            </div>
            <div className="min-w-0">
              <div className="text-sm font-bold text-foreground tracking-wide">SNR</div>
              <div className="text-[10px] text-muted-foreground uppercase tracking-widest">Signal to Noise</div>
            </div>
          </div>
          <button
            onClick={onToggleCollapse}
            className="text-muted-foreground/50 hover:text-foreground transition-colors flex-shrink-0 p-0.5 rounded hover:bg-secondary/50"
            aria-label="Collapse sidebar"
            title="Collapse sidebar"
          >
            <ChevronLeft className="w-3.5 h-3.5" />
          </button>
        </div>
        <div className="mt-1 text-[10px] text-muted-foreground/60">v1.0</div>
      </div>

      {/* New Analysis button */}
      <div className="p-3 border-b border-border">
        <Button
          variant="cyan"
          className="w-full h-9 text-sm"
          onClick={onNewSession}
          disabled={loading}
        >
          <Plus className="w-4 h-4" />
          New Analysis
        </Button>
      </div>

      {/* Global Intelligence Search */}
      {onOpenSearch && (
        <div className="px-3 py-1.5 border-b border-border">
          <button
            onClick={onOpenSearch}
            className="w-full flex items-center gap-2 px-2.5 py-1.5 rounded-md bg-secondary/40 border border-border hover:bg-secondary/60 hover:border-border/80 transition-colors text-left group"
          >
            <Search className="w-3 h-3 text-muted-foreground/50 group-hover:text-cyan-400 transition-colors" />
            <span className="text-[11px] text-muted-foreground/50 flex-1">Search intelligence...</span>
            <kbd className="hidden sm:inline-flex text-[9px] text-muted-foreground/30 bg-secondary/50 border border-border/50 rounded px-1 py-0 font-mono">
              {navigator.platform?.includes('Mac') ? '⌘' : 'Ctrl+'}K
            </kbd>
          </button>
        </div>
      )}

      {/* Search & Filters */}
      <div className="px-3 py-2 border-b border-border space-y-1.5">
        <div className="relative">
          <Search className="absolute left-2 top-1/2 -translate-y-1/2 w-3 h-3 text-muted-foreground/50" />
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Search sessions…"
            className="w-full bg-secondary/50 border border-border rounded-md pl-6 pr-6 py-1.5 text-xs text-foreground placeholder:text-muted-foreground/40 focus:outline-none focus:ring-1 focus:ring-cyan-500/50 focus:border-cyan-500/50 transition-colors"
          />
          {(searchQuery || severityFilter || audienceFilter || tagFilter.length > 0) && (
            <button
              onClick={() => { setSearchQuery(''); setSeverityFilter(''); setAudienceFilter(''); setTagFilter([]); }}
              className="absolute right-1.5 top-1/2 -translate-y-1/2 text-muted-foreground/50 hover:text-foreground transition-colors"
            >
              <X className="w-3 h-3" />
            </button>
          )}
        </div>
        <div className="flex gap-1.5">
          <select
            value={severityFilter}
            onChange={(e) => setSeverityFilter(e.target.value)}
            className="flex-1 bg-secondary/50 border border-border rounded-md px-1.5 py-1 text-[10px] text-foreground focus:outline-none focus:ring-1 focus:ring-cyan-500/50 appearance-none cursor-pointer"
          >
            <option value="">All Severity</option>
            <option value="Critical">Critical</option>
            <option value="High">High</option>
            <option value="Medium">Medium</option>
            <option value="Low">Low</option>
            <option value="Informational">Info</option>
          </select>
          <select
            value={audienceFilter}
            onChange={(e) => setAudienceFilter(e.target.value)}
            className="flex-1 bg-secondary/50 border border-border rounded-md px-1.5 py-1 text-[10px] text-foreground focus:outline-none focus:ring-1 focus:ring-cyan-500/50 appearance-none cursor-pointer"
          >
            <option value="">All Audience</option>
            <option value="soc">SOC</option>
            <option value="executive">Executive</option>
            <option value="technical">Technical</option>
            <option value="compliance">Compliance</option>
          </select>
        </div>

        {/* Tag filter — compact dropdown */}
        {allTags.length > 0 && (
          <div className="relative" ref={tagDropdownRef}>
            <button
              onClick={() => setTagDropdownOpen(!tagDropdownOpen)}
              className={cn(
                'w-full flex items-center gap-1.5 px-1.5 py-1 rounded-md border text-[10px] transition-colors',
                tagFilter.length > 0
                  ? 'bg-cyan-500/10 border-cyan-500/30 text-cyan-300'
                  : 'bg-secondary/50 border-border text-muted-foreground/60 hover:text-muted-foreground'
              )}
            >
              <Tag className="w-3 h-3 flex-shrink-0" />
              {tagFilter.length > 0 ? (
                <span className="flex-1 text-left truncate">
                  {tagFilter.slice(0, 2).join(', ')}{tagFilter.length > 2 ? ` +${tagFilter.length - 2}` : ''}
                </span>
              ) : (
                <span className="flex-1 text-left">Filter by tag</span>
              )}
              <ChevronDown className={cn('w-3 h-3 flex-shrink-0 transition-transform', tagDropdownOpen && 'rotate-180')} />
            </button>

            {/* Active tag pills — shown inline when filters applied, dropdown closed */}
            {tagFilter.length > 0 && !tagDropdownOpen && (
              <div className="flex flex-wrap gap-1 mt-1">
                {tagFilter.map((tag) => (
                  <span
                    key={tag}
                    className="inline-flex items-center gap-0.5 text-[9px] px-1.5 py-0.5 rounded-full bg-cyan-500/15 text-cyan-400 border border-cyan-500/25"
                  >
                    {tag}
                    <button
                      onClick={(e) => { e.stopPropagation(); setTagFilter((prev) => prev.filter((t) => t !== tag)); }}
                      className="hover:text-foreground transition-colors"
                    >
                      <X className="w-2 h-2" />
                    </button>
                  </span>
                ))}
              </div>
            )}

            {/* Dropdown panel */}
            {tagDropdownOpen && (
              <div className="absolute top-full left-0 right-0 mt-1 bg-navy-800 border border-border rounded-md shadow-lg overflow-hidden z-50">
                <div className="max-h-[180px] overflow-y-auto py-1">
                  {allTags.map((tag) => {
                    const isActive = tagFilter.includes(tag);
                    return (
                      <button
                        key={tag}
                        onClick={() => {
                          setTagFilter((prev) =>
                            isActive ? prev.filter((t) => t !== tag) : [...prev, tag]
                          );
                        }}
                        className={cn(
                          'w-full flex items-center gap-2 px-2.5 py-1.5 text-[10px] transition-colors text-left',
                          isActive ? 'bg-cyan-500/10 text-cyan-300' : 'text-muted-foreground hover:bg-secondary/50 hover:text-foreground'
                        )}
                      >
                        <div className={cn(
                          'w-3 h-3 rounded border flex items-center justify-center flex-shrink-0 transition-colors',
                          isActive ? 'bg-cyan-500 border-cyan-500' : 'border-border'
                        )}>
                          {isActive && <span className="text-[7px] text-white font-bold">✓</span>}
                        </div>
                        <Tag className="w-2.5 h-2.5 flex-shrink-0 opacity-50" />
                        <span className="truncate">{tag}</span>
                      </button>
                    );
                  })}
                </div>
                {tagFilter.length > 0 && (
                  <div className="border-t border-border px-2.5 py-1.5">
                    <button
                      onClick={() => { setTagFilter([]); setTagDropdownOpen(false); }}
                      className="text-[10px] text-muted-foreground/60 hover:text-foreground transition-colors"
                    >
                      Clear tag filters
                    </button>
                  </div>
                )}
              </div>
            )}
          </div>
        )}
      </div>

      {/* View mode toggle */}
      <div className="px-3 py-1.5 border-b border-border flex gap-1">
        <button
          onClick={() => { setViewMode('sessions'); onClearThreatActor(); }}
          className={cn('flex-1 text-[10px] py-1 rounded transition-colors flex items-center justify-center gap-1',
            viewMode === 'sessions' ? 'bg-cyan-500/15 text-cyan-400 font-medium' : 'text-muted-foreground/60 hover:text-muted-foreground')}
        >
          <Clock className="w-3 h-3" />
          Sessions
        </button>
        <button
          onClick={() => setViewMode('actors')}
          className={cn('flex-1 text-[10px] py-1 rounded transition-colors flex items-center justify-center gap-1',
            viewMode === 'actors' ? 'bg-cyan-500/15 text-cyan-400 font-medium' : 'text-muted-foreground/60 hover:text-muted-foreground')}
        >
          <Shield className="w-3 h-3" />
          Threat Actors
          {threatActors.length > 0 && (
            <span className={cn('text-[9px] px-1 rounded-full', viewMode === 'actors' ? 'bg-cyan-500/20 text-cyan-400' : 'bg-secondary text-muted-foreground/60')}>
              {threatActors.length}
            </span>
          )}
        </button>
      </div>

      {/* Session list */}
      {viewMode === 'sessions' && (
      <div className="flex-1 overflow-y-auto">
        <div className="px-3 py-2">
          <div className="text-[10px] uppercase tracking-widest text-muted-foreground/60 mb-2 flex items-center gap-1">
            <Clock className="w-3 h-3" />
            {(searchQuery || severityFilter || audienceFilter || tagFilter.length > 0) ? `Results (${filteredSessions.length})` : 'Recent Sessions'}
            <span className="flex-1" />
            {onBulkDelete && filteredSessions.length > 0 && (
              <button
                onClick={() => { setSelectMode(!selectMode); setSelectedIds(new Set()); }}
                className={cn('text-[10px] px-1.5 py-0.5 rounded transition-colors', selectMode ? 'text-cyan-400 bg-cyan-500/10' : 'text-muted-foreground/40 hover:text-muted-foreground')}
              >
                {selectMode ? 'Done' : 'Select'}
              </button>
            )}
          </div>

          {selectMode && selectedIds.size > 0 && (
            <div className="flex items-center gap-2 mb-2 px-1">
              <button
                onClick={toggleSelectAll}
                className="text-[10px] text-cyan-400 hover:underline"
              >
                {selectedIds.size === filteredSessions.length ? 'Deselect All' : 'Select All'}
              </button>
              <span className="flex-1" />
              <button
                onClick={() => setShowBulkActorAssign(true)}
                className="text-[10px] px-2 py-0.5 rounded bg-red-500/10 text-red-300 hover:bg-red-500/20 border border-red-500/20 transition-colors flex items-center gap-1"
              >
                <Shield className="w-2.5 h-2.5" />
                Group ({selectedIds.size})
              </button>
              <button
                onClick={handleBulkDelete}
                className="text-[10px] px-2 py-0.5 rounded bg-red-500/20 text-red-400 hover:bg-red-500/30 transition-colors"
              >
                Delete {selectedIds.size}
              </button>
            </div>
          )}

          {sessions.length === 0 && (
            <div className="text-xs text-muted-foreground text-center py-8">
              No sessions yet.
              <br />Start a new analysis.
            </div>
          )}

          {(searchQuery || severityFilter || audienceFilter || tagFilter.length > 0) && filteredSessions.length === 0 && (
            <div className="text-xs text-muted-foreground text-center py-6">
              No sessions match{searchQuery ? <><br />"{truncate(searchQuery, 20)}"</> : ' filters'}
            </div>
          )}

          <div className="space-y-1">
            {filteredSessions.map((session) => (
              <div
                key={session.id}
                className={cn(
                  'relative rounded-md transition-colors group border',
                  activeSessionId === session.id
                    ? 'bg-cyan-500/10 border-cyan-500/20'
                    : 'hover:bg-secondary/50 border-transparent'
                )}
                onContextMenu={(e) => handleContextMenu(e, session.id)}
              >
                <button
                  onClick={() => selectMode ? toggleSelect(session.id) : onSelectSession(session.id)}
                  className="w-full text-left px-2.5 py-2.5 pr-14"
                >
                  <div className="flex items-start justify-between gap-1">
                    {selectMode && (
                      <div className={cn('w-3.5 h-3.5 rounded border flex-shrink-0 mt-0.5 mr-1.5 flex items-center justify-center transition-colors', selectedIds.has(session.id) ? 'bg-cyan-500 border-cyan-500' : 'border-border')}>
                        {selectedIds.has(session.id) && <span className="text-[8px] text-white font-bold">✓</span>}
                      </div>
                    )}
                    <div className="flex-1 min-w-0">
                      {editingId === session.id ? (
                        <input
                          ref={editInputRef}
                          value={editingName}
                          onChange={(e) => { editingNameRef.current = e.target.value; setEditingName(e.target.value); }}
                          onBlur={commitEdit}
                          onKeyDown={(e) => {
                            if (e.key === 'Enter') { e.preventDefault(); commitEdit(); }
                            if (e.key === 'Escape') { e.preventDefault(); cancelEdit(); }
                          }}
                          onClick={(e) => e.stopPropagation()}
                          className="w-full bg-navy-950 border border-cyan-500/50 rounded px-1.5 py-0.5 text-xs text-foreground focus:outline-none focus:ring-1 focus:ring-cyan-500"
                        />
                      ) : (
                        <div
                          className={cn(
                            'text-xs font-medium truncate cursor-text',
                            activeSessionId === session.id ? 'text-cyan-300' : 'text-foreground'
                          )}
                          onDoubleClick={(e) => startEdit(session, e)}
                          title="Double-click to rename"
                        >
                          {truncate(session.name, 26)}
                        </div>
                      )}
                      <div className="text-[10px] text-muted-foreground mt-0.5">
                        {formatTimestamp(session.created_at)}
                      </div>
                    </div>
                    <div className="flex flex-col items-end gap-1 flex-shrink-0">
                      {session.severity && (
                        <div className="flex items-center gap-1">
                          <div className={cn('w-1.5 h-1.5 rounded-full', severityDot(session.severity))} />
                          <span className="text-[9px] text-muted-foreground uppercase">{session.severity}</span>
                        </div>
                      )}
                      {session.status === 'analyzing' && (
                        <span className="text-[9px] text-cyan-400 animate-pulse">Analyzing…</span>
                      )}
                      {session.status === 'failed' && (
                        <span className="text-[9px] text-red-400 border border-red-500/30 bg-red-500/10 rounded px-1 py-0">Failed</span>
                      )}
                    </div>
                  </div>
                  {(session.audience || (session.tags && session.tags.length > 0)) && (
                    <div className="mt-1 flex items-center gap-1 flex-wrap">
                      {session.audience && (
                        <Badge variant="secondary" className="text-[9px] px-1.5 py-0 h-4">
                          {session.audience.replace(/_/g, ' ').toUpperCase()}
                        </Badge>
                      )}
                      {session.tags && session.tags.slice(0, 3).map((tag) => (
                        <span
                          key={tag}
                          className="inline-flex items-center gap-0.5 text-[8px] px-1 py-0 h-3.5 rounded bg-cyan-500/10 text-cyan-400/70 border border-cyan-500/20"
                        >
                          <Tag className="w-2 h-2" />
                          {tag}
                        </span>
                      ))}
                      {session.tags && session.tags.length > 3 && (
                        <span className="text-[8px] text-muted-foreground/40">+{session.tags.length - 3}</span>
                      )}
                    </div>
                  )}
                </button>
                {/* Hover action icons */}
                <div className="absolute top-2 right-2 flex items-center gap-0.5 opacity-0 group-hover:opacity-100 transition-opacity">
                  <button
                    onClick={(e) => {
                      e.stopPropagation();
                      setTagPopoverId(tagPopoverId === session.id ? null : session.id);
                      setTagPopoverInput('');
                    }}
                    className={cn(
                      'p-1 rounded transition-all',
                      tagPopoverId === session.id
                        ? 'text-cyan-400 bg-cyan-500/10'
                        : 'text-muted-foreground/50 hover:text-cyan-400 hover:bg-cyan-400/10'
                    )}
                    aria-label="Manage tags"
                    title="Manage tags"
                  >
                    <Tag className="w-3 h-3" />
                  </button>
                  <button
                    onClick={(e) => {
                      e.stopPropagation();
                      setConfirmDelete({ ids: [session.id], name: session.name });
                    }}
                    className="p-1 rounded text-muted-foreground/50 hover:text-red-400 hover:bg-red-400/10 transition-all"
                    aria-label="Delete session"
                    title="Delete session"
                  >
                    <Trash2 className="w-3 h-3" />
                  </button>
                </div>

                {/* Tag popover */}
                {tagPopoverId === session.id && (
                  <div
                    ref={tagPopoverRef}
                    className="absolute top-8 right-1 w-48 bg-navy-800 border border-border rounded-md shadow-lg overflow-hidden z-50"
                    onClick={(e) => e.stopPropagation()}
                  >
                    {/* New tag input */}
                    <div className="px-2 py-1.5 border-b border-border">
                      <input
                        type="text"
                        value={tagPopoverInput}
                        onChange={(e) => setTagPopoverInput(e.target.value)}
                        onKeyDown={(e) => {
                          if (e.key === 'Enter' && tagPopoverInput.trim()) {
                            e.preventDefault();
                            addNewTagToSession(session.id, tagPopoverInput);
                            setTagPopoverInput('');
                          }
                          if (e.key === 'Escape') {
                            setTagPopoverId(null);
                            setTagPopoverInput('');
                          }
                        }}
                        placeholder="Type new tag + Enter"
                        className="w-full bg-secondary/50 border border-border rounded px-1.5 py-1 text-[10px] text-foreground placeholder:text-muted-foreground/40 focus:outline-none focus:ring-1 focus:ring-cyan-500/50"
                        autoFocus
                        maxLength={30}
                        autoComplete="off"
                        spellCheck={false}
                      />
                    </div>
                    {/* Existing tags */}
                    <div className="max-h-[140px] overflow-y-auto py-0.5">
                      {allTags.length === 0 && (
                        <div className="px-2 py-2 text-[10px] text-muted-foreground/50 text-center">
                          No tags yet — type above to create one
                        </div>
                      )}
                      {allTags.map((tag) => {
                        const hasTag = (session.tags ?? []).includes(tag);
                        return (
                          <button
                            key={tag}
                            onClick={() => toggleSessionTag(session.id, tag)}
                            className={cn(
                              'w-full flex items-center gap-2 px-2 py-1 text-[10px] transition-colors text-left',
                              hasTag ? 'bg-cyan-500/10 text-cyan-300' : 'text-muted-foreground hover:bg-secondary/50 hover:text-foreground'
                            )}
                          >
                            <div className={cn(
                              'w-3 h-3 rounded border flex items-center justify-center flex-shrink-0',
                              hasTag ? 'bg-cyan-500 border-cyan-500' : 'border-border'
                            )}>
                              {hasTag && <span className="text-[7px] text-white font-bold">✓</span>}
                            </div>
                            <Tag className="w-2.5 h-2.5 flex-shrink-0 opacity-50" />
                            <span className="truncate">{tag}</span>
                          </button>
                        );
                      })}
                    </div>
                  </div>
                )}
              </div>
            ))}
          </div>
        </div>
      </div>
      )}

      {/* Right-click context menu */}
      {contextMenu && (() => {
        const session = sessions.find((s) => s.id === contextMenu.sessionId);
        if (!session) return null;
        return (
          <div
            ref={contextMenuRef}
            className="fixed bg-navy-800 border border-border rounded-md shadow-xl overflow-hidden z-[200] min-w-[160px]"
            style={{ left: contextMenu.x, top: contextMenu.y }}
          >
            <button
              onClick={() => { onSelectSession(session.id); setContextMenu(null); }}
              className="w-full flex items-center gap-2 px-3 py-2 text-xs text-foreground hover:bg-secondary/50 transition-colors text-left"
            >
              <Clock className="w-3 h-3 opacity-60" />
              Open
            </button>
            <button
              onClick={() => {
                setContextMenu(null);
                editingIdRef.current = session.id;
                editingNameRef.current = session.name;
                setEditingId(session.id);
                setEditingName(session.name);
              }}
              className="w-full flex items-center gap-2 px-3 py-2 text-xs text-foreground hover:bg-secondary/50 transition-colors text-left"
            >
              <Pencil className="w-3 h-3 opacity-60" />
              Rename
            </button>
            <button
              onClick={() => {
                setContextMenu(null);
                setTagPopoverId(session.id);
                setTagPopoverInput('');
              }}
              className="w-full flex items-center gap-2 px-3 py-2 text-xs text-foreground hover:bg-secondary/50 transition-colors text-left"
            >
              <Tag className="w-3 h-3 opacity-60" />
              Manage Tags
              {session.tags && session.tags.length > 0 && (
                <span className="text-[9px] text-cyan-400/70 ml-auto">{session.tags.length}</span>
              )}
            </button>
            <button
              onClick={() => {
                setContextMenu(null);
                setActorAssignSessionId(session.id);
              }}
              className="w-full flex items-center gap-2 px-3 py-2 text-xs text-foreground hover:bg-secondary/50 transition-colors text-left"
            >
              <Shield className="w-3 h-3 opacity-60" />
              Assign Threat Actor
            </button>
            <div className="border-t border-border" />
            <button
              onClick={() => {
                setContextMenu(null);
                setConfirmDelete({ ids: [session.id], name: session.name });
              }}
              className="w-full flex items-center gap-2 px-3 py-2 text-xs text-red-400/80 hover:text-red-400 hover:bg-red-500/10 transition-colors text-left"
            >
              <Trash2 className="w-3 h-3" />
              Delete
            </button>
          </div>
        );
      })()}

      {/* Threat Actors list */}
      {viewMode === 'actors' && (
      <div className="flex-1 overflow-y-auto">
        <div className="px-3 py-2">
          <div className="text-[10px] uppercase tracking-widest text-muted-foreground/60 mb-2 flex items-center justify-between">
            <div className="flex items-center gap-1">
              <Shield className="w-3 h-3" />
              Threat Actors ({threatActors.length})
            </div>
            <button
              onClick={() => setShowCreateActor(true)}
              className="flex items-center gap-0.5 text-[10px] text-cyan-400/60 hover:text-cyan-400 transition-colors"
              title="Create new threat actor"
            >
              <Plus className="w-3 h-3" />
              New
            </button>
          </div>

          {threatActors.length === 0 && (
            <div className="text-xs text-muted-foreground text-center py-8">
              No threat actors yet.
              <br />Run an analysis that identifies a threat actor.
            </div>
          )}

          <div className="space-y-1">
            {[...threatActors].sort((a, b) => a.name === 'Unattributed' ? 1 : b.name === 'Unattributed' ? -1 : 0).map((actor) => {
              const isUnattributed = actor.name === 'Unattributed';
              return (
              <button
                key={actor.id}
                onClick={() => onSelectThreatActor(actor.id)}
                className={cn(
                  'w-full text-left rounded-md transition-colors border px-2.5 py-2.5',
                  activeThreatActorId === actor.id
                    ? isUnattributed ? 'bg-secondary/40 border-border' : 'bg-red-500/10 border-red-500/20'
                    : 'hover:bg-secondary/50 border-transparent',
                  isUnattributed && activeThreatActorId !== actor.id && 'opacity-60'
                )}
              >
                <div className="flex items-start justify-between gap-1">
                  <div className="flex-1 min-w-0">
                    <div className={cn(
                      'text-xs font-medium truncate',
                      isUnattributed ? 'text-muted-foreground italic'
                        : activeThreatActorId === actor.id ? 'text-red-300' : 'text-foreground'
                    )}>
                      {actor.name}
                    </div>
                    {actor.intrusion_set && (
                      <div className="text-[10px] text-cyan-400/70 truncate mt-0.5">
                        {actor.intrusion_set}
                      </div>
                    )}
                    <div className="text-[10px] text-muted-foreground mt-0.5">
                      {actor.session_count} session{actor.session_count !== 1 ? 's' : ''}
                      {actor.latest_session_at && <> &middot; {formatTimestamp(actor.latest_session_at)}</>}
                    </div>
                  </div>
                  <div className="flex flex-col items-end gap-1 flex-shrink-0">
                    {actor.attribution_confidence && (
                      <span className={cn(
                        'text-[9px] px-1.5 py-0.5 rounded border',
                        actor.attribution_confidence === 'High' ? 'bg-red-500/10 text-red-400 border-red-500/20'
                          : actor.attribution_confidence === 'Medium' ? 'bg-yellow-500/10 text-yellow-400 border-yellow-500/20'
                          : 'bg-green-500/10 text-green-400 border-green-500/20'
                      )}>
                        {actor.attribution_confidence}
                      </span>
                    )}
                    {actor.session_count > 0 && (
                      <Badge variant="secondary" className="text-[9px] px-1 py-0 h-4">
                        {actor.session_count}
                      </Badge>
                    )}
                  </div>
                </div>
                {actor.aliases.length > 0 && (
                  <div className="flex items-center gap-1 mt-1 flex-wrap">
                    {actor.aliases.slice(0, 3).map((alias, i) => (
                      <Badge key={i} variant="secondary" className="text-[8px] px-1 py-0 h-3.5">{truncate(alias, 16)}</Badge>
                    ))}
                    {actor.aliases.length > 3 && (
                      <span className="text-[9px] text-muted-foreground/50">+{actor.aliases.length - 3}</span>
                    )}
                  </div>
                )}
              </button>
              );
            })}
          </div>
        </div>
      </div>
      )}

      {/* Team Selector */}
      {teams.length > 1 && (
        <div className="px-3 py-2 border-t border-border">
          <label className="text-[10px] uppercase tracking-widest text-muted-foreground/60 mb-1 block">Team</label>
          <select
            value={activeTeamId ?? ''}
            onChange={(e) => { switchTeam(e.target.value); onNewSession(); }}
            className="w-full bg-secondary/50 border border-border rounded-md px-2 py-1.5 text-xs text-foreground focus:outline-none focus:ring-1 focus:ring-cyan-500/50"
          >
            {teams.map((t) => (
              <option key={t.id} value={t.id}>{t.name}</option>
            ))}
          </select>
        </div>
      )}

      {/* Footer */}
      <div className="p-3 border-t border-border space-y-2">
        <button
          onClick={onOpenReports}
          className="w-full flex items-center gap-2 px-2 py-1.5 rounded-md text-xs text-muted-foreground hover:text-foreground hover:bg-secondary/50 transition-colors"
        >
          <BarChart2 className="w-3.5 h-3.5" />
          Activity Log
        </button>
        {isAdmin && (
          <button
            onClick={onOpenAdmin}
            className="w-full flex items-center gap-2 px-2 py-1.5 rounded-md text-xs text-muted-foreground hover:text-foreground hover:bg-secondary/50 transition-colors"
          >
            <Users className="w-3.5 h-3.5" />
            Admin Panel
          </button>
        )}
        <button
          onClick={onOpenSettings}
          className="w-full flex items-center gap-2 px-2 py-1.5 rounded-md text-xs text-muted-foreground hover:text-foreground hover:bg-secondary/50 transition-colors"
        >
          <Settings className="w-3.5 h-3.5" />
          Settings
        </button>
        <button
          onClick={onOpenHelp}
          className="w-full flex items-center gap-2 px-2 py-1.5 rounded-md text-xs text-muted-foreground hover:text-foreground hover:bg-secondary/50 transition-colors"
        >
          <HelpCircle className="w-3.5 h-3.5" />
          Help
        </button>

        {/* User menu */}
        <div className="relative" ref={userMenuRef}>
          <button
            onClick={() => setUserMenuOpen(!userMenuOpen)}
            className="w-full flex items-center gap-2 px-2 py-1.5 rounded-md text-xs text-muted-foreground hover:text-foreground hover:bg-secondary/50 transition-colors"
          >
            <User className="w-3.5 h-3.5" />
            <span className="flex-1 text-left truncate">{user?.displayName ?? 'User'}</span>
            <ChevronDown className={cn('w-3 h-3 transition-transform', userMenuOpen && 'rotate-180')} />
          </button>

          {userMenuOpen && (
            <div className="absolute bottom-full left-0 right-0 mb-1 bg-navy-800 border border-border rounded-md shadow-lg overflow-hidden z-50">
              <div className="px-3 py-2 border-b border-border">
                <div className="text-xs font-medium text-foreground truncate">{user?.email}</div>
                <div className="text-[10px] text-muted-foreground capitalize">{user?.role}</div>
              </div>
              <button
                onClick={() => { setUserMenuOpen(false); onOpenChangePassword(); }}
                className="w-full flex items-center gap-2 px-3 py-2 text-xs text-muted-foreground hover:text-foreground hover:bg-secondary/50 transition-colors"
              >
                <Key className="w-3 h-3" />
                Change Password
              </button>
              <button
                onClick={() => { setUserMenuOpen(false); logout(); }}
                className="w-full flex items-center gap-2 px-3 py-2 text-xs text-red-400/80 hover:text-red-400 hover:bg-red-500/10 transition-colors"
              >
                <LogOut className="w-3 h-3" />
                Sign Out
              </button>
            </div>
          )}
        </div>

        <div className="text-[10px] text-muted-foreground/30 text-center">
          SNR — Signal to Noise
        </div>
      </div>

      {/* Delete confirmation */}
      <ConfirmDialog
        open={!!confirmDelete}
        title={confirmDelete && confirmDelete.ids.length > 1 ? `Delete ${confirmDelete.ids.length} sessions?` : 'Delete session?'}
        message={confirmDelete && confirmDelete.ids.length > 1
          ? `${confirmDelete.ids.length} sessions will be deleted. You can undo from the toast, and deleted sessions are recoverable for 7 days.`
          : `"${confirmDelete?.name ?? ''}" will be deleted. You can undo from the toast, and deleted sessions are recoverable for 7 days.`}
        confirmLabel="Delete"
        danger
        onConfirm={() => {
          if (!confirmDelete) return;
          if (confirmDelete.ids.length > 1) {
            onBulkDelete?.(confirmDelete.ids);
            setSelectedIds(new Set());
            setSelectMode(false);
          } else {
            onDeleteSession(confirmDelete.ids[0]);
          }
          setConfirmDelete(null);
        }}
        onCancel={() => setConfirmDelete(null)}
      />

      {/* Threat Actor assign dialog — single session from context menu */}
      {actorAssignSessionId && (
        <ThreatActorAssignDialog
          open={!!actorAssignSessionId}
          onClose={() => setActorAssignSessionId(null)}
          sessionIds={[actorAssignSessionId]}
          actors={threatActors}
          onAssigned={handleActorAssignedLocal}
          mode="assign"
        />
      )}

      {/* Threat Actor assign dialog — bulk from selection mode */}
      {showBulkActorAssign && selectedIds.size > 0 && (
        <ThreatActorAssignDialog
          open={showBulkActorAssign}
          onClose={() => setShowBulkActorAssign(false)}
          sessionIds={Array.from(selectedIds)}
          actors={threatActors}
          onAssigned={handleActorAssignedLocal}
          mode="bulk"
        />
      )}

      {/* Threat Actor create dialog — from actors list */}
      {showCreateActor && (
        <ThreatActorAssignDialog
          open={showCreateActor}
          onClose={() => setShowCreateActor(false)}
          sessionIds={[]}
          actors={threatActors}
          onAssigned={handleActorAssignedLocal}
          mode="create"
        />
      )}
    </aside>
  );
}
