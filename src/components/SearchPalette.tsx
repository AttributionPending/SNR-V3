/**
 * Global Intelligence Search — Cmd+K / Ctrl+K command palette.
 * Searches across IOCs, ATT&CK techniques, threat actors, sessions, and affected assets.
 * Aggregated results (techniques, IOCs, assets) show a single row with expandable session list.
 */
import { useState, useEffect, useRef, useCallback } from 'react';
import { Search, X, Globe, Shield, Crosshair, Server, FileText, Loader2, ChevronRight, ExternalLink } from 'lucide-react';
import { cn } from '@/lib/utils';
import { searchIntelligence, type SearchHit } from '@/lib/api';

interface SearchPaletteProps {
  open: boolean;
  onClose: () => void;
  onSelectSession: (id: string) => void;
  onSelectThreatActor: (id: string) => void;
}

const CATEGORY_CONFIG: Record<SearchHit['category'], {
  label: string;
  icon: React.ElementType;
  color: string;
  bgColor: string;
}> = {
  ioc: { label: 'IOC', icon: Globe, color: 'text-cyan-400', bgColor: 'bg-cyan-500/15' },
  technique: { label: 'Technique', icon: Crosshair, color: 'text-orange-400', bgColor: 'bg-orange-500/15' },
  threat_actor: { label: 'Threat Actor', icon: Shield, color: 'text-red-400', bgColor: 'bg-red-500/15' },
  session: { label: 'Session', icon: FileText, color: 'text-emerald-400', bgColor: 'bg-emerald-500/15' },
  asset: { label: 'Asset', icon: Server, color: 'text-purple-400', bgColor: 'bg-purple-500/15' },
};

export default function SearchPalette({ open, onClose, onSelectSession, onSelectThreatActor }: SearchPaletteProps) {
  const [query, setQuery] = useState('');
  const [results, setResults] = useState<SearchHit[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(false);
  const [selectedIndex, setSelectedIndex] = useState(0);
  const [expandedKeys, setExpandedKeys] = useState<Set<string>>(new Set());
  const inputRef = useRef<HTMLInputElement>(null);
  const listRef = useRef<HTMLDivElement>(null);
  const debounceRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  // Focus input when opened
  useEffect(() => {
    if (open) {
      setQuery('');
      setResults([]);
      setTotal(0);
      setSelectedIndex(0);
      setExpandedKeys(new Set());
      setTimeout(() => inputRef.current?.focus(), 50);
    }
  }, [open]);

  // Debounced search
  const doSearch = useCallback(async (q: string) => {
    if (q.trim().length < 2) {
      setResults([]);
      setTotal(0);
      return;
    }
    setLoading(true);
    try {
      const data = await searchIntelligence(q.trim());
      setResults(data.results);
      setTotal(data.total);
      setSelectedIndex(0);
      setExpandedKeys(new Set());
    } catch {
      setResults([]);
      setTotal(0);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    if (debounceRef.current) clearTimeout(debounceRef.current);
    debounceRef.current = setTimeout(() => doSearch(query), 250);
    return () => {
      if (debounceRef.current) clearTimeout(debounceRef.current);
    };
  }, [query, doSearch]);

  // Keyboard navigation
  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'ArrowDown') {
      e.preventDefault();
      setSelectedIndex((prev) => Math.min(prev + 1, results.length - 1));
    } else if (e.key === 'ArrowUp') {
      e.preventDefault();
      setSelectedIndex((prev) => Math.max(prev - 1, 0));
    } else if (e.key === 'Enter' && results[selectedIndex]) {
      e.preventDefault();
      const hit = results[selectedIndex];
      const hasMultipleSessions = hit.sessions && hit.sessions.length > 1;
      if (hasMultipleSessions) {
        // Toggle expand for multi-session results
        toggleExpand(hit);
      } else {
        handleSelect(hit);
      }
    } else if (e.key === 'Escape') {
      e.preventDefault();
      onClose();
    }
  };

  // Scroll selected item into view
  useEffect(() => {
    if (!listRef.current) return;
    const items = listRef.current.querySelectorAll('[data-search-item]');
    items[selectedIndex]?.scrollIntoView({ block: 'nearest' });
  }, [selectedIndex]);

  const handleSelect = (hit: SearchHit, sessionId?: string) => {
    onClose();
    if (hit.category === 'threat_actor' && hit.meta?.actor_id) {
      onSelectThreatActor(hit.meta.actor_id);
    } else {
      onSelectSession(sessionId || hit.session_id);
    }
  };

  const toggleExpand = (hit: SearchHit) => {
    const key = `${hit.category}::${hit.value}`;
    setExpandedKeys((prev) => {
      const next = new Set(prev);
      if (next.has(key)) next.delete(key);
      else next.add(key);
      return next;
    });
  };

  // Close on backdrop click
  const handleBackdropClick = (e: React.MouseEvent) => {
    if (e.target === e.currentTarget) onClose();
  };

  if (!open) return null;

  // Group results by category for display
  const grouped = results.reduce<Record<string, SearchHit[]>>((acc, hit) => {
    if (!acc[hit.category]) acc[hit.category] = [];
    acc[hit.category].push(hit);
    return acc;
  }, {});

  let flatIndex = 0;

  return (
    <div
      className="fixed inset-0 z-[100] flex items-start justify-center pt-[15vh] bg-black/60 backdrop-blur-sm"
      onClick={handleBackdropClick}
    >
      <div className="w-full max-w-xl mx-4 bg-navy-900 border border-border rounded-xl shadow-2xl overflow-hidden animate-in fade-in zoom-in-95 duration-150">
        {/* Search input */}
        <div className="flex items-center gap-2 px-4 py-3 border-b border-border">
          <Search className="w-4 h-4 text-muted-foreground/60 flex-shrink-0" />
          <input
            ref={inputRef}
            type="text"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            onKeyDown={handleKeyDown}
            placeholder="Search IOCs, techniques, threat actors, sessions, assets..."
            className="flex-1 bg-transparent text-sm text-foreground placeholder:text-muted-foreground/40 focus:outline-none"
            autoComplete="off"
            spellCheck={false}
          />
          {loading && <Loader2 className="w-4 h-4 text-cyan-400 animate-spin flex-shrink-0" />}
          <kbd className="hidden sm:inline-flex items-center gap-0.5 px-1.5 py-0.5 text-[10px] text-muted-foreground/50 bg-secondary/50 border border-border rounded font-mono">
            ESC
          </kbd>
          <button
            onClick={onClose}
            className="sm:hidden p-1 text-muted-foreground/50 hover:text-foreground transition-colors"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Results */}
        <div ref={listRef} className="max-h-[50vh] overflow-y-auto">
          {query.trim().length < 2 && (
            <div className="px-4 py-8 text-center">
              <Search className="w-8 h-8 text-muted-foreground/20 mx-auto mb-2" />
              <p className="text-xs text-muted-foreground/50">
                Type at least 2 characters to search across all intelligence data
              </p>
              <div className="flex flex-wrap justify-center gap-2 mt-3">
                {Object.entries(CATEGORY_CONFIG).map(([key, cfg]) => {
                  const Icon = cfg.icon;
                  return (
                    <span key={key} className={cn('inline-flex items-center gap-1 text-[10px] px-2 py-0.5 rounded-full', cfg.bgColor, cfg.color)}>
                      <Icon className="w-2.5 h-2.5" />
                      {cfg.label}
                    </span>
                  );
                })}
              </div>
            </div>
          )}

          {query.trim().length >= 2 && results.length === 0 && !loading && (
            <div className="px-4 py-8 text-center">
              <p className="text-xs text-muted-foreground/50">
                No results found for &ldquo;{query.trim()}&rdquo;
              </p>
            </div>
          )}

          {Object.entries(grouped).map(([category, hits]) => {
            const cfg = CATEGORY_CONFIG[category as SearchHit['category']];
            if (!cfg) return null;
            const Icon = cfg.icon;

            return (
              <div key={category}>
                {/* Section header */}
                <div className="px-4 py-1.5 bg-secondary/30 border-b border-border/50 flex items-center gap-1.5">
                  <Icon className={cn('w-3 h-3', cfg.color)} />
                  <span className={cn('text-[10px] font-medium uppercase tracking-wider', cfg.color)}>
                    {cfg.label}s
                  </span>
                  <span className="text-[10px] text-muted-foreground/40">
                    ({hits.length})
                  </span>
                </div>

                {/* Items */}
                {hits.map((hit) => {
                  const idx = flatIndex++;
                  const isSelected = idx === selectedIndex;
                  const hasMultipleSessions = hit.sessions && hit.sessions.length > 1;
                  const expandKey = `${hit.category}::${hit.value}`;
                  const isExpanded = expandedKeys.has(expandKey);

                  return (
                    <div key={`${hit.category}-${hit.value}-${idx}`}>
                      {/* Main row */}
                      <button
                        data-search-item
                        onClick={() => {
                          if (hasMultipleSessions) {
                            toggleExpand(hit);
                          } else {
                            handleSelect(hit);
                          }
                        }}
                        className={cn(
                          'w-full text-left px-4 py-2 border-b border-border/30 transition-colors',
                          isSelected ? 'bg-cyan-500/10' : 'hover:bg-secondary/40'
                        )}
                      >
                        <div className="flex items-start justify-between gap-2">
                          <div className="min-w-0 flex-1">
                            <div className="flex items-center gap-1.5">
                              {/* Expand chevron for multi-session results */}
                              {hasMultipleSessions && (
                                <ChevronRight className={cn(
                                  'w-3 h-3 flex-shrink-0 text-muted-foreground/50 transition-transform duration-150',
                                  isExpanded && 'rotate-90'
                                )} />
                              )}
                              <span className={cn('text-xs font-medium', isSelected ? 'text-cyan-300' : 'text-foreground')}>
                                {hit.value}
                              </span>
                              {hit.meta?.type && (
                                <span className="text-[9px] px-1.5 py-0 rounded bg-secondary text-muted-foreground/70">
                                  {hit.meta.type}
                                </span>
                              )}
                              {hit.meta?.confidence && (
                                <span className={cn(
                                  'text-[9px] px-1.5 py-0 rounded',
                                  hit.meta.confidence === 'High' ? 'bg-red-500/15 text-red-400' :
                                  hit.meta.confidence === 'Medium' ? 'bg-yellow-500/15 text-yellow-400' :
                                  'bg-green-500/15 text-green-400'
                                )}>
                                  {hit.meta.confidence}
                                </span>
                              )}
                            </div>
                            {hit.context && (
                              <div className={cn('text-[10px] text-muted-foreground mt-0.5 truncate', hasMultipleSessions && 'ml-[18px]')}>
                                {hit.context}
                              </div>
                            )}
                          </div>
                          {/* Right side: session count badge OR single session name */}
                          {hasMultipleSessions ? (
                            <span className={cn(
                              'text-[9px] px-2 py-0.5 rounded-full flex-shrink-0 font-medium',
                              cfg.bgColor, cfg.color
                            )}>
                              {hit.sessions!.length} sessions
                            </span>
                          ) : (
                            hit.session_name && (
                              <div className="text-[10px] text-muted-foreground/50 text-right flex-shrink-0 max-w-[140px] truncate">
                                {hit.session_name}
                              </div>
                            )
                          )}
                        </div>
                      </button>

                      {/* Expanded session list */}
                      {isExpanded && hit.sessions && (
                        <div className="border-b border-border/30 bg-secondary/20">
                          {hit.sessions.map((session) => (
                            <button
                              key={session.id}
                              onClick={() => handleSelect(hit, session.id)}
                              className="w-full text-left pl-10 pr-4 py-1.5 hover:bg-cyan-500/10 transition-colors flex items-center gap-2 group"
                            >
                              <ExternalLink className="w-2.5 h-2.5 text-muted-foreground/30 group-hover:text-cyan-400 flex-shrink-0 transition-colors" />
                              <span className="text-[11px] text-muted-foreground group-hover:text-foreground truncate transition-colors">
                                {session.name}
                              </span>
                            </button>
                          ))}
                        </div>
                      )}
                    </div>
                  );
                })}
              </div>
            );
          })}
        </div>

        {/* Footer */}
        {results.length > 0 && (
          <div className="px-4 py-2 border-t border-border bg-secondary/20 flex items-center justify-between">
            <span className="text-[10px] text-muted-foreground/50">
              {total} result{total !== 1 ? 's' : ''} found
            </span>
            <div className="flex items-center gap-3 text-[10px] text-muted-foreground/40">
              <span className="flex items-center gap-1">
                <kbd className="px-1 py-0 bg-secondary/50 border border-border rounded text-[9px] font-mono">
                  <span className="text-[8px]">&#9650;&#9660;</span>
                </kbd>
                Navigate
              </span>
              <span className="flex items-center gap-1">
                <kbd className="px-1 py-0 bg-secondary/50 border border-border rounded text-[9px] font-mono">
                  <span className="text-[8px]">&#9166;</span>
                </kbd>
                Open
              </span>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
