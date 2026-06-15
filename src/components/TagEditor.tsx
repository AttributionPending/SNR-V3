/**
 * TagEditor — inline tag management component.
 * Shows existing tags as removable pills and an input to add new ones.
 * Used in WorkflowCanvas session header when a session is active.
 */
import { useState, useRef, useEffect, useCallback } from 'react';
import { X, Plus, Tag } from 'lucide-react';
import { cn } from '@/lib/utils';

interface TagEditorProps {
  tags: string[];
  allTags: string[];
  onChange: (tags: string[]) => void;
  readOnly?: boolean;
  compact?: boolean;
}

export default function TagEditor({ tags, allTags, onChange, readOnly = false, compact = false }: TagEditorProps) {
  const [inputValue, setInputValue] = useState('');
  const [isAdding, setIsAdding] = useState(false);
  const [suggestions, setSuggestions] = useState<string[]>([]);
  const [selectedSuggestion, setSelectedSuggestion] = useState(0);
  const inputRef = useRef<HTMLInputElement>(null);
  const containerRef = useRef<HTMLDivElement>(null);

  // Focus input when entering add mode
  useEffect(() => {
    if (isAdding) {
      setTimeout(() => inputRef.current?.focus(), 50);
    }
  }, [isAdding]);

  // Close on outside click
  useEffect(() => {
    if (!isAdding) return;
    const handler = (e: MouseEvent) => {
      if (containerRef.current && !containerRef.current.contains(e.target as Node)) {
        setIsAdding(false);
        setInputValue('');
        setSuggestions([]);
      }
    };
    document.addEventListener('mousedown', handler);
    return () => document.removeEventListener('mousedown', handler);
  }, [isAdding]);

  // Update suggestions based on input
  const updateSuggestions = useCallback((value: string) => {
    if (!value.trim()) {
      setSuggestions([]);
      setSelectedSuggestion(0);
      return;
    }
    const lower = value.trim().toLowerCase();
    const filtered = allTags
      .filter((t) => t.includes(lower) && !tags.includes(t))
      .slice(0, 5);
    setSuggestions(filtered);
    setSelectedSuggestion(0);
  }, [allTags, tags]);

  const addTag = useCallback((tag: string) => {
    const normalized = tag.trim().toLowerCase();
    if (!normalized || normalized.length > 30) return;
    if (tags.includes(normalized)) return;
    if (tags.length >= 20) return;

    onChange([...tags, normalized]);
    setInputValue('');
    setSuggestions([]);
    // Keep input focused for quick multi-add
    setTimeout(() => inputRef.current?.focus(), 50);
  }, [tags, onChange]);

  const removeTag = useCallback((tag: string) => {
    onChange(tags.filter((t) => t !== tag));
  }, [tags, onChange]);

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter') {
      e.preventDefault();
      if (suggestions.length > 0 && suggestions[selectedSuggestion]) {
        addTag(suggestions[selectedSuggestion]);
      } else if (inputValue.trim()) {
        addTag(inputValue);
      }
    } else if (e.key === 'Escape') {
      e.preventDefault();
      setIsAdding(false);
      setInputValue('');
      setSuggestions([]);
    } else if (e.key === 'ArrowDown') {
      e.preventDefault();
      setSelectedSuggestion((prev) => Math.min(prev + 1, suggestions.length - 1));
    } else if (e.key === 'ArrowUp') {
      e.preventDefault();
      setSelectedSuggestion((prev) => Math.max(prev - 1, 0));
    } else if (e.key === 'Backspace' && !inputValue && tags.length > 0) {
      // Remove last tag on backspace when input is empty
      removeTag(tags[tags.length - 1]);
    }
  };

  // Tag color palette — deterministic by tag content
  const tagColor = (tag: string): string => {
    const colors = [
      'bg-cyan-500/15 text-cyan-400 border-cyan-500/30',
      'bg-purple-500/15 text-purple-400 border-purple-500/30',
      'bg-emerald-500/15 text-emerald-400 border-emerald-500/30',
      'bg-orange-500/15 text-orange-400 border-orange-500/30',
      'bg-pink-500/15 text-pink-400 border-pink-500/30',
      'bg-yellow-500/15 text-yellow-400 border-yellow-500/30',
      'bg-blue-500/15 text-blue-400 border-blue-500/30',
      'bg-red-500/15 text-red-400 border-red-500/30',
    ];
    let hash = 0;
    for (let i = 0; i < tag.length; i++) {
      hash = ((hash << 5) - hash) + tag.charCodeAt(i);
      hash |= 0;
    }
    return colors[Math.abs(hash) % colors.length];
  };

  return (
    <div ref={containerRef} className={cn('flex items-center gap-1 flex-wrap', compact && 'gap-0.5')}>
      {/* Existing tags */}
      {tags.map((tag) => (
        <span
          key={tag}
          className={cn(
            'inline-flex items-center gap-0.5 rounded border transition-colors',
            tagColor(tag),
            compact ? 'text-[8px] px-1 py-0 h-3.5' : 'text-[10px] px-1.5 py-0.5',
          )}
        >
          {tag}
          {!readOnly && (
            <button
              onClick={(e) => { e.stopPropagation(); removeTag(tag); }}
              className="hover:text-foreground transition-colors ml-0.5"
              aria-label={`Remove tag ${tag}`}
            >
              <X className={cn(compact ? 'w-2 h-2' : 'w-2.5 h-2.5')} />
            </button>
          )}
        </span>
      ))}

      {/* Add tag input */}
      {!readOnly && (
        <>
          {isAdding ? (
            <div className="relative">
              <input
                ref={inputRef}
                type="text"
                value={inputValue}
                onChange={(e) => {
                  setInputValue(e.target.value);
                  updateSuggestions(e.target.value);
                }}
                onKeyDown={handleKeyDown}
                placeholder="Add tag..."
                className={cn(
                  'bg-secondary/50 border border-border rounded px-1.5 py-0.5 text-foreground placeholder:text-muted-foreground/40 focus:outline-none focus:ring-1 focus:ring-cyan-500/50 focus:border-cyan-500/50',
                  compact ? 'text-[9px] w-16 h-4' : 'text-[10px] w-24',
                )}
                maxLength={30}
                autoComplete="off"
                spellCheck={false}
              />
              {/* Autocomplete suggestions */}
              {suggestions.length > 0 && (
                <div className="absolute top-full left-0 mt-1 w-40 bg-navy-800 border border-border rounded-md shadow-lg overflow-hidden z-50">
                  {suggestions.map((s, i) => (
                    <button
                      key={s}
                      onClick={() => addTag(s)}
                      className={cn(
                        'w-full text-left px-2 py-1 text-[10px] transition-colors',
                        i === selectedSuggestion ? 'bg-cyan-500/15 text-cyan-300' : 'text-foreground hover:bg-secondary/50'
                      )}
                    >
                      <Tag className="w-2.5 h-2.5 inline mr-1 opacity-50" />
                      {s}
                    </button>
                  ))}
                </div>
              )}
            </div>
          ) : (
            <button
              onClick={() => setIsAdding(true)}
              className={cn(
                'inline-flex items-center gap-0.5 rounded border border-dashed border-border text-muted-foreground/50 hover:text-muted-foreground hover:border-border/80 transition-colors',
                compact ? 'text-[8px] px-1 py-0 h-3.5' : 'text-[10px] px-1.5 py-0.5',
              )}
              title="Add tag"
            >
              <Plus className={cn(compact ? 'w-2 h-2' : 'w-2.5 h-2.5')} />
              {!compact && 'tag'}
            </button>
          )}
        </>
      )}
    </div>
  );
}
