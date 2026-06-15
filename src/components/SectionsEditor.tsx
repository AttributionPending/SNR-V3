import { useState } from 'react';
import { ChevronUp, ChevronDown, Trash2, Plus, RotateCcw } from 'lucide-react';
import { Button } from './ui/button';
import { cn } from '@/lib/utils';
import type { BriefSection } from '@/types';
import { DEFAULT_SECTIONS } from '@/lib/sections';

interface Props {
  sections: BriefSection[];
  onChange: (sections: BriefSection[]) => void;
}

const TYPE_OPTIONS: Array<{ value: BriefSection['type']; label: string; badge: string }> = [
  { value: 'text',       label: 'Text',       badge: 'text-blue-400'   },
  { value: 'bullets',    label: 'Bullets',    badge: 'text-green-400'  },
  { value: 'numbered',   label: 'Numbered',   badge: 'text-yellow-400' },
  { value: 'techniques', label: 'Techniques', badge: 'text-cyan-400'   },
  { value: 'iocs',       label: 'IOCs',       badge: 'text-orange-400' },
];

const TYPE_LABELS: Record<BriefSection['type'], string> = {
  text:       'Text',
  bullets:    'Bullets',
  numbered:   'Numbered',
  techniques: 'Techniques (auto)',
  iocs:       'IOCs (auto)',
};

const AUTO_TYPES = new Set<BriefSection['type']>(['techniques', 'iocs']);

export default function SectionsEditor({ sections, onChange }: Props) {
  const [expandedKey, setExpandedKey] = useState<string | null>(null);

  const update = (index: number, patch: Partial<BriefSection>) => {
    const next = sections.map((s, i) => i === index ? { ...s, ...patch } : s);
    onChange(next);
  };

  const moveUp = (index: number) => {
    if (index === 0) return;
    const next = [...sections];
    [next[index - 1], next[index]] = [next[index], next[index - 1]];
    onChange(next);
  };

  const moveDown = (index: number) => {
    if (index === sections.length - 1) return;
    const next = [...sections];
    [next[index], next[index + 1]] = [next[index + 1], next[index]];
    onChange(next);
  };

  const remove = (index: number) => {
    onChange(sections.filter((_, i) => i !== index));
  };

  const addSection = () => {
    const newSection: BriefSection = {
      key: `section_${Date.now()}`,
      label: 'New Section',
      description: 'Describe what Claude should write in this section',
      type: 'text',
      enabled: true,
    };
    onChange([...sections, newSection]);
    setExpandedKey(newSection.key);
  };

  const resetToDefaults = () => {
    onChange(DEFAULT_SECTIONS);
    setExpandedKey(null);
  };

  return (
    <div className="space-y-2">
      <p className="text-xs text-muted-foreground mb-3">
        Configure which sections appear in the stakeholder brief email. The order here determines the order in the email.
        <span className="text-cyan-400/80"> Auto sections</span> (Techniques, IOCs) are populated from the AI analysis — Claude does not write them.
        All other sections become fields in the Claude output schema.
      </p>

      <div className="space-y-1.5">
        {sections.map((section, index) => {
          const isExpanded = expandedKey === section.key;
          const isAuto = AUTO_TYPES.has(section.type);

          return (
            <div
              key={section.key}
              className={cn(
                'rounded-lg border transition-colors',
                section.enabled ? 'border-border bg-navy-900/50' : 'border-border/40 bg-navy-950 opacity-60',
              )}
            >
              {/* Row header */}
              <div className="flex items-center gap-2 px-3 py-2">
                {/* Enable toggle */}
                <input
                  type="checkbox"
                  checked={section.enabled}
                  onChange={(e) => update(index, { enabled: e.target.checked })}
                  className="h-3.5 w-3.5 shrink-0 accent-cyan-500"
                  title={section.enabled ? 'Disable section' : 'Enable section'}
                />

                {/* Label (click to expand) */}
                <button
                  className="flex-1 text-left"
                  onClick={() => setExpandedKey(isExpanded ? null : section.key)}
                >
                  <span className={cn('text-xs font-medium', section.enabled ? 'text-foreground' : 'text-muted-foreground')}>
                    {section.label}
                  </span>
                  <span className={cn('ml-2 text-[10px] font-mono', TYPE_OPTIONS.find(t => t.value === section.type)?.badge ?? 'text-muted-foreground')}>
                    {TYPE_LABELS[section.type]}
                  </span>
                </button>

                {/* Move up/down */}
                <div className="flex items-center gap-0.5">
                  <button
                    onClick={() => moveUp(index)}
                    disabled={index === 0}
                    className="p-1 rounded text-muted-foreground/60 hover:text-foreground hover:bg-secondary/50 disabled:opacity-20 disabled:cursor-not-allowed transition-colors"
                    title="Move up"
                  >
                    <ChevronUp className="w-3 h-3" />
                  </button>
                  <button
                    onClick={() => moveDown(index)}
                    disabled={index === sections.length - 1}
                    className="p-1 rounded text-muted-foreground/60 hover:text-foreground hover:bg-secondary/50 disabled:opacity-20 disabled:cursor-not-allowed transition-colors"
                    title="Move down"
                  >
                    <ChevronDown className="w-3 h-3" />
                  </button>
                  <button
                    onClick={() => remove(index)}
                    className="p-1 rounded text-muted-foreground/40 hover:text-red-400 hover:bg-red-400/10 transition-colors"
                    title="Remove section"
                  >
                    <Trash2 className="w-3 h-3" />
                  </button>
                </div>
              </div>

              {/* Expanded detail editor */}
              {isExpanded && (
                <div className="px-3 pb-3 pt-1 border-t border-border/50 space-y-2.5">
                  <div className="grid grid-cols-2 gap-2">
                    {/* Label */}
                    <div>
                      <div className="text-[9px] uppercase tracking-wide text-muted-foreground mb-1">Section Label</div>
                      <input
                        type="text"
                        value={section.label}
                        onChange={(e) => update(index, { label: e.target.value })}
                        className="w-full bg-secondary/30 border border-border rounded px-2 py-1 text-xs text-foreground focus:outline-none focus:ring-1 focus:ring-cyan-500/50"
                        placeholder="Section heading shown in email"
                      />
                    </div>
                    {/* Type */}
                    <div>
                      <div className="text-[9px] uppercase tracking-wide text-muted-foreground mb-1">Type</div>
                      <select
                        value={section.type}
                        onChange={(e) => update(index, { type: e.target.value as BriefSection['type'] })}
                        className="w-full bg-secondary/30 border border-border rounded px-2 py-1 text-xs text-foreground focus:outline-none focus:ring-1 focus:ring-cyan-500/50"
                      >
                        {TYPE_OPTIONS.map(opt => (
                          <option key={opt.value} value={opt.value}>{opt.label}</option>
                        ))}
                      </select>
                    </div>
                  </div>

                  {/* Key (read-only) */}
                  <div>
                    <div className="text-[9px] uppercase tracking-wide text-muted-foreground mb-1">JSON Key</div>
                    <input
                      type="text"
                      value={section.key}
                      onChange={(e) => {
                        const clean = e.target.value.toLowerCase().replace(/[^a-z0-9_]/g, '_');
                        update(index, { key: clean });
                      }}
                      className="w-full bg-secondary/20 border border-border/60 rounded px-2 py-1 text-[10px] font-mono text-muted-foreground focus:outline-none focus:ring-1 focus:ring-cyan-500/30"
                      placeholder="snake_case_key"
                    />
                    <p className="text-[9px] text-muted-foreground/50 mt-0.5">Used as the output field name in Claude's JSON response. Must be unique.</p>
                  </div>

                  {/* Description — only for non-auto sections */}
                  {!isAuto && (
                    <div>
                      <div className="text-[9px] uppercase tracking-wide text-muted-foreground mb-1">Claude Instructions</div>
                      <textarea
                        value={section.description}
                        onChange={(e) => update(index, { description: e.target.value })}
                        rows={2}
                        className="w-full bg-secondary/30 border border-border rounded px-2 py-1 text-xs text-foreground focus:outline-none focus:ring-1 focus:ring-cyan-500/50 resize-none leading-relaxed"
                        placeholder="Describe what Claude should write in this section…"
                      />
                      <p className="text-[9px] text-muted-foreground/50 mt-0.5">
                        This is sent to Claude as the schema field description. Be specific about length, format, and audience focus.
                      </p>
                    </div>
                  )}

                  {isAuto && (
                    <p className="text-[10px] text-cyan-400/60 bg-cyan-400/5 border border-cyan-400/10 rounded px-2 py-1.5">
                      Auto-populated from Phase 1 analysis. Claude does not generate this section — it renders directly from the structured technical data.
                    </p>
                  )}
                </div>
              )}
            </div>
          );
        })}
      </div>

      {/* Actions */}
      <div className="flex gap-2 pt-2">
        <Button
          variant="outline"
          size="sm"
          className="text-xs gap-1.5 flex-1"
          onClick={addSection}
        >
          <Plus className="w-3 h-3" />
          Add Section
        </Button>
        <Button
          variant="ghost"
          size="sm"
          className="text-xs gap-1.5 text-muted-foreground hover:text-foreground"
          onClick={resetToDefaults}
          title="Reset to default sections"
        >
          <RotateCcw className="w-3 h-3" />
          Reset Defaults
        </Button>
      </div>
    </div>
  );
}
