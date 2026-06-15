import { Copy, Filter, ChevronDown, ChevronUp } from 'lucide-react';
import { useState, useMemo } from 'react';
import { Button } from './ui/button';
import { cn } from '@/lib/utils';
import { highlightRule } from '@/lib/rule-highlight';
import type { DetectionRule } from '@/types';

const RULE_TYPE_COLORS: Record<string, string> = {
  sigma: 'text-purple-400',
  yara: 'text-orange-400',
  suricata: 'text-cyan-400',
};

const RULE_TYPE_BG: Record<string, string> = {
  sigma: 'bg-purple-900/30 border-purple-500/30',
  yara: 'bg-orange-900/30 border-orange-500/30',
  suricata: 'bg-cyan-900/30 border-cyan-500/30',
};

const SOURCE_LABEL: Record<string, string> = {
  extracted: 'Extracted',
  generated: 'AI Generated',
};

interface Props {
  rules: DetectionRule[];
}

export default function DetectionRulesTable({ rules }: Props) {
  const [filter, setFilter] = useState<string>('all');
  const [expandedIdx, setExpandedIdx] = useState<number | null>(null);
  const [copied, setCopied] = useState<string | null>(null);

  const types = ['all', ...Array.from(new Set(rules.map((r) => r.rule_type)))];
  const visible = filter === 'all' ? rules : rules.filter((r) => r.rule_type === filter);

  const copyValue = async (value: string, id: string) => {
    try {
      await navigator.clipboard.writeText(value);
    } catch {
      const el = document.createElement('textarea');
      el.value = value;
      el.style.position = 'fixed';
      el.style.opacity = '0';
      document.body.appendChild(el);
      el.select();
      document.execCommand('copy');
      document.body.removeChild(el);
    }
    setCopied(id);
    setTimeout(() => setCopied(null), 1500);
  };

  const copyAll = async () => {
    const text = visible.map((r) =>
      `# [${r.rule_type.toUpperCase()}] ${r.rule_name}\n# ${r.description}\n${r.rule_content}`
    ).join('\n\n---\n\n');
    await copyValue(text, 'all');
  };

  if (rules.length === 0) {
    return (
      <div className="text-center py-8 text-muted-foreground text-sm">
        No detection rules extracted or generated from this analysis.
      </div>
    );
  }

  return (
    <div className="space-y-3">
      {/* Filter bar */}
      <div className="flex items-center gap-2 flex-wrap">
        <Filter className="w-3.5 h-3.5 text-muted-foreground" />
        {types.map((t) => (
          <button
            key={t}
            onClick={() => setFilter(t)}
            className={cn(
              'text-[10px] uppercase px-2 py-0.5 rounded transition-colors',
              filter === t
                ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/30'
                : 'text-muted-foreground hover:text-foreground'
            )}
          >
            {t} {t !== 'all' && `(${rules.filter((r) => r.rule_type === t).length})`}
          </button>
        ))}
        <div className="ml-auto">
          <Button variant="ghost" size="sm" onClick={copyAll} className="text-xs h-7">
            {copied === 'all' ? '✓ Copied' : 'Copy All'}
          </Button>
        </div>
      </div>

      {/* Rules list */}
      <div className="space-y-2">
        {visible.map((rule, idx) => {
          const globalIdx = rules.indexOf(rule);
          const isExpanded = expandedIdx === globalIdx;
          const ruleId = `rule-${globalIdx}`;

          return (
            <div
              key={globalIdx}
              className={cn(
                'rounded-lg border overflow-hidden transition-colors',
                RULE_TYPE_BG[rule.rule_type] ?? 'bg-secondary/30 border-border'
              )}
            >
              {/* Header */}
              <button
                className="w-full flex items-center gap-2 px-3 py-2 text-left"
                onClick={() => setExpandedIdx(isExpanded ? null : globalIdx)}
              >
                <span className={cn(
                  'text-[9px] font-bold uppercase px-1.5 py-0.5 rounded',
                  RULE_TYPE_COLORS[rule.rule_type] ?? 'text-foreground'
                )}>
                  {rule.rule_type}
                </span>
                <span className="text-xs text-foreground font-medium flex-1 truncate">
                  {rule.rule_name}
                </span>
                <span className={cn(
                  'text-[9px] px-1.5 py-0.5 rounded',
                  rule.source === 'extracted'
                    ? 'bg-green-900/50 text-green-300'
                    : 'bg-blue-900/50 text-blue-300'
                )}>
                  {SOURCE_LABEL[rule.source] ?? rule.source}
                </span>
                <span className={cn(
                  'text-[9px] px-1.5 py-0.5 rounded',
                  rule.confidence === 'High' ? 'bg-orange-900/50 text-orange-300'
                  : rule.confidence === 'Medium' ? 'bg-yellow-900/50 text-yellow-300'
                  : 'bg-green-900/50 text-green-300'
                )}>
                  {rule.confidence}
                </span>
                {isExpanded
                  ? <ChevronUp className="w-3.5 h-3.5 text-muted-foreground flex-shrink-0" />
                  : <ChevronDown className="w-3.5 h-3.5 text-muted-foreground flex-shrink-0" />}
              </button>

              {/* Expanded content */}
              {isExpanded && (
                <div className="px-3 pb-3 space-y-2">
                  <p className="text-[11px] text-muted-foreground leading-relaxed">
                    {rule.description}
                  </p>
                  {rule.related_technique && (
                    <div className="text-[10px] text-cyan-400/80">
                      ATT&CK: <span className="font-mono">{rule.related_technique}</span>
                    </div>
                  )}
                  <div className="relative">
                    <pre className="bg-navy-950 border border-border rounded p-2.5 text-[10px] font-mono text-foreground/80 overflow-x-auto whitespace-pre leading-relaxed max-h-64 overflow-y-auto">
                      {highlightRule(rule.rule_content, rule.rule_type)}
                    </pre>
                    <button
                      onClick={(e) => { e.stopPropagation(); copyValue(rule.rule_content, ruleId); }}
                      className="absolute top-1.5 right-1.5 text-muted-foreground hover:text-cyan-400 transition-colors p-1 rounded bg-navy-900/80"
                      aria-label="Copy rule"
                    >
                      {copied === ruleId ? (
                        <span className="text-[9px] text-green-400">✓</span>
                      ) : (
                        <Copy className="w-3 h-3" />
                      )}
                    </button>
                  </div>
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}
