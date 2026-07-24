/**
 * RuleViewer — a modal showing one detection rule's full body, with copy and
 * download. Opened from the Detection Coverage panel's rule list; mirrors the
 * IOCPivot overlay so the two detail surfaces feel the same.
 *
 * Rule syntax highlighting reuses `highlightRule` from src/lib/rule-highlight,
 * the same renderer the per-session DetectionRulesTable uses.
 */
import { useEffect, useState } from 'react';
import { X, Copy, Check, Download, FileText, ExternalLink } from 'lucide-react';
import { cn } from '@/lib/utils';
import { highlightRule } from '@/lib/rule-highlight';
import type { CoverageRule } from '@/lib/api';

const RULE_TYPE_COLOR: Record<string, string> = {
  sigma: 'text-purple-400',
  yara: 'text-orange-400',
  suricata: 'text-cyan-400',
};

/** Conventional file extension per rule language. */
const RULE_EXT: Record<string, string> = { sigma: 'yml', yara: 'yar', suricata: 'rules' };

interface Props {
  rule: CoverageRule;
  onClose: () => void;
  /** Open the incident this rule came from (closes the viewer). */
  onSelectSession?: (id: string) => void;
}

export default function RuleViewer({ rule, onClose, onSelectSession }: Props) {
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    const handler = (e: KeyboardEvent) => { if (e.key === 'Escape') onClose(); };
    document.addEventListener('keydown', handler);
    return () => document.removeEventListener('keydown', handler);
  }, [onClose]);

  const copy = async () => {
    try {
      await navigator.clipboard.writeText(rule.rule_content);
      setCopied(true);
      setTimeout(() => setCopied(false), 1400);
    } catch { /* clipboard unavailable */ }
  };

  const download = () => {
    // A short header keeps provenance with the rule once it leaves the app.
    const header = [
      `# ${rule.rule_name}`,
      `# Type: ${rule.rule_type} | Source: ${rule.source}${rule.confidence ? ` | Confidence: ${rule.confidence}` : ''}`,
      rule.technique_id ? `# ATT&CK: ${rule.technique_id}` : null,
      `# Incident: ${rule.session_name}`,
      '',
    ].filter(Boolean).join('\n');
    const blob = new Blob([header + rule.rule_content], { type: 'text/plain;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    const safe = rule.rule_name.replace(/[^\w.-]+/g, '_').slice(0, 80) || 'detection-rule';
    a.download = `${safe}.${RULE_EXT[rule.rule_type] ?? 'txt'}.txt`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div
      className="fixed inset-0 z-[130] flex items-center justify-center p-4 bg-black/70 backdrop-blur-sm"
      onClick={onClose}
    >
      <div
        className="bg-navy-950 border border-border rounded-lg shadow-2xl w-full max-w-3xl max-h-[85vh] flex flex-col"
        onClick={(e) => e.stopPropagation()}
        role="dialog"
        aria-modal="true"
        aria-label="Detection rule"
      >
        <div className="px-5 py-4 border-b border-border flex items-start gap-3">
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-2">
              <span className={cn('text-[9px] uppercase font-mono px-1.5 py-px rounded bg-secondary/60', RULE_TYPE_COLOR[rule.rule_type] ?? 'text-muted-foreground')}>
                {rule.rule_type}
              </span>
              <h2 className="text-sm font-semibold text-foreground truncate">{rule.rule_name}</h2>
            </div>
            <p className="text-[11px] text-muted-foreground mt-0.5">
              {rule.source === 'extracted' ? 'Extracted' : 'AI generated'}
              {rule.confidence ? ` · ${rule.confidence} confidence` : ''}
              {rule.technique_id ? ` · ATT&CK ${rule.technique_id}` : ' · unmapped'}
            </p>
          </div>
          <button
            onClick={() => void copy()}
            className="inline-flex items-center gap-1.5 text-[11px] px-2 py-1 rounded-md border border-border text-muted-foreground hover:text-foreground hover:bg-secondary/50 transition-colors flex-shrink-0"
            title="Copy rule to clipboard"
          >
            {copied ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
            {copied ? 'Copied' : 'Copy'}
          </button>
          <button
            onClick={download}
            className="inline-flex items-center gap-1.5 text-[11px] px-2 py-1 rounded-md border border-border text-muted-foreground hover:text-foreground hover:bg-secondary/50 transition-colors flex-shrink-0"
            title="Download rule as a .txt file"
          >
            <Download className="w-3 h-3" /> Download
          </button>
          <button onClick={onClose} className="text-muted-foreground hover:text-foreground p-1 -m-1" aria-label="Close">
            <X className="w-4 h-4" />
          </button>
        </div>

        <div className="px-5 py-4 overflow-y-auto">
          {rule.description && <p className="text-xs text-muted-foreground mb-3">{rule.description}</p>}

          {rule.rule_content.trim() ? (
            <pre className="bg-navy-900 border border-border rounded p-3 text-[11px] font-mono text-foreground/85 overflow-x-auto whitespace-pre leading-relaxed">
              {highlightRule(rule.rule_content, rule.rule_type)}
            </pre>
          ) : (
            <p className="text-xs text-muted-foreground py-4">
              This rule has no stored body — re-run or re-save the incident to index its content.
            </p>
          )}

          {onSelectSession && (
            <button
              onClick={() => { onSelectSession(rule.session_id); onClose(); }}
              className="mt-3 inline-flex items-center gap-1.5 text-[11px] text-muted-foreground hover:text-cyan-300 transition-colors"
              title="Open the incident this rule came from"
            >
              <FileText className="w-3 h-3" />
              <span className="truncate max-w-[420px]">{rule.session_name}</span>
              <ExternalLink className="w-3 h-3 flex-shrink-0" />
            </button>
          )}
        </div>
      </div>
    </div>
  );
}
