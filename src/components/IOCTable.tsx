import { Copy, Filter, AlertTriangle, Download, Shield, ShieldOff, FileSpreadsheet, Flag } from 'lucide-react';
import { useState } from 'react';
import { Button } from './ui/button';
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from './ui/tooltip';
import { cn } from '@/lib/utils';
import { defangIoc } from '@/lib/defang';
import type { IOC } from '@/types';

const IOC_TYPE_COLORS: Record<string, string> = {
  ipv4: 'text-red-400',
  ipv6: 'text-red-400',
  domain: 'text-orange-400',
  url: 'text-orange-400',
  md5: 'text-purple-400',
  sha1: 'text-purple-400',
  sha256: 'text-purple-400',
  email: 'text-blue-400',
  filename: 'text-yellow-400',
  registry: 'text-pink-400',
  user_agent: 'text-teal-400',
};

/** Stable identity key for an IOC — used for false-positive tracking. */
export function iocKey(ioc: Pick<IOC, 'type' | 'value'>): string {
  return `${ioc.type}::${ioc.value.toLowerCase().trim()}`;
}

interface Props {
  iocs: IOC[];
  /** Keys (type::value) of IOCs marked as false positives */
  falsePositives?: string[];
  /** Toggle false-positive state for an IOC key; absence hides the FP feature */
  onToggleFalsePositive?: (key: string) => void;
}

export default function IOCTable({ iocs, falsePositives = [], onToggleFalsePositive }: Props) {
  const [filter, setFilter] = useState<string>('all');
  const [hideInvalid, setHideInvalid] = useState(false);
  const [hideFp, setHideFp] = useState(false);
  const [defang, setDefang] = useState(false);
  const [copied, setCopied] = useState<string | null>(null);

  const fpSet = new Set(falsePositives);
  const types = ['all', ...Array.from(new Set(iocs.map((i) => i.type)))];

  const invalidCount = iocs.filter(i => i.validation && !i.validation.valid).length;
  const fpCount = iocs.filter(i => fpSet.has(iocKey(i))).length;

  let visible = filter === 'all' ? iocs : iocs.filter((i) => i.type === filter);
  if (hideInvalid) visible = visible.filter(i => !i.validation || i.validation.valid);
  if (hideFp) visible = visible.filter(i => !fpSet.has(iocKey(i)));

  // Copy/export operate on non-FP rows only (false positives are excluded from outputs)
  const exportable = visible.filter(i => !fpSet.has(iocKey(i)));

  const displayValue = (ioc: IOC) => (defang ? defangIoc(ioc.type, ioc.value) : ioc.value);

  const writeClipboard = async (text: string, marker: string) => {
    try {
      await navigator.clipboard.writeText(text);
      setCopied(marker);
      setTimeout(() => setCopied(null), 1500);
    } catch {
      // Fallback for non-HTTPS or denied permission
      const el = document.createElement('textarea');
      el.value = text;
      el.style.position = 'fixed';
      el.style.opacity = '0';
      document.body.appendChild(el);
      el.select();
      document.execCommand('copy');
      document.body.removeChild(el);
      setCopied(marker);
      setTimeout(() => setCopied(null), 1500);
    }
  };

  const copyValue = (ioc: IOC) => writeClipboard(displayValue(ioc), ioc.value);

  const copyAll = () => {
    const text = exportable.map((i) => `[${i.type}] ${displayValue(i)}`).join('\n');
    writeClipboard(text, 'all');
  };

  const downloadBlob = (content: string, mime: string, filename: string) => {
    const blob = new Blob([content], { type: mime });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    a.click();
    URL.revokeObjectURL(url);
  };

  const downloadTxt = () => {
    // Group IOCs by type for a clean TXT layout
    const groups = new Map<string, string[]>();
    for (const ioc of exportable) {
      const list = groups.get(ioc.type) ?? [];
      list.push(displayValue(ioc));
      groups.set(ioc.type, list);
    }
    const lines: string[] = [];
    groups.forEach((values, type) => {
      lines.push(`# ${type.toUpperCase()} (${values.length})`);
      values.forEach(v => lines.push(v));
      lines.push('');
    });
    downloadBlob(lines.join('\n'), 'text/plain', `SNR-IOCs-${new Date().toISOString().split('T')[0]}.txt`);
  };

  const downloadCsv = () => {
    const esc = (s: string) => `"${String(s ?? '').replace(/"/g, '""')}"`;
    const rows = [
      'type,value,confidence,context',
      ...exportable.map((i) => [esc(i.type), esc(displayValue(i)), esc(i.confidence), esc(i.context)].join(',')),
    ];
    downloadBlob(rows.join('\r\n'), 'text/csv', `SNR-IOCs-${new Date().toISOString().split('T')[0]}.csv`);
  };

  if (iocs.length === 0) {
    return (
      <div className="text-center py-8 text-muted-foreground text-sm">
        No IOCs extracted from this analysis.
      </div>
    );
  }

  return (
    <TooltipProvider>
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
              {t} {t !== 'all' && `(${iocs.filter((i) => i.type === t).length})`}
            </button>
          ))}

          {/* Invalid IOC toggle */}
          {invalidCount > 0 && (
            <button
              onClick={() => setHideInvalid(!hideInvalid)}
              className={cn(
                'text-[10px] px-2 py-0.5 rounded transition-colors flex items-center gap-1',
                hideInvalid
                  ? 'bg-red-500/20 text-red-300 border border-red-500/30'
                  : 'text-muted-foreground hover:text-foreground'
              )}
            >
              <AlertTriangle className="w-3 h-3" />
              {hideInvalid ? `${invalidCount} hidden` : `${invalidCount} invalid`}
            </button>
          )}

          {/* False-positive toggle */}
          {fpCount > 0 && (
            <button
              onClick={() => setHideFp(!hideFp)}
              className={cn(
                'text-[10px] px-2 py-0.5 rounded transition-colors flex items-center gap-1',
                hideFp
                  ? 'bg-yellow-500/20 text-yellow-300 border border-yellow-500/30'
                  : 'text-muted-foreground hover:text-foreground'
              )}
              title="False positives are excluded from copies and exports"
            >
              <Flag className="w-3 h-3" />
              {hideFp ? `${fpCount} FP hidden` : `${fpCount} FP`}
            </button>
          )}

          <div className="ml-auto flex items-center gap-1">
            {/* Defang toggle */}
            <Tooltip>
              <TooltipTrigger asChild>
                <button
                  onClick={() => setDefang(!defang)}
                  className={cn(
                    'text-[10px] px-2 py-1 rounded transition-colors flex items-center gap-1 border',
                    defang
                      ? 'bg-emerald-500/15 text-emerald-300 border-emerald-500/30'
                      : 'text-muted-foreground hover:text-foreground border-transparent'
                  )}
                >
                  {defang ? <Shield className="w-3 h-3" /> : <ShieldOff className="w-3 h-3" />}
                  {defang ? 'Defanged' : 'Defang'}
                </button>
              </TooltipTrigger>
              <TooltipContent side="bottom" className="text-xs">
                {defang ? 'Showing safe values (hxxp, [.]) — copies and exports match' : 'Show defanged values safe for tickets and email'}
              </TooltipContent>
            </Tooltip>
            <Button variant="ghost" size="sm" onClick={copyAll} className="text-xs h-7">
              {copied === 'all' ? '✓ Copied' : 'Copy All'}
            </Button>
            <Button variant="ghost" size="sm" onClick={downloadCsv} className="text-xs h-7 gap-1">
              <FileSpreadsheet className="w-3 h-3" />
              CSV
            </Button>
            <Button variant="ghost" size="sm" onClick={downloadTxt} className="text-xs h-7 gap-1">
              <Download className="w-3 h-3" />
              TXT
            </Button>
          </div>
        </div>

        {/* Table */}
        <div className="rounded-lg border border-border overflow-hidden">
          <table className="w-full text-xs">
            <thead>
              <tr className="bg-navy-900 border-b border-border">
                <th className="text-left px-3 py-2 text-[10px] uppercase tracking-wide text-muted-foreground w-24">Type</th>
                <th className="text-left px-3 py-2 text-[10px] uppercase tracking-wide text-muted-foreground">Value</th>
                <th className="text-left px-3 py-2 text-[10px] uppercase tracking-wide text-muted-foreground hidden sm:table-cell">Context</th>
                <th className="text-left px-3 py-2 text-[10px] uppercase tracking-wide text-muted-foreground w-20">Confidence</th>
                <th className="w-14" />
              </tr>
            </thead>
            <tbody>
              {visible.map((ioc, idx) => {
                const isInvalid = ioc.validation && !ioc.validation.valid;
                const hasWarnings = ioc.validation?.warnings?.length ?? 0;
                const dupCount = ioc.duplicateCount ?? 1;
                const key = iocKey(ioc);
                const isFp = fpSet.has(key);

                return (
                  <tr
                    key={idx}
                    className={cn(
                      'border-b border-border/50 transition-colors group',
                      isInvalid
                        ? 'bg-red-950/30 hover:bg-red-950/50'
                        : isFp
                          ? 'bg-yellow-950/10 hover:bg-yellow-950/20 opacity-50'
                          : 'hover:bg-secondary/20'
                    )}
                  >
                    <td className="px-3 py-2">
                      <div className="flex items-center gap-1">
                        <span className={cn('font-mono font-semibold', IOC_TYPE_COLORS[ioc.type] ?? 'text-foreground')}>
                          {ioc.type.toUpperCase()}
                        </span>
                        {dupCount > 1 && (
                          <Tooltip>
                            <TooltipTrigger asChild>
                              <span className="text-[8px] bg-cyan-900/50 text-cyan-300 px-1 py-0.5 rounded font-mono">
                                x{dupCount}
                              </span>
                            </TooltipTrigger>
                            <TooltipContent side="right" className="text-xs">
                              {dupCount} duplicate IOCs merged
                            </TooltipContent>
                          </Tooltip>
                        )}
                        {isFp && (
                          <span className="text-[8px] bg-yellow-900/50 text-yellow-300 px-1 py-0.5 rounded font-mono">
                            FP
                          </span>
                        )}
                      </div>
                    </td>
                    <td className="px-3 py-2 font-mono text-foreground/90 max-w-[200px] truncate" title={displayValue(ioc)}>
                      <div className="flex items-center gap-1.5">
                        {(isInvalid || hasWarnings > 0) && (
                          <Tooltip>
                            <TooltipTrigger asChild>
                              <AlertTriangle className={cn(
                                'w-3 h-3 flex-shrink-0',
                                isInvalid ? 'text-red-400' : 'text-yellow-400'
                              )} />
                            </TooltipTrigger>
                            <TooltipContent side="bottom" className="text-xs max-w-xs">
                              <ul className="space-y-0.5">
                                {ioc.validation?.warnings.map((w, i) => (
                                  <li key={i} className={isInvalid ? 'text-red-300' : 'text-yellow-300'}>
                                    {w}
                                  </li>
                                ))}
                              </ul>
                            </TooltipContent>
                          </Tooltip>
                        )}
                        <span className={cn('truncate', (isInvalid || isFp) && 'line-through opacity-60')}>
                          {displayValue(ioc)}
                        </span>
                      </div>
                    </td>
                    <td className="px-3 py-2 text-muted-foreground max-w-[160px] truncate hidden sm:table-cell" title={ioc.context}>
                      {ioc.context}
                    </td>
                    <td className="px-3 py-2">
                      <span className={cn(
                        'text-[9px] px-1.5 py-0.5 rounded',
                        ioc.confidence === 'High' ? 'bg-orange-900/50 text-orange-300'
                        : ioc.confidence === 'Medium' ? 'bg-yellow-900/50 text-yellow-300'
                        : 'bg-green-900/50 text-green-300'
                      )}>
                        {ioc.confidence}
                      </span>
                    </td>
                    <td className="px-1 py-2">
                      <div className="flex items-center">
                        {onToggleFalsePositive && (
                          <Tooltip>
                            <TooltipTrigger asChild>
                              <button
                                onClick={() => onToggleFalsePositive(key)}
                                className={cn(
                                  'p-1 rounded transition-colors',
                                  isFp
                                    ? 'text-yellow-400 hover:text-yellow-300'
                                    : 'text-muted-foreground/0 group-hover:text-muted-foreground hover:!text-yellow-400'
                                )}
                                aria-label={isFp ? 'Unmark false positive' : 'Mark as false positive'}
                              >
                                <Flag className="w-3 h-3" />
                              </button>
                            </TooltipTrigger>
                            <TooltipContent side="left" className="text-xs">
                              {isFp ? 'Unmark false positive' : 'Mark as false positive (excluded from exports)'}
                            </TooltipContent>
                          </Tooltip>
                        )}
                        <button
                          onClick={() => copyValue(ioc)}
                          className="text-muted-foreground hover:text-cyan-400 transition-colors p-1 rounded"
                          aria-label="Copy IOC value"
                        >
                          {copied === ioc.value ? (
                            <span className="text-[9px] text-green-400">✓</span>
                          ) : (
                            <Copy className="w-3 h-3" />
                          )}
                        </button>
                      </div>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>
    </TooltipProvider>
  );
}
