/**
 * IOCPivot — a lightweight modal that answers "where else have we seen this
 * indicator?" for a single IOC. Lists the other incidents that share it (with
 * click-through) and the threat actors those incidents are attributed to.
 * Backed by GET /api/iocs/occurrences.
 */
import { useEffect, useState } from 'react';
import { X, Crosshair, FileText, UserRound, Loader2, PencilLine, Trash2, Folder, Copy, Check } from 'lucide-react';
import { fetchIocOccurrences, deleteManualIoc, type IocOccurrences } from '@/lib/api';
import { defangIoc } from '@/lib/defang';
import { cn } from '@/lib/utils';
import EntityAnnotations from './EntityAnnotations';
import AddToCaseDialog from './AddToCaseDialog';
import EnrichmentPanel from './enrichment/EnrichmentPanel';

interface Props {
  type: string;
  value: string;
  /** Navigate to a session (closes the pivot). */
  onSelectSession: (sessionId: string) => void;
  onClose: () => void;
  /** Called after a manual indicator is removed, so the host can refresh. */
  onRemoved?: () => void;
}

const SEV_COLOR: Record<string, string> = {
  Critical: 'text-red-400',
  High: 'text-orange-400',
  Medium: 'text-yellow-400',
  Low: 'text-emerald-400',
};

export default function IOCPivot({ type, value, onSelectSession, onClose, onRemoved }: Props) {
  const [data, setData] = useState<IocOccurrences | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [removing, setRemoving] = useState(false);
  const [addToCase, setAddToCase] = useState(false);
  const [copied, setCopied] = useState(false);

  const copyValue = async () => {
    try {
      await navigator.clipboard.writeText(value);
      setCopied(true);
      setTimeout(() => setCopied(false), 1200);
    } catch { /* clipboard unavailable */ }
  };

  const removeManual = async () => {
    if (!window.confirm('Remove this manually-added indicator?')) return;
    setRemoving(true);
    try {
      await deleteManualIoc(type, value);
      onRemoved?.();
      onClose();
    } catch {
      setError('Could not remove the indicator.');
      setRemoving(false);
    }
  };

  useEffect(() => {
    const handler = (e: KeyboardEvent) => { if (e.key === 'Escape') onClose(); };
    document.addEventListener('keydown', handler);
    return () => document.removeEventListener('keydown', handler);
  }, [onClose]);

  useEffect(() => {
    let alive = true;
    setLoading(true);
    setError(null);
    fetchIocOccurrences(type, value)
      .then((d) => { if (alive) setData(d); })
      .catch(() => { if (alive) setError('Could not load correlations.'); })
      .finally(() => { if (alive) setLoading(false); });
    return () => { alive = false; };
  }, [type, value]);

  const others = data ? data.sessions : [];

  return (
    <>
    <div
      className="fixed inset-0 z-[130] flex items-center justify-center p-4 bg-black/70 backdrop-blur-sm"
      onClick={onClose}
    >
      <div
        className="bg-navy-950 border border-border rounded-lg shadow-2xl w-full max-w-4xl max-h-[85vh] flex flex-col"
        onClick={(e) => e.stopPropagation()}
        role="dialog"
        aria-modal="true"
        aria-label="Indicator detail"
      >
        <div className="px-5 py-4 border-b border-border flex items-start gap-3">
          <div className="w-8 h-8 rounded-full bg-cyan-500/15 flex items-center justify-center flex-shrink-0">
            <Crosshair className="w-4 h-4 text-muted-foreground" />
          </div>
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-2">
              <span className="text-[9px] uppercase tracking-wide font-mono px-1.5 py-px rounded bg-secondary/60 text-muted-foreground flex-shrink-0">{type}</span>
              <h2 className="text-sm font-semibold text-foreground font-mono truncate">{defangIoc(type, value)}</h2>
              <button onClick={() => void copyValue()} className="text-muted-foreground/50 hover:text-foreground flex-shrink-0" title="Copy indicator">
                {copied ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
              </button>
            </div>
            <p className="text-[11px] text-muted-foreground mt-0.5">
              {loading ? 'Loading…' : `Seen in ${others.length} incident${others.length !== 1 ? 's' : ''}`}
              {data?.actors.length ? ` · ${data.actors.length} attributed actor${data.actors.length !== 1 ? 's' : ''}` : ''}
            </p>
          </div>
          <button
            onClick={() => setAddToCase(true)}
            className="inline-flex items-center gap-1.5 text-[11px] px-2 py-1 rounded-md border border-border text-muted-foreground hover:text-foreground hover:bg-secondary/50 transition-colors flex-shrink-0"
            title="Add this indicator to a case"
          >
            <Folder className="w-3 h-3" /> Add to case
          </button>
          <button onClick={onClose} className="text-muted-foreground hover:text-foreground p-1 -m-1" aria-label="Close">
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Two columns: what WE know (left) vs. external context + analyst notes (right). */}
        <div className="flex-1 min-h-0 grid grid-cols-1 md:grid-cols-2 md:divide-x divide-border overflow-hidden">
          <div className="px-5 py-4 overflow-y-auto min-h-0">
          {loading && (
            <div className="flex items-center gap-2 text-xs text-muted-foreground py-6 justify-center">
              <Loader2 className="w-4 h-4 animate-spin" /> Loading…
            </div>
          )}
          {error && <p className="text-xs text-red-400 py-4">{error}</p>}

          {!loading && !error && data && (
            <>
              {data.manual && (
                <div className="mb-4 rounded-md border border-primary/25 bg-primary/5 px-3 py-2.5">
                  <div className="flex items-center gap-1.5 mb-1.5">
                    <PencilLine className="w-3 h-3 text-primary" />
                    <span className="text-[10px] uppercase tracking-wide text-primary font-semibold flex-1">Manually added</span>
                    <button onClick={() => void removeManual()} disabled={removing} className="inline-flex items-center gap-1 text-[10px] text-muted-foreground hover:text-red-400 disabled:opacity-60" title="Remove indicator">
                      {removing ? <Loader2 className="w-3 h-3 animate-spin" /> : <Trash2 className="w-3 h-3" />} Remove
                    </button>
                  </div>
                  {data.manual.context && <p className="text-xs text-foreground/90 mb-1">{data.manual.context}</p>}
                  <div className="flex flex-wrap gap-x-3 gap-y-0.5 text-[10px] text-muted-foreground">
                    {data.manual.confidence && <span>Confidence: <span className="text-foreground/80">{data.manual.confidence}</span></span>}
                    {data.manual.source && <span>Source: <span className="text-foreground/80">{data.manual.source}</span></span>}
                    {data.manual.authorName && <span>Added by {data.manual.authorName}</span>}
                  </div>
                </div>
              )}

              {data.actors.length > 0 && (
                <div className="mb-4">
                  <h3 className="text-[11px] uppercase tracking-wide text-muted-foreground/70 mb-2">
                    Attributed actors
                  </h3>
                  <div className="flex flex-wrap gap-1.5">
                    {data.actors.map((a) => (
                      <span key={a.id} className="inline-flex items-center gap-1 text-xs px-2 py-0.5 rounded-full bg-cyan-500/15 text-cyan-300 border border-cyan-500/20">
                        <UserRound className="w-3 h-3" /> {a.name}
                      </span>
                    ))}
                  </div>
                </div>
              )}

              <h3 className="text-[11px] uppercase tracking-wide text-muted-foreground/70 mb-2">
                Seen in {others.length} incident{others.length !== 1 ? 's' : ''}
              </h3>
              {others.length === 0 ? (
                <p className="text-xs text-muted-foreground py-2">
                  This indicator does not appear in any other incident.
                </p>
              ) : (
                <ul className="space-y-1">
                  {others.map((s) => (
                    <li key={s.id}>
                      <button
                        onClick={() => { onSelectSession(s.id); onClose(); }}
                        className="w-full flex items-center gap-2 text-left px-2 py-1.5 rounded hover:bg-secondary/60 transition-colors group"
                      >
                        <FileText className="w-3.5 h-3.5 text-muted-foreground/60 flex-shrink-0" />
                        <span className="flex-1 min-w-0 text-xs text-foreground truncate group-hover:text-cyan-300">
                          {s.name}
                        </span>
                        {s.severity && (
                          <span className={cn('text-[10px] font-medium flex-shrink-0', SEV_COLOR[s.severity] ?? 'text-muted-foreground')}>
                            {s.severity}
                          </span>
                        )}
                        <span className="text-[10px] text-muted-foreground/50 flex-shrink-0">
                          {new Date(s.createdAt).toLocaleDateString()}
                        </span>
                      </button>
                    </li>
                  ))}
                </ul>
              )}
            </>
          )}
          </div>

          <div className="px-5 py-4 overflow-y-auto min-h-0 border-t md:border-t-0 border-border space-y-4">
            <EnrichmentPanel type={type} value={value} />
            <div className="border-t border-border pt-4">
              <EntityAnnotations entityType="ioc" iocType={type} iocValue={value} label={value} />
            </div>
          </div>
        </div>
      </div>
    </div>

    <AddToCaseDialog
      open={addToCase}
      ioc={{ type, value }}
      onClose={() => setAddToCase(false)}
      onChanged={onRemoved}
    />
    </>
  );
}
