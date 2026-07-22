/**
 * IOCPivot — a lightweight modal that answers "where else have we seen this
 * indicator?" for a single IOC. Lists the other incidents that share it (with
 * click-through) and the threat actors those incidents are attributed to.
 * Backed by GET /api/iocs/occurrences.
 */
import { useEffect, useState } from 'react';
import { X, Crosshair, FileText, UserRound, Loader2 } from 'lucide-react';
import { fetchIocOccurrences, type IocOccurrences } from '@/lib/api';
import { defangIoc } from '@/lib/defang';
import { cn } from '@/lib/utils';

interface Props {
  type: string;
  value: string;
  /** Navigate to a session (closes the pivot). */
  onSelectSession: (sessionId: string) => void;
  onClose: () => void;
}

const SEV_COLOR: Record<string, string> = {
  Critical: 'text-red-400',
  High: 'text-orange-400',
  Medium: 'text-yellow-400',
  Low: 'text-emerald-400',
};

export default function IOCPivot({ type, value, onSelectSession, onClose }: Props) {
  const [data, setData] = useState<IocOccurrences | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

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
    <div
      className="fixed inset-0 z-[130] flex items-center justify-center p-4 bg-black/70 backdrop-blur-sm"
      onClick={onClose}
    >
      <div
        className="bg-navy-950 border border-border rounded-lg shadow-2xl w-full max-w-lg max-h-[80vh] flex flex-col"
        onClick={(e) => e.stopPropagation()}
        role="dialog"
        aria-modal="true"
        aria-label="Indicator correlations"
      >
        <div className="px-5 py-4 border-b border-border flex items-start gap-3">
          <div className="w-8 h-8 rounded-full bg-cyan-500/15 flex items-center justify-center flex-shrink-0">
            <Crosshair className="w-4 h-4 text-muted-foreground" />
          </div>
          <div className="flex-1 min-w-0">
            <h2 className="text-sm font-semibold text-foreground">Indicator correlations</h2>
            <p className="text-xs text-muted-foreground mt-0.5 font-mono break-all">
              <span className="text-muted-foreground/60">{type}</span> {defangIoc(type, value)}
            </p>
          </div>
          <button onClick={onClose} className="text-muted-foreground hover:text-foreground p-1 -m-1" aria-label="Close">
            <X className="w-4 h-4" />
          </button>
        </div>

        <div className="px-5 py-4 overflow-y-auto">
          {loading && (
            <div className="flex items-center gap-2 text-xs text-muted-foreground py-6 justify-center">
              <Loader2 className="w-4 h-4 animate-spin" /> Loading…
            </div>
          )}
          {error && <p className="text-xs text-red-400 py-4">{error}</p>}

          {!loading && !error && data && (
            <>
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
      </div>
    </div>
  );
}
