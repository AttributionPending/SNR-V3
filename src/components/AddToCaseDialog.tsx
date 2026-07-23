/**
 * AddToCaseDialog — attach one or more sessions to an existing investigation, or
 * spin up a new one seeded with them. Used both for a single session ("Add to
 * case" on a session) and for pivoting an entity (an IOC's / actor's related
 * incidents) into a case. Self-contained (fetches its own case list).
 */
import { useState, useEffect, useMemo } from 'react';
import { Folder, Plus, X, Loader2 } from 'lucide-react';
import { Button } from './ui/button';
import { cn } from '@/lib/utils';
import * as api from '@/lib/api';
import type { CaseSummary } from '@/lib/api';

interface Props {
  open: boolean;
  /** A single session (back-compat) … */
  sessionId?: string;
  /** … or an explicit set (entity pivot). One of the two must be provided. */
  sessionIds?: string[];
  /**
   * …or an indicator to pin directly to the case as a first-class member
   * (used from the global Intelligence indicator list / IOC pivot). When set,
   * this takes precedence over sessionIds.
   */
  ioc?: { type: string; value: string };
  /** Optional context shown in the header (e.g. the IOC value or actor name). */
  label?: string;
  onClose: () => void;
  onShowToast?: (message: string, type?: 'success' | 'error' | 'info') => void;
  onChanged?: () => void;
}

export default function AddToCaseDialog({ open, sessionId, sessionIds, ioc, label, onClose, onShowToast, onChanged }: Props) {
  const [cases, setCases] = useState<CaseSummary[]>([]);
  const [loading, setLoading] = useState(false);
  const [newName, setNewName] = useState('');
  const [busy, setBusy] = useState(false);

  const ids = useMemo(
    () => (sessionIds && sessionIds.length ? sessionIds : sessionId ? [sessionId] : []),
    [sessionIds, sessionId],
  );

  useEffect(() => {
    if (!open) return;
    setLoading(true);
    setNewName('');
    api.fetchCases().then((d) => setCases(d.cases)).catch(() => setCases([])).finally(() => setLoading(false));
  }, [open]);

  if (!open) return null;

  const done = (msg: string) => { onShowToast?.(msg, 'success'); onChanged?.(); onClose(); };

  const linkExisting = async (c: CaseSummary) => {
    if (!ioc && ids.length === 0) return;
    setBusy(true);
    try {
      if (ioc) {
        await api.pinCaseIoc(c.id, { type: ioc.type, value: ioc.value });
        done(`Added ${ioc.value} to "${c.name}"`);
      } else {
        const { added } = await api.linkCaseSessions(c.id, ids);
        done(added > 0 ? `Added ${added} incident${added !== 1 ? 's' : ''} to "${c.name}"` : `Already in "${c.name}"`);
      }
    } catch { onShowToast?.('Failed to add to case', 'error'); } finally { setBusy(false); }
  };

  const createNew = async () => {
    if (!newName.trim() || (!ioc && ids.length === 0)) return;
    setBusy(true);
    try {
      const { case: created } = await api.createCase({ name: newName.trim() });
      if (ioc) await api.pinCaseIoc(created.id, { type: ioc.type, value: ioc.value });
      else await api.linkCaseSessions(created.id, ids);
      done(`Created case "${newName.trim()}"`);
    } catch { onShowToast?.('Failed to create case', 'error'); } finally { setBusy(false); }
  };

  return (
    <div className="fixed inset-0 z-[140] flex items-center justify-center p-4 bg-black/70 backdrop-blur-sm" onClick={onClose}>
      <div className="bg-navy-950 border border-border rounded-lg shadow-2xl w-full max-w-sm max-h-[80vh] flex flex-col" onClick={(e) => e.stopPropagation()} role="dialog" aria-modal="true" aria-label="Add to case">
        <div className="px-5 py-4 border-b border-border flex items-center gap-2">
          <Folder className="w-4 h-4 text-violet-400" />
          <div className="flex-1 min-w-0">
            <h2 className="text-sm font-semibold text-foreground">Add to case</h2>
            {ioc
              ? <p className="text-[11px] text-muted-foreground truncate font-mono">{ioc.value} <span className="text-muted-foreground/60">({ioc.type})</span></p>
              : label && <p className="text-[11px] text-muted-foreground truncate">{label} · {ids.length} incident{ids.length !== 1 ? 's' : ''}</p>}
          </div>
          <button onClick={onClose} className="text-muted-foreground hover:text-foreground p-1 -m-1"><X className="w-4 h-4" /></button>
        </div>
        <div className="px-5 py-4 overflow-y-auto">
          {!ioc && ids.length === 0 ? (
            <p className="text-xs text-muted-foreground py-2">No incidents to add for this entity.</p>
          ) : (
            <>
              <div className="flex gap-2 mb-3">
                <input
                  value={newName} onChange={(e) => setNewName(e.target.value)}
                  onKeyDown={(e) => { if (e.key === 'Enter') void createNew(); }}
                  placeholder="New case name…"
                  className="flex-1 bg-secondary/40 border border-border rounded-md px-3 py-1.5 text-xs focus:outline-none focus:ring-1 focus:ring-cyan-500/40"
                />
                <Button size="sm" className="text-xs gap-1" disabled={!newName.trim() || busy} onClick={() => void createNew()}><Plus className="w-3 h-3" />Create</Button>
              </div>
              <div className="text-[10px] uppercase tracking-wide text-muted-foreground/70 mb-1.5">Existing cases</div>
              {loading ? (
                <div className="flex items-center gap-2 text-xs text-muted-foreground py-4 justify-center"><Loader2 className="w-4 h-4 animate-spin" />Loading…</div>
              ) : cases.length === 0 ? (
                <p className="text-xs text-muted-foreground py-2">No cases yet — create one above.</p>
              ) : (
                <ul className="space-y-0.5">
                  {cases.map((c) => (
                    <li key={c.id}>
                      <button disabled={busy} onClick={() => void linkExisting(c)} className={cn('w-full flex items-center gap-2 text-left px-2 py-1.5 rounded hover:bg-secondary/60 text-xs', busy && 'opacity-50')}>
                        <Folder className="w-3 h-3 text-violet-400/70" />
                        <span className="flex-1 truncate">{c.name}</span>
                        <span className="text-[10px] text-muted-foreground/50">{c.status}</span>
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
