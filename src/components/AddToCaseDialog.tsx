/**
 * AddToCaseDialog — attach the current session to an existing investigation, or
 * spin up a new one seeded with it. Self-contained (fetches its own case list).
 */
import { useState, useEffect } from 'react';
import { Folder, Plus, X, Loader2 } from 'lucide-react';
import { Button } from './ui/button';
import { cn } from '@/lib/utils';
import * as api from '@/lib/api';
import type { CaseSummary } from '@/lib/api';

interface Props {
  open: boolean;
  sessionId: string;
  onClose: () => void;
  onShowToast?: (message: string, type?: 'success' | 'error' | 'info') => void;
  onChanged?: () => void;
}

export default function AddToCaseDialog({ open, sessionId, onClose, onShowToast, onChanged }: Props) {
  const [cases, setCases] = useState<CaseSummary[]>([]);
  const [loading, setLoading] = useState(false);
  const [newName, setNewName] = useState('');
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    if (!open) return;
    setLoading(true);
    api.fetchCases().then((d) => setCases(d.cases)).catch(() => setCases([])).finally(() => setLoading(false));
  }, [open]);

  if (!open) return null;

  const linkExisting = async (c: CaseSummary) => {
    setBusy(true);
    try {
      await api.linkCaseSessions(c.id, [sessionId]);
      onShowToast?.(`Added to "${c.name}"`, 'success');
      onChanged?.();
      onClose();
    } catch { onShowToast?.('Failed to add to case', 'error'); } finally { setBusy(false); }
  };

  const createNew = async () => {
    if (!newName.trim()) return;
    setBusy(true);
    try {
      await api.createCase({ name: newName.trim(), sessionId });
      onShowToast?.(`Created case "${newName.trim()}"`, 'success');
      onChanged?.();
      onClose();
    } catch { onShowToast?.('Failed to create case', 'error'); } finally { setBusy(false); }
  };

  return (
    <div className="fixed inset-0 z-[120] flex items-center justify-center p-4 bg-black/70 backdrop-blur-sm" onClick={onClose}>
      <div className="bg-navy-950 border border-border rounded-lg shadow-2xl w-full max-w-sm max-h-[80vh] flex flex-col" onClick={(e) => e.stopPropagation()} role="dialog" aria-modal="true" aria-label="Add session to case">
        <div className="px-5 py-4 border-b border-border flex items-center gap-2">
          <Folder className="w-4 h-4 text-violet-400" />
          <h2 className="text-sm font-semibold text-foreground flex-1">Add to case</h2>
          <button onClick={onClose} className="text-muted-foreground hover:text-foreground p-1 -m-1"><X className="w-4 h-4" /></button>
        </div>
        <div className="px-5 py-4 overflow-y-auto">
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
        </div>
      </div>
    </div>
  );
}
