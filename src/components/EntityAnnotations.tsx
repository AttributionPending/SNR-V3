/**
 * EntityAnnotations — a comment thread attached to an IOC or a threat actor.
 * Reusable across the Search workspace, the IOC pivot, and the actor view. The
 * canonical entity key is derived server-side, so this just passes the raw
 * (ioc_type, ioc_value) or actor_id.
 */
import { useState, useEffect, useCallback } from 'react';
import { MessageSquare, Send, Trash2, Loader2, Pencil, Check, X } from 'lucide-react';
import { useAuth } from '@/contexts/AuthContext';
import { formatTimestamp } from '@/lib/utils';
import * as api from '@/lib/api';
import type { EntityRef, EntityAnnotation } from '@/lib/api';

type Props =
  | { entityType: 'ioc'; iocType: string; iocValue: string; label?: string }
  | { entityType: 'actor'; actorId: string; label?: string };

function toRef(p: Props): EntityRef {
  return p.entityType === 'ioc'
    ? { entity_type: 'ioc', ioc_type: p.iocType, ioc_value: p.iocValue, label: p.label }
    : { entity_type: 'actor', actor_id: p.actorId, label: p.label };
}

export default function EntityAnnotations(props: Props) {
  const { user } = useAuth();
  const ref = toRef(props);
  const refKey = props.entityType === 'ioc' ? `ioc:${props.iocType}:${props.iocValue}` : `actor:${props.actorId}`;

  const [items, setItems] = useState<EntityAnnotation[]>([]);
  const [loading, setLoading] = useState(true);
  const [draft, setDraft] = useState('');
  const [busy, setBusy] = useState(false);
  const [editId, setEditId] = useState<string | null>(null);
  const [editText, setEditText] = useState('');

  const load = useCallback(async () => {
    setLoading(true);
    try { setItems(await api.listEntityAnnotations(ref)); } catch { setItems([]); } finally { setLoading(false); }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [refKey]);

  useEffect(() => { void load(); }, [load]);

  const add = async () => {
    if (!draft.trim()) return;
    setBusy(true);
    try { const a = await api.addEntityAnnotation(ref, draft.trim()); setItems((xs) => [a, ...xs]); setDraft(''); }
    catch { /* surfaced by caller toasts elsewhere; keep inline */ } finally { setBusy(false); }
  };
  const remove = async (id: string) => {
    setItems((xs) => xs.filter((x) => x.id !== id));
    try { await api.deleteEntityAnnotation(id); } catch { void load(); }
  };
  const saveEdit = async (id: string) => {
    const content = editText.trim();
    if (!content) return;
    setItems((xs) => xs.map((x) => (x.id === id ? { ...x, content } : x)));
    setEditId(null);
    try { await api.updateEntityAnnotation(id, content); } catch { void load(); }
  };

  const canModify = (a: EntityAnnotation) => a.user_id === user?.id;
  const canDelete = (a: EntityAnnotation) => a.user_id === user?.id || user?.role === 'admin';

  return (
    <div>
      <div className="flex items-center gap-1.5 mb-2 text-[10px] uppercase tracking-wide text-muted-foreground/70">
        <MessageSquare className="w-3 h-3" /> Comments {items.length > 0 && `(${items.length})`}
      </div>

      <div className="flex gap-2 mb-3">
        <textarea
          value={draft} onChange={(e) => setDraft(e.target.value)}
          onKeyDown={(e) => { if (e.key === 'Enter' && (e.metaKey || e.ctrlKey)) void add(); }}
          placeholder="Add a comment…  (⌘/Ctrl+Enter)"
          rows={2}
          className="flex-1 bg-secondary/40 border border-border rounded-md px-2.5 py-1.5 text-xs text-foreground resize-none focus:outline-none focus:ring-1 focus:ring-cyan-500/40"
        />
        <button onClick={() => void add()} disabled={!draft.trim() || busy} className="self-end px-2.5 py-1.5 rounded-md bg-primary text-primary-foreground text-xs disabled:opacity-40 flex items-center gap-1">
          {busy ? <Loader2 className="w-3 h-3 animate-spin" /> : <Send className="w-3 h-3" />}
        </button>
      </div>

      {loading ? (
        <div className="flex items-center gap-2 text-xs text-muted-foreground py-3 justify-center"><Loader2 className="w-3.5 h-3.5 animate-spin" />Loading…</div>
      ) : items.length === 0 ? (
        <p className="text-xs text-muted-foreground/70 py-1">No comments yet.</p>
      ) : (
        <ul className="space-y-2">
          {items.map((a) => (
            <li key={a.id} className="border border-border/60 rounded-md px-2.5 py-2 bg-secondary/20 group">
              <div className="flex items-center justify-between gap-2 mb-1">
                <span className="text-[11px] font-medium text-foreground/90">{a.author_name}</span>
                <div className="flex items-center gap-1.5">
                  <span className="text-[10px] text-muted-foreground/50">{formatTimestamp(a.created_at)}{a.updated_at !== a.created_at ? ' · edited' : ''}</span>
                  {canModify(a) && editId !== a.id && (
                    <button onClick={() => { setEditId(a.id); setEditText(a.content); }} className="text-muted-foreground/40 hover:text-foreground opacity-0 group-hover:opacity-100" title="Edit"><Pencil className="w-3 h-3" /></button>
                  )}
                  {canDelete(a) && editId !== a.id && (
                    <button onClick={() => void remove(a.id)} className="text-muted-foreground/40 hover:text-red-400 opacity-0 group-hover:opacity-100" title="Delete"><Trash2 className="w-3 h-3" /></button>
                  )}
                </div>
              </div>
              {editId === a.id ? (
                <div className="flex gap-1.5">
                  <textarea value={editText} onChange={(e) => setEditText(e.target.value)} rows={2} className="flex-1 bg-secondary/40 border border-border rounded px-2 py-1 text-xs resize-none focus:outline-none focus:ring-1 focus:ring-cyan-500/40" />
                  <div className="flex flex-col gap-1">
                    <button onClick={() => void saveEdit(a.id)} className="text-emerald-400 p-1" title="Save"><Check className="w-3.5 h-3.5" /></button>
                    <button onClick={() => setEditId(null)} className="text-muted-foreground p-1" title="Cancel"><X className="w-3.5 h-3.5" /></button>
                  </div>
                </div>
              ) : (
                <p className="text-xs text-foreground/85 whitespace-pre-wrap break-words">{a.content}</p>
              )}
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
