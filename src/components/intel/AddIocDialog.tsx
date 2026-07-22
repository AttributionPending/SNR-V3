/**
 * AddIocDialog — add a manual (analyst-curated) indicator that isn't tied to any
 * report. Captures type, value, an optional context note, confidence, and a
 * free-text source. On save it POSTs to /api/iocs and the indicator then appears
 * in the merged Indicators holdings, flagged "manual".
 */
import { useEffect, useState } from 'react';
import { X, Loader2, Plus } from 'lucide-react';
import * as api from '@/lib/api';

const IOC_TYPES = ['ipv4', 'ipv6', 'domain', 'url', 'md5', 'sha1', 'sha256', 'email', 'filename', 'registry', 'user_agent'];
const CONFIDENCE = ['Low', 'Medium', 'High'];

interface Props {
  onClose: () => void;
  onAdded: () => void;
}

export default function AddIocDialog({ onClose, onAdded }: Props) {
  const [type, setType] = useState('ipv4');
  const [value, setValue] = useState('');
  const [context, setContext] = useState('');
  const [confidence, setConfidence] = useState('Medium');
  const [source, setSource] = useState('');
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const handler = (e: KeyboardEvent) => { if (e.key === 'Escape') onClose(); };
    document.addEventListener('keydown', handler);
    return () => document.removeEventListener('keydown', handler);
  }, [onClose]);

  const submit = async () => {
    const v = value.trim();
    if (!v) { setError('Enter an indicator value.'); return; }
    setSaving(true);
    setError(null);
    try {
      await api.createManualIoc({ type, value: v, context: context.trim(), confidence, source: source.trim() });
      onAdded();
      onClose();
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Failed to add indicator');
      setSaving(false);
    }
  };

  const field = 'w-full bg-navy-900 border border-border rounded px-2.5 py-1.5 text-xs text-foreground focus:outline-none focus:ring-1 focus:ring-primary/50';

  return (
    <div className="fixed inset-0 z-[130] flex items-center justify-center p-4 bg-black/70 backdrop-blur-sm" onClick={onClose}>
      <div className="bg-navy-950 border border-border rounded-lg shadow-2xl w-full max-w-md flex flex-col" onClick={(e) => e.stopPropagation()} role="dialog" aria-modal="true" aria-label="Add indicator">
        <div className="px-5 py-4 border-b border-border flex items-center gap-2">
          <Plus className="w-4 h-4 text-muted-foreground" />
          <h2 className="text-sm font-semibold text-foreground flex-1">Add indicator</h2>
          <button onClick={onClose} className="text-muted-foreground hover:text-foreground p-1 -m-1" aria-label="Close"><X className="w-4 h-4" /></button>
        </div>

        <div className="px-5 py-4 space-y-3">
          <div className="flex gap-2">
            <div className="w-32 flex-shrink-0">
              <label className="block text-[11px] font-medium text-muted-foreground mb-1">Type</label>
              <select className={field} value={type} onChange={(e) => setType(e.target.value)}>
                {IOC_TYPES.map((t) => <option key={t} value={t}>{t}</option>)}
              </select>
            </div>
            <div className="flex-1 min-w-0">
              <label className="block text-[11px] font-medium text-muted-foreground mb-1">Value</label>
              <input className={`${field} font-mono`} value={value} autoFocus placeholder="203.0.113.9" onChange={(e) => setValue(e.target.value)} onKeyDown={(e) => { if (e.key === 'Enter') void submit(); }} />
            </div>
          </div>

          <div>
            <label className="block text-[11px] font-medium text-muted-foreground mb-1">Context <span className="text-muted-foreground/50">(optional)</span></label>
            <textarea className={`${field} resize-none`} rows={2} value={context} placeholder="Why you're tracking this…" onChange={(e) => setContext(e.target.value)} />
          </div>

          <div className="flex gap-2">
            <div className="w-32 flex-shrink-0">
              <label className="block text-[11px] font-medium text-muted-foreground mb-1">Confidence</label>
              <select className={field} value={confidence} onChange={(e) => setConfidence(e.target.value)}>
                {CONFIDENCE.map((c) => <option key={c} value={c}>{c}</option>)}
              </select>
            </div>
            <div className="flex-1 min-w-0">
              <label className="block text-[11px] font-medium text-muted-foreground mb-1">Source <span className="text-muted-foreground/50">(optional)</span></label>
              <input className={field} value={source} placeholder="CISA advisory, partner feed…" onChange={(e) => setSource(e.target.value)} />
            </div>
          </div>

          {error && <p className="text-xs text-red-400">{error}</p>}
        </div>

        <div className="px-5 py-3 border-t border-border flex justify-end gap-2">
          <button onClick={onClose} className="text-xs px-3 py-1.5 rounded-md border border-border text-muted-foreground hover:text-foreground hover:bg-secondary/50">Cancel</button>
          <button onClick={() => void submit()} disabled={saving} className="inline-flex items-center gap-1.5 text-xs px-3 py-1.5 rounded-md bg-primary text-primary-foreground disabled:opacity-60">
            {saving ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Plus className="w-3.5 h-3.5" />} Add indicator
          </button>
        </div>
      </div>
    </div>
  );
}
