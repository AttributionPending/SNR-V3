import { useState, useEffect, useCallback } from 'react';
import { Plus, Loader2, Rss, Trash2, Play, FlaskConical } from 'lucide-react';
import {
  listFeeds, createFeed, updateFeed, deleteFeed, testFeed, pollFeedNow,
  type FeedRecord, type FeedInput,
} from '../lib/api';

/**
 * Admin/lead UI for threat-intel feeds: add TAXII/MISP/RSS sources, test, poll,
 * enable/disable, delete. Feeds auto-create analyzed sessions on their cadence.
 */
export default function FeedsPanel() {
  const [feeds, setFeeds] = useState<FeedRecord[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [busyId, setBusyId] = useState<string | null>(null);
  const [note, setNote] = useState<string | null>(null);

  const [showCreate, setShowCreate] = useState(false);
  const [form, setForm] = useState<FeedInput>({ name: '', type: 'rss', url: '', audience: 'soc', cadenceMinutes: 60, maxItems: 5, tags: [], allowInternal: false });
  const [tagsText, setTagsText] = useState('');
  const [creating, setCreating] = useState(false);

  const load = useCallback(async () => {
    setLoading(true); setError(null);
    try { setFeeds(await listFeeds()); }
    catch (e) { setError(e instanceof Error ? e.message : 'Failed to load'); }
    finally { setLoading(false); }
  }, []);
  useEffect(() => { void load(); }, [load]);

  async function handleCreate() {
    if (!form.name.trim() || !form.url.trim()) return;
    setCreating(true); setError(null);
    try {
      await createFeed({ ...form, tags: tagsText.split(',').map((t) => t.trim()).filter(Boolean) });
      setShowCreate(false);
      setForm({ name: '', type: 'rss', url: '', audience: 'soc', cadenceMinutes: 60, maxItems: 5, tags: [], allowInternal: false });
      setTagsText('');
      await load();
    } catch (e) { setError(e instanceof Error ? e.message : 'Failed'); }
    finally { setCreating(false); }
  }

  async function withBusy(id: string, fn: () => Promise<void>) {
    setBusyId(id); setError(null); setNote(null);
    try { await fn(); } catch (e) { setError(e instanceof Error ? e.message : 'Failed'); }
    finally { setBusyId(null); }
  }

  const fmt = (t: number | null) => (t ? new Date(t).toLocaleString() : 'never');

  if (loading) return <div className="flex items-center justify-center py-12 text-muted-foreground"><Loader2 className="w-5 h-5 animate-spin" /></div>;

  return (
    <div className="space-y-4">
      {error && <div className="text-xs text-red-400 bg-red-500/10 border border-red-500/20 rounded px-3 py-2">{error}</div>}
      {note && <div className="text-xs text-cyan-300 bg-cyan-500/10 border border-cyan-500/20 rounded px-3 py-2">{note}</div>}

      <div className="flex items-center justify-between">
        <p className="text-xs text-muted-foreground">Feeds poll TAXII / MISP / RSS sources and auto-analyze new items as sessions.</p>
        <button onClick={() => setShowCreate((v) => !v)} className="flex items-center gap-1.5 text-xs text-cyan-400 hover:text-cyan-300"><Plus className="w-3.5 h-3.5" /> Add feed</button>
      </div>

      {showCreate && (
        <div className="bg-muted/30 border border-border rounded p-3 space-y-2">
          <div className="flex flex-wrap gap-2">
            <input value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} placeholder="Name (e.g. CISA advisories)" className="flex-1 min-w-[160px] bg-background border border-border rounded px-2 py-1.5 text-xs" />
            <select value={form.type} onChange={(e) => setForm({ ...form, type: e.target.value as FeedInput['type'] })} className="bg-background border border-border rounded px-2 py-1.5 text-xs">
              <option value="rss">RSS/Atom</option>
              <option value="taxii">TAXII 2.1</option>
              <option value="misp">MISP</option>
            </select>
          </div>
          <input value={form.url} onChange={(e) => setForm({ ...form, url: e.target.value })} placeholder="Feed URL (https://…)" className="w-full bg-background border border-border rounded px-2 py-1.5 text-xs" />
          <input value={form.authToken ?? ''} onChange={(e) => setForm({ ...form, authToken: e.target.value })} placeholder="Auth token / API key (optional)" className="w-full bg-background border border-border rounded px-2 py-1.5 text-xs" />
          {form.type === 'taxii' && (
            <input value={form.config ?? ''} onChange={(e) => setForm({ ...form, config: e.target.value })} placeholder='Config JSON, e.g. {"collectionId":"…"}' className="w-full bg-background border border-border rounded px-2 py-1.5 text-xs font-mono" />
          )}
          <div className="flex flex-wrap gap-2 items-center">
            <input value={form.audience} onChange={(e) => setForm({ ...form, audience: e.target.value })} placeholder="audience" className="w-24 bg-background border border-border rounded px-2 py-1.5 text-xs" />
            <input value={tagsText} onChange={(e) => setTagsText(e.target.value)} placeholder="tags (comma-sep)" className="flex-1 min-w-[120px] bg-background border border-border rounded px-2 py-1.5 text-xs" />
            <label className="text-[11px] text-muted-foreground flex items-center gap-1">every <input type="number" value={form.cadenceMinutes} onChange={(e) => setForm({ ...form, cadenceMinutes: parseInt(e.target.value) || 60 })} className="w-16 bg-background border border-border rounded px-1.5 py-1 text-xs" /> min</label>
            <label className="text-[11px] text-muted-foreground flex items-center gap-1">max <input type="number" value={form.maxItems} onChange={(e) => setForm({ ...form, maxItems: parseInt(e.target.value) || 5 })} className="w-14 bg-background border border-border rounded px-1.5 py-1 text-xs" /></label>
          </div>
          <label className="flex items-start gap-2 text-[11px] text-muted-foreground cursor-pointer">
            <input type="checkbox" checked={!!form.allowInternal} onChange={(e) => setForm({ ...form, allowInternal: e.target.checked })} className="accent-cyan-500 mt-0.5" />
            <span>
              Internal host — self-hosted MISP/TAXII on a private network.
              <span className="block text-muted-foreground/60">
                Feeds may only reach public https addresses by default. Tick this to allow private ranges and http for this feed. Loopback and cloud-metadata stay blocked.
              </span>
            </span>
          </label>
          <div className="flex gap-2 justify-end">
            <button onClick={() => setShowCreate(false)} className="px-2.5 py-1.5 text-xs text-muted-foreground border border-border rounded">Cancel</button>
            <button onClick={handleCreate} disabled={creating} className="px-2.5 py-1.5 text-xs bg-cyan-600 hover:bg-cyan-500 disabled:opacity-50 text-white rounded flex items-center gap-1">{creating ? <Loader2 className="w-3 h-3 animate-spin" /> : <Plus className="w-3 h-3" />} Create</button>
          </div>
        </div>
      )}

      <div className="space-y-1.5">
        {feeds.length === 0 && <p className="text-xs text-muted-foreground py-4 text-center">No feeds configured.</p>}
        {feeds.map((f) => (
          <div key={f.id} className={`border border-border rounded px-3 py-2 ${f.enabled ? 'bg-muted/20' : 'opacity-60'}`}>
            <div className="flex items-center gap-2">
              <Rss className="w-4 h-4 text-muted-foreground" />
              <div className="flex-1 min-w-0">
                <div className="text-xs font-medium flex items-center gap-2">
                  {f.name}
                  <span className="text-[10px] uppercase text-muted-foreground">{f.type}</span>
                  {f.allow_internal === 1 && <span className="text-[10px] text-yellow-400" title="Permitted to reach private/internal addresses">internal</span>}
                </div>
                <div className="text-[10px] text-muted-foreground truncate">{f.url}</div>
                <div className="text-[10px] text-muted-foreground">every {f.cadence_minutes}m · audience {f.audience} · last polled {fmt(f.last_polled_at)}{f.last_status ? ` · ${f.last_status}` : ''}</div>
              </div>
              <div className="flex items-center gap-1.5 flex-shrink-0">
                <button title="Test" disabled={busyId === f.id} onClick={() => withBusy(f.id, async () => { const r = await testFeed(f.id); setNote(`${f.name}: fetched ${r.count} item(s). ${r.sample.slice(0, 3).join(' · ')}`); })} className="p-1.5 text-muted-foreground hover:text-cyan-300"><FlaskConical className="w-3.5 h-3.5" /></button>
                <button title="Poll now" disabled={busyId === f.id} onClick={() => withBusy(f.id, async () => { const r = await pollFeedNow(f.id); setNote(`${f.name}: ${r.ingested} new, ${r.skipped} duplicate, ${r.fetched} fetched`); await load(); })} className="p-1.5 text-muted-foreground hover:text-green-400">{busyId === f.id ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Play className="w-3.5 h-3.5" />}</button>
                <label className="flex items-center gap-1 text-[10px] text-muted-foreground cursor-pointer">
                  <input type="checkbox" checked={!!f.enabled} onChange={(e) => withBusy(f.id, async () => { await updateFeed(f.id, { enabled: e.target.checked }); await load(); })} className="accent-cyan-500" /> on
                </label>
                <button title="Delete" disabled={busyId === f.id} onClick={() => withBusy(f.id, async () => { await deleteFeed(f.id); await load(); })} className="p-1.5 text-red-400/60 hover:text-red-400"><Trash2 className="w-3.5 h-3.5" /></button>
              </div>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
