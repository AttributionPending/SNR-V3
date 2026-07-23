import { useState, useEffect, useCallback } from 'react';
import { Plus, Loader2, Sparkles, Trash2, FlaskConical, ExternalLink } from 'lucide-react';
import {
  fetchEnrichmentCatalog, listEnrichmentProviders, createEnrichmentProvider,
  updateEnrichmentProvider, deleteEnrichmentProvider, testEnrichmentProvider,
  type EnrichmentCatalogEntry, type EnrichmentProviderRecord, type EnrichmentProviderConfig,
} from '../lib/api';

/**
 * Admin/lead UI for indicator enrichment providers: enable a built-in catalog
 * entry (VirusTotal, AbuseIPDB, …) with an API key, or define a Custom HTTP
 * provider with its own URL, headers and response mappings. Test, toggle, delete.
 *
 * Mirrors FeedsPanel — the same shape of per-team external source with a secret.
 * Stored API keys are never returned by the API; rows only report `has_key`.
 */

const CUSTOM: EnrichmentProviderConfig = {
  supports: ['ipv4'],
  url: 'https://api.example.com/lookup/{value_enc}',
  headers: { Authorization: 'Bearer {api_key}' },
  summary: '{status}',
  facts: [],
  notFound: [404],
};

/** A sensible sample indicator to Test each supported type against. */
const SAMPLE: Record<string, string> = {
  ipv4: '8.8.8.8', ipv6: '2606:4700:4700::1111', domain: 'example.com',
  url: 'https://example.com', md5: 'd41d8cd98f00b204e9800998ecf8427e',
  sha1: 'da39a3ee5e6b4b0d3255bfef95601890afd80709',
  sha256: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
};

export default function EnrichmentProvidersPanel() {
  const [providers, setProviders] = useState<EnrichmentProviderRecord[]>([]);
  const [catalog, setCatalog] = useState<EnrichmentCatalogEntry[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [note, setNote] = useState<string | null>(null);
  const [busyId, setBusyId] = useState<string | null>(null);

  const [showCreate, setShowCreate] = useState(false);
  const [kind, setKind] = useState('virustotal');
  const [name, setName] = useState('');
  const [apiKey, setApiKey] = useState('');
  const [configText, setConfigText] = useState(JSON.stringify(CUSTOM, null, 2));
  const [creating, setCreating] = useState(false);

  const load = useCallback(async () => {
    setLoading(true); setError(null);
    try {
      const [p, c] = await Promise.all([listEnrichmentProviders(), fetchEnrichmentCatalog()]);
      setProviders(p); setCatalog(c);
    } catch (e) { setError(e instanceof Error ? e.message : 'Failed to load'); }
    finally { setLoading(false); }
  }, []);
  useEffect(() => { void load(); }, [load]);

  const preset = catalog.find((c) => c.kind === kind);

  // Switching kind reseeds the editable config so custom edits start from a
  // working example rather than a blank box.
  const pickKind = (k: string) => {
    setKind(k);
    const p = catalog.find((c) => c.kind === k);
    setConfigText(JSON.stringify(p ? p.config : CUSTOM, null, 2));
    setName(p ? p.name : '');
  };

  async function handleCreate() {
    setCreating(true); setError(null);
    try {
      let config: EnrichmentProviderConfig | undefined;
      if (kind === 'custom') {
        try { config = JSON.parse(configText) as EnrichmentProviderConfig; }
        catch { throw new Error('Config is not valid JSON'); }
      }
      await createEnrichmentProvider({ kind, name: name.trim() || undefined, apiKey: apiKey.trim() || undefined, config });
      setShowCreate(false); setApiKey(''); setName(''); setKind('virustotal');
      await load();
    } catch (e) { setError(e instanceof Error ? e.message : 'Failed'); }
    finally { setCreating(false); }
  }

  async function withBusy(id: string, fn: () => Promise<void>) {
    setBusyId(id); setError(null); setNote(null);
    try { await fn(); } catch (e) { setError(e instanceof Error ? e.message : 'Failed'); }
    finally { setBusyId(null); }
  }

  const supportsOf = (p: EnrichmentProviderRecord): string[] => {
    try { return (JSON.parse(p.config) as EnrichmentProviderConfig).supports ?? []; } catch { return []; }
  };

  if (loading) return <div className="flex items-center justify-center py-12 text-muted-foreground"><Loader2 className="w-5 h-5 animate-spin" /></div>;

  return (
    <div className="space-y-4">
      {error && <div className="text-xs text-red-400 bg-red-500/10 border border-red-500/20 rounded px-3 py-2">{error}</div>}
      {note && <div className="text-xs text-cyan-300 bg-cyan-500/10 border border-cyan-500/20 rounded px-3 py-2">{note}</div>}

      <div className="flex items-center justify-between">
        <p className="text-xs text-muted-foreground">
          Enrichment providers add external context to indicator cards. Nothing is sent to a third party until you enable one.
        </p>
        <button onClick={() => { setShowCreate((v) => !v); if (!showCreate) pickKind('virustotal'); }} className="flex items-center gap-1.5 text-xs text-cyan-400 hover:text-cyan-300 flex-shrink-0">
          <Plus className="w-3.5 h-3.5" /> Add provider
        </button>
      </div>

      {showCreate && (
        <div className="bg-muted/30 border border-border rounded p-3 space-y-2">
          <div className="flex flex-wrap gap-2">
            <select value={kind} onChange={(e) => pickKind(e.target.value)} className="bg-background border border-border rounded px-2 py-1.5 text-xs">
              {catalog.map((c) => <option key={c.kind} value={c.kind}>{c.name}</option>)}
              <option value="custom">Custom HTTP…</option>
            </select>
            <input value={name} onChange={(e) => setName(e.target.value)} placeholder="Display name" className="flex-1 min-w-[160px] bg-background border border-border rounded px-2 py-1.5 text-xs" />
          </div>

          <input
            value={apiKey} onChange={(e) => setApiKey(e.target.value)} type="password" autoComplete="new-password"
            placeholder={preset ? preset.keyLabel : 'API key (if the provider needs one)'}
            className="w-full bg-background border border-border rounded px-2 py-1.5 text-xs"
          />
          {preset?.docsUrl && (
            <a href={preset.docsUrl} target="_blank" rel="noopener noreferrer" className="inline-flex items-center gap-1 text-[10px] text-cyan-400 hover:text-cyan-300">
              <ExternalLink className="w-2.5 h-2.5" /> {preset.name} API docs
            </a>
          )}

          {kind === 'custom' && (
            <div>
              <label className="block text-[10px] uppercase tracking-wide text-muted-foreground mb-1">
                Config — url, headers, supports[], summary, facts[], link. Tokens: {'{value}'} {'{value_enc}'} {'{api_key}'}; facts read JSON dot-paths.
              </label>
              <textarea
                value={configText} onChange={(e) => setConfigText(e.target.value)} rows={12} spellCheck={false}
                className="w-full bg-background border border-border rounded px-2 py-1.5 text-[11px] font-mono"
              />
              <p className="text-[10px] text-muted-foreground mt-1">
                Requests must be <span className="font-mono">https</span> to a public address — private, loopback and cloud-metadata destinations are refused.
              </p>
            </div>
          )}

          <div className="flex gap-2 justify-end">
            <button onClick={() => setShowCreate(false)} className="px-2.5 py-1.5 text-xs text-muted-foreground border border-border rounded">Cancel</button>
            <button onClick={handleCreate} disabled={creating} className="px-2.5 py-1.5 text-xs bg-cyan-600 hover:bg-cyan-500 disabled:opacity-50 text-white rounded flex items-center gap-1">
              {creating ? <Loader2 className="w-3 h-3 animate-spin" /> : <Plus className="w-3 h-3" />} Add
            </button>
          </div>
        </div>
      )}

      <div className="space-y-1.5">
        {providers.length === 0 && <p className="text-xs text-muted-foreground py-4 text-center">No enrichment providers configured.</p>}
        {providers.map((p) => {
          const types = supportsOf(p);
          return (
            <div key={p.id} className={`border border-border rounded px-3 py-2 ${p.enabled ? 'bg-muted/20' : 'opacity-60'}`}>
              <div className="flex items-center gap-2">
                <Sparkles className="w-4 h-4 text-muted-foreground flex-shrink-0" />
                <div className="flex-1 min-w-0">
                  <div className="text-xs font-medium flex items-center gap-2">
                    {p.name}
                    <span className="text-[10px] uppercase text-muted-foreground">{p.kind}</span>
                    {!p.has_key && <span className="text-[10px] text-yellow-400">no key</span>}
                  </div>
                  <div className="text-[10px] text-muted-foreground truncate">{types.join(', ') || 'no indicator types'}</div>
                  <div className="text-[10px] text-muted-foreground">
                    {p.last_status ? `last test: ${p.last_status}` : 'never tested'}
                    {p.last_used_at ? ` · ${new Date(p.last_used_at).toLocaleString()}` : ''}
                  </div>
                </div>
                <div className="flex items-center gap-1.5 flex-shrink-0">
                  <button
                    title="Test with a sample indicator" disabled={busyId === p.id}
                    onClick={() => withBusy(p.id, async () => {
                      const t = types[0] ?? 'ipv4';
                      const r = await testEnrichmentProvider(p.id, t, SAMPLE[t] ?? '8.8.8.8');
                      setNote(`${p.name} (${t}): ${r.status}${r.summary ? ` — ${r.summary}` : ''}${r.message ? ` — ${r.message}` : ''}`);
                      await load();
                    })}
                    className="p-1.5 text-muted-foreground hover:text-cyan-300"
                  >
                    {busyId === p.id ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <FlaskConical className="w-3.5 h-3.5" />}
                  </button>
                  <label className="flex items-center gap-1 text-[10px] text-muted-foreground cursor-pointer">
                    <input
                      type="checkbox" checked={!!p.enabled}
                      onChange={(e) => withBusy(p.id, async () => { await updateEnrichmentProvider(p.id, { enabled: e.target.checked }); await load(); })}
                      className="accent-cyan-500"
                    /> on
                  </label>
                  <button
                    title="Delete" disabled={busyId === p.id}
                    onClick={() => withBusy(p.id, async () => { await deleteEnrichmentProvider(p.id); await load(); })}
                    className="p-1.5 text-red-400/60 hover:text-red-400"
                  >
                    <Trash2 className="w-3.5 h-3.5" />
                  </button>
                </div>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
