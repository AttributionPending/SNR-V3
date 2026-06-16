import { useState, useEffect, useCallback } from 'react';
import { Plus, Loader2, Copy, Check, Ban, KeyRound, ChevronRight } from 'lucide-react';
import {
  listServiceAccounts,
  createServiceAccount,
  setServiceAccountDisabled,
  listApiKeys,
  mintApiKey,
  revokeApiKey,
  getApiScopes,
  type ServiceAccountRecord,
  type ApiKeyRecord,
} from '../lib/api';

/**
 * Admin UI for the integration API: service accounts and their API keys.
 * Minted tokens are shown once. Team is taken from the active team context.
 */
export default function ApiKeysPanel() {
  const [accounts, setAccounts] = useState<ServiceAccountRecord[]>([]);
  const [scopes, setScopes] = useState<string[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const [showCreate, setShowCreate] = useState(false);
  const [newName, setNewName] = useState('');
  const [newRole, setNewRole] = useState<'analyst' | 'viewer'>('analyst');
  const [busy, setBusy] = useState(false);

  const [selected, setSelected] = useState<ServiceAccountRecord | null>(null);
  const [keys, setKeys] = useState<ApiKeyRecord[]>([]);

  const [mintName, setMintName] = useState('');
  const [mintScopes, setMintScopes] = useState<string[]>([]);
  const [mintedToken, setMintedToken] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const [accts, sc] = await Promise.all([listServiceAccounts(), getApiScopes()]);
      setAccounts(accts);
      setScopes(sc);
      setMintScopes(sc);
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Failed to load');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { void load(); }, [load]);

  const loadKeys = useCallback(async (acct: ServiceAccountRecord) => {
    setSelected(acct);
    setMintedToken(null);
    setMintName('');
    setMintScopes(scopes);
    try { setKeys(await listApiKeys(acct.id)); } catch (e) { setError(e instanceof Error ? e.message : 'Failed'); }
  }, [scopes]);

  async function handleCreate() {
    if (!newName.trim()) return;
    setBusy(true);
    try {
      await createServiceAccount(newName.trim(), newRole);
      setNewName(''); setShowCreate(false);
      await load();
    } catch (e) { setError(e instanceof Error ? e.message : 'Failed'); }
    finally { setBusy(false); }
  }

  async function handleMint() {
    if (!selected || !mintName.trim()) return;
    setBusy(true);
    try {
      const { token } = await mintApiKey(selected.id, { name: mintName.trim(), scopes: mintScopes });
      setMintedToken(token);
      setMintName('');
      setKeys(await listApiKeys(selected.id));
      await load();
    } catch (e) { setError(e instanceof Error ? e.message : 'Failed'); }
    finally { setBusy(false); }
  }

  async function handleRevoke(keyId: string) {
    setBusy(true);
    try { await revokeApiKey(keyId); if (selected) setKeys(await listApiKeys(selected.id)); await load(); }
    catch (e) { setError(e instanceof Error ? e.message : 'Failed'); }
    finally { setBusy(false); }
  }

  function toggleScope(s: string) {
    setMintScopes((cur) => (cur.includes(s) ? cur.filter((x) => x !== s) : [...cur, s]));
  }

  const fmt = (t: number | null) => (t ? new Date(t).toLocaleString() : '—');

  if (loading) return <div className="flex items-center justify-center py-12 text-muted-foreground"><Loader2 className="w-5 h-5 animate-spin" /></div>;

  return (
    <div className="space-y-4">
      {error && <div className="text-xs text-red-400 bg-red-500/10 border border-red-500/20 rounded px-3 py-2">{error}</div>}

      {!selected ? (
        <>
          <div className="flex items-center justify-between">
            <p className="text-xs text-muted-foreground">Service accounts let external systems call the SNR API. Keys are team-scoped.</p>
            <button onClick={() => setShowCreate(true)} className="flex items-center gap-1.5 text-xs text-cyan-400 hover:text-cyan-300">
              <Plus className="w-3.5 h-3.5" /> New account
            </button>
          </div>

          {showCreate && (
            <div className="flex flex-wrap items-end gap-2 bg-muted/30 border border-border rounded p-3">
              <input value={newName} onChange={(e) => setNewName(e.target.value)} placeholder="Account name (e.g. soar-prod)" className="flex-1 min-w-[180px] bg-background border border-border rounded px-2 py-1.5 text-xs" />
              <select value={newRole} onChange={(e) => setNewRole(e.target.value as 'analyst' | 'viewer')} className="bg-background border border-border rounded px-2 py-1.5 text-xs">
                <option value="analyst">analyst</option>
                <option value="viewer">viewer</option>
              </select>
              <button onClick={handleCreate} disabled={busy} className="px-2.5 py-1.5 text-xs bg-cyan-600 hover:bg-cyan-500 disabled:opacity-50 text-white rounded">Create</button>
              <button onClick={() => setShowCreate(false)} className="px-2.5 py-1.5 text-xs text-muted-foreground border border-border rounded">Cancel</button>
            </div>
          )}

          <div className="space-y-1.5">
            {accounts.length === 0 && <p className="text-xs text-muted-foreground py-4 text-center">No service accounts yet.</p>}
            {accounts.map((a) => (
              <button key={a.id} onClick={() => loadKeys(a)} className="w-full flex items-center gap-2 bg-muted/20 hover:bg-muted/40 border border-border rounded px-3 py-2 text-left transition-colors">
                <KeyRound className="w-4 h-4 text-cyan-400/70" />
                <div className="flex-1">
                  <div className="text-xs font-medium flex items-center gap-2">{a.name}{a.disabled ? <span className="text-[10px] text-red-400">disabled</span> : null}</div>
                  <div className="text-[10px] text-muted-foreground">{a.role} · {a.active_keys} active key{a.active_keys === 1 ? '' : 's'}</div>
                </div>
                <ChevronRight className="w-4 h-4 text-muted-foreground" />
              </button>
            ))}
          </div>
        </>
      ) : (
        <>
          <div className="flex items-center justify-between">
            <button onClick={() => { setSelected(null); setMintedToken(null); }} className="text-xs text-cyan-400 hover:text-cyan-300">← Back</button>
            <button onClick={() => setServiceAccountDisabled(selected.id, !selected.disabled).then(load).then(() => setSelected({ ...selected, disabled: selected.disabled ? 0 : 1 }))} className="text-xs text-muted-foreground hover:text-foreground flex items-center gap-1">
              <Ban className="w-3.5 h-3.5" /> {selected.disabled ? 'Enable' : 'Disable'} account
            </button>
          </div>
          <h3 className="text-sm font-semibold flex items-center gap-2"><KeyRound className="w-4 h-4 text-cyan-400" /> {selected.name}</h3>

          {mintedToken && (
            <div className="bg-amber-500/10 border border-amber-500/30 rounded p-3 space-y-2">
              <p className="text-[11px] text-amber-300">Copy this key now — it won't be shown again.</p>
              <div className="flex items-center gap-2">
                <code className="flex-1 text-[11px] bg-background border border-border rounded px-2 py-1.5 break-all">{mintedToken}</code>
                <button onClick={() => { navigator.clipboard.writeText(mintedToken); setCopied(true); setTimeout(() => setCopied(false), 1500); }} className="p-1.5 bg-cyan-600 hover:bg-cyan-500 text-white rounded">
                  {copied ? <Check className="w-3.5 h-3.5" /> : <Copy className="w-3.5 h-3.5" />}
                </button>
              </div>
            </div>
          )}

          <div className="bg-muted/30 border border-border rounded p-3 space-y-2">
            <div className="text-[11px] font-medium text-muted-foreground">Mint a new key</div>
            <input value={mintName} onChange={(e) => setMintName(e.target.value)} placeholder="Key label (e.g. prod 2026)" className="w-full bg-background border border-border rounded px-2 py-1.5 text-xs" />
            <div className="flex flex-wrap gap-2">
              {scopes.map((s) => (
                <label key={s} className="flex items-center gap-1.5 text-[11px] text-muted-foreground cursor-pointer">
                  <input type="checkbox" checked={mintScopes.includes(s)} onChange={() => toggleScope(s)} className="accent-cyan-500" /> {s}
                </label>
              ))}
            </div>
            <button onClick={handleMint} disabled={busy || !mintName.trim() || mintScopes.length === 0} className="px-2.5 py-1.5 text-xs bg-cyan-600 hover:bg-cyan-500 disabled:opacity-50 text-white rounded flex items-center gap-1">
              {busy ? <Loader2 className="w-3 h-3 animate-spin" /> : <Plus className="w-3 h-3" />} Mint key
            </button>
          </div>

          <div className="space-y-1.5">
            {keys.length === 0 && <p className="text-xs text-muted-foreground py-2 text-center">No keys yet.</p>}
            {keys.map((k) => (
              <div key={k.id} className={`flex items-center gap-2 border border-border rounded px-3 py-2 ${k.revoked_at ? 'opacity-50' : 'bg-muted/20'}`}>
                <div className="flex-1">
                  <div className="text-xs font-medium flex items-center gap-2">{k.name} <code className="text-[10px] text-muted-foreground">{k.prefix}…</code>{k.revoked_at ? <span className="text-[10px] text-red-400">revoked</span> : null}</div>
                  <div className="text-[10px] text-muted-foreground">scopes: {(JSON.parse(k.scopes || '[]') as string[]).join(', ') || 'none'} · {k.rate_limit_per_min}/min · last used {fmt(k.last_used_at)}</div>
                </div>
                {!k.revoked_at && (
                  <button onClick={() => handleRevoke(k.id)} disabled={busy} className="text-[11px] text-red-400/70 hover:text-red-400">Revoke</button>
                )}
              </div>
            ))}
          </div>
        </>
      )}
    </div>
  );
}
