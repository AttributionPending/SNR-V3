/**
 * IntelDashboard — the Intelligence landing panel. A holdings overview: counts +
 * top indicators, threat actors, top ATT&CK techniques, and recent activity, all
 * drilling into the existing detail surfaces. Backed by GET /api/intel/overview.
 */
import { useState, useEffect, useCallback } from 'react';
import { Search, Loader2, RefreshCw, Globe, Shield, Crosshair, FileText } from 'lucide-react';
import * as api from '@/lib/api';
import type { IntelOverview } from '@/lib/api';
import { StatTiles } from './intel/HoldingsPanels';
import HoldingsCard from './intel/HoldingsCard';
import IOCPivot from './IOCPivot';

interface Props {
  onSelectSession: (id: string) => void;
  onSelectThreatActor: (id: string) => void;
  onOpenSearch: (query?: string) => void;
}

export default function IntelDashboard({ onSelectSession, onSelectThreatActor, onOpenSearch }: Props) {
  const [data, setData] = useState<IntelOverview | null>(null);
  const [loading, setLoading] = useState(true);
  const [pivot, setPivot] = useState<{ type: string; value: string } | null>(null);
  const [reloadKey, setReloadKey] = useState(0);

  const load = useCallback(async () => {
    setLoading(true);
    try { setData(await api.fetchIntelOverview()); } catch { setData(null); } finally { setLoading(false); }
    setReloadKey((k) => k + 1);
  }, []);
  useEffect(() => { void load(); }, [load]);

  return (
    <main className="flex-1 h-full overflow-y-auto bg-background">
      <div className="p-5 max-w-6xl mx-auto">
        <div className="flex items-center justify-between mb-4">
          <div>
            <h1 className="text-base font-semibold text-foreground">Intelligence</h1>
            <p className="text-xs text-muted-foreground mt-0.5">Explore your team's threat-intelligence holdings.</p>
          </div>
          <div className="flex items-center gap-2">
            <button onClick={() => void load()} className="p-1.5 rounded-md border border-border text-muted-foreground hover:text-foreground hover:bg-secondary/50" title="Refresh"><RefreshCw className="w-3.5 h-3.5" /></button>
            <button onClick={() => onOpenSearch()} className="inline-flex items-center gap-1.5 text-xs px-3 py-1.5 rounded-md bg-primary text-primary-foreground">
              <Search className="w-3.5 h-3.5" /> Search intelligence
            </button>
          </div>
        </div>

        {loading && !data ? (
          <div className="flex items-center justify-center gap-2 text-sm text-muted-foreground py-20"><Loader2 className="w-4 h-4 animate-spin" />Loading holdings…</div>
        ) : !data ? (
          <div className="text-sm text-muted-foreground py-20 text-center">Couldn't load the intelligence overview.</div>
        ) : (
          <>
            <StatTiles counts={data.counts} />
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-3 mt-4">
              <div className="h-80"><HoldingsCard key={`ind-${reloadKey}`} kind="indicators" title="Indicators" icon={Globe}
                orders={[{ value: 'mentions', label: 'Most mentions' }, { value: 'recent', label: 'Recently added' }]}
                onSelectIoc={(type, value) => setPivot({ type, value })} /></div>
              <div className="h-80"><HoldingsCard key={`act-${reloadKey}`} kind="actors" title="Threat actors" icon={Shield}
                orders={[{ value: 'mentions', label: 'Most mentions' }, { value: 'recent', label: 'Recently active' }]}
                onSelectActor={(id) => onSelectThreatActor(id)} /></div>
              <div className="h-80"><HoldingsCard key={`tec-${reloadKey}`} kind="techniques" title="ATT&CK techniques" icon={Crosshair}
                orders={[{ value: 'mentions', label: 'Most mentions' }, { value: 'recent', label: 'Recently seen' }]}
                onSelectTechnique={(id) => onOpenSearch(id)} /></div>
              <div className="h-80"><HoldingsCard key={`ses-${reloadKey}`} kind="sessions" title="Incidents" icon={FileText}
                orders={[{ value: 'recent', label: 'Most recent' }, { value: 'severity', label: 'Severity' }]}
                onSelectSession={onSelectSession} /></div>
            </div>
          </>
        )}
      </div>

      {pivot && <IOCPivot type={pivot.type} value={pivot.value} onSelectSession={(id) => { setPivot(null); onSelectSession(id); }} onClose={() => setPivot(null)} />}
    </main>
  );
}
