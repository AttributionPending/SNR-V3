/**
 * IndicatorsTab — browse the team's indicators across all incidents, ranked by
 * how many incidents each appears in. Click an indicator to pivot to the
 * incidents (and attributed actors) that share it. Backed by GET /api/iocs.
 */
import { useState, useEffect, useCallback } from 'react';
import { Search, Crosshair, Loader2 } from 'lucide-react';
import * as api from '@/lib/api';
import type { IocIndicator } from '@/lib/api';
import { defangIoc } from '@/lib/defang';
import { cn } from '@/lib/utils';
import IOCPivot from './IOCPivot';

interface Props {
  open: boolean;
  onSelectSession: (id: string) => void;
  onClose: () => void;
}

const TYPE_COLOR: Record<string, string> = {
  ipv4: 'text-red-400', ipv6: 'text-red-400',
  domain: 'text-orange-400', url: 'text-orange-400',
  md5: 'text-purple-400', sha1: 'text-purple-400', sha256: 'text-purple-400',
  email: 'text-blue-400', filename: 'text-yellow-400',
  registry: 'text-pink-400', user_agent: 'text-teal-400',
};

export default function IndicatorsTab({ open, onSelectSession, onClose }: Props) {
  const [indicators, setIndicators] = useState<IocIndicator[]>([]);
  const [loading, setLoading] = useState(false);
  const [query, setQuery] = useState('');
  const [pivot, setPivot] = useState<{ type: string; value: string } | null>(null);

  const load = useCallback(async (q: string) => {
    setLoading(true);
    try {
      setIndicators(await api.listIocs(q, '', 100));
    } catch {
      setIndicators([]);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    if (!open) return;
    const t = setTimeout(() => load(query.trim()), 200);
    return () => clearTimeout(t);
  }, [open, query, load]);

  return (
    <div className="flex-1 flex flex-col px-5 pb-4 mt-3 overflow-hidden">
      <div className="relative mb-3 flex-shrink-0">
        <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-muted-foreground/50" />
        <input
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          placeholder="Search indicators…"
          className="w-full bg-secondary/40 border border-border rounded-md pl-8 pr-3 py-1.5 text-xs text-foreground placeholder:text-muted-foreground/50 focus:outline-none focus:ring-1 focus:ring-cyan-500/40"
        />
      </div>

      <div className="flex-1 overflow-y-auto min-h-0">
        {loading ? (
          <div className="flex items-center justify-center gap-2 text-xs text-muted-foreground py-8">
            <Loader2 className="w-4 h-4 animate-spin" /> Loading…
          </div>
        ) : indicators.length === 0 ? (
          <p className="text-xs text-muted-foreground py-8 text-center">
            {query.trim() ? 'No matching indicators.' : 'No indicators indexed yet.'}
          </p>
        ) : (
          <table className="w-full text-xs">
            <thead className="sticky top-0 bg-navy-800">
              <tr className="text-left text-[10px] uppercase tracking-wide text-muted-foreground border-b border-border">
                <th className="px-3 py-2 w-24">Type</th>
                <th className="px-3 py-2">Indicator</th>
                <th className="px-3 py-2 w-28 text-right">Incidents</th>
              </tr>
            </thead>
            <tbody>
              {indicators.map((ind) => (
                <tr
                  key={`${ind.type}:${ind.norm}`}
                  className="border-b border-border/40 hover:bg-secondary/30 cursor-pointer transition-colors"
                  onClick={() => setPivot({ type: ind.type, value: ind.value })}
                >
                  <td className={cn('px-3 py-2 font-mono font-semibold', TYPE_COLOR[ind.type] ?? 'text-foreground')}>
                    {ind.type.toUpperCase()}
                  </td>
                  <td className="px-3 py-2 font-mono text-foreground/90 truncate max-w-[360px]" title={ind.value}>
                    {defangIoc(ind.type, ind.value)}
                  </td>
                  <td className="px-3 py-2 text-right">
                    <span className={cn(
                      'inline-flex items-center gap-1 px-1.5 py-0.5 rounded font-mono text-[10px]',
                      ind.sessionCount > 1 ? 'bg-cyan-900/40 text-cyan-300' : 'text-muted-foreground',
                    )}>
                      <Crosshair className="w-2.5 h-2.5" />{ind.sessionCount}
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      {pivot && (
        <IOCPivot
          type={pivot.type}
          value={pivot.value}
          onSelectSession={(id) => { onSelectSession(id); onClose(); }}
          onClose={() => setPivot(null)}
        />
      )}
    </div>
  );
}
