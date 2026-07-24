/**
 * EnrichmentPanel — the extensible external-intelligence section of the indicator
 * card. Renders one card per registered enrichment provider (VirusTotal,
 * AbuseIPDB, …) using a provider-agnostic shape (summary + fact rows + a deep
 * link), so adding a provider server-side needs no change here.
 *
 * No providers ship enabled, so the default state is an explicit setup prompt —
 * which also makes it obvious that nothing has been sent to a third party.
 */
import { useEffect, useState } from 'react';
import { Sparkles, ExternalLink, Loader2, AlertTriangle, RefreshCw } from 'lucide-react';
import { cn } from '@/lib/utils';
import * as api from '@/lib/api';
import type { EnrichmentResponse, EnrichmentResult } from '@/lib/api';

const TONE: Record<string, string> = {
  good: 'text-emerald-400', warn: 'text-yellow-400', bad: 'text-red-400', neutral: 'text-foreground/80',
};

const STATUS_LABEL: Record<EnrichmentResult['status'], string> = {
  ok: '', not_found: 'Nothing known', unconfigured: 'Not configured', unsupported: 'Not applicable', error: 'Lookup failed',
};

function ProviderCard({ r }: { r: EnrichmentResult }) {
  const bad = r.status === 'error';
  return (
    <div className="rounded-md border border-border bg-secondary/20 px-3 py-2">
      <div className="flex items-center gap-1.5 mb-1">
        <span className="text-[11px] font-semibold text-foreground flex-1 truncate">{r.providerName}</span>
        {r.status !== 'ok' && (
          <span className={cn('text-[9px] uppercase tracking-wide', bad ? 'text-red-400' : 'text-muted-foreground/60')}>
            {STATUS_LABEL[r.status]}
          </span>
        )}
        {r.link && (
          <a href={r.link} target="_blank" rel="noopener noreferrer" className="text-muted-foreground/60 hover:text-foreground" title="Open in provider">
            <ExternalLink className="w-3 h-3" />
          </a>
        )}
      </div>
      {r.summary && <p className="text-xs text-foreground/90 mb-1">{r.summary}</p>}
      {r.message && <p className="text-[11px] text-muted-foreground">{r.message}</p>}
      {r.facts && r.facts.length > 0 && (
        <dl className="mt-1 space-y-0.5">
          {r.facts.map((f) => (
            <div key={f.label} className="flex items-baseline gap-2 text-[11px]">
              <dt className="text-muted-foreground/70 w-28 flex-shrink-0 truncate">{f.label}</dt>
              <dd className={cn('flex-1 min-w-0 truncate', TONE[f.tone ?? 'neutral'])}>{f.value}</dd>
            </div>
          ))}
        </dl>
      )}
      {r.fetchedAt && <div className="text-[9px] text-muted-foreground/50 mt-1">{new Date(r.fetchedAt).toLocaleString()}</div>}
    </div>
  );
}

export default function EnrichmentPanel({ type, value }: { type: string; value: string }) {
  const [data, setData] = useState<EnrichmentResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [failed, setFailed] = useState(false);

  /** `refresh` re-queries the vendors instead of serving the cached result. */
  const load = (refresh = false) => {
    setLoading(true);
    setFailed(false);
    api.fetchEnrichment(type, value, refresh)
      .then(setData)
      .catch(() => setFailed(true))
      .finally(() => setLoading(false));
  };
  useEffect(() => { load(); /* eslint-disable-line react-hooks/exhaustive-deps */ }, [type, value]);

  return (
    <section>
      <div className="flex items-center gap-1.5 mb-2">
        <Sparkles className="w-3 h-3 text-muted-foreground" />
        <h3 className="text-[11px] uppercase tracking-wide text-muted-foreground/70 flex-1">Enrichment</h3>
        {!loading && (
          <button onClick={() => load(true)} className="text-muted-foreground/50 hover:text-foreground" title="Re-query providers (bypasses the cached result)">
            <RefreshCw className="w-3 h-3" />
          </button>
        )}
      </div>

      {loading ? (
        <div className="flex items-center gap-2 text-[11px] text-muted-foreground py-3"><Loader2 className="w-3.5 h-3.5 animate-spin" />Looking up…</div>
      ) : failed ? (
        <div className="flex items-start gap-1.5 text-[11px] text-muted-foreground rounded-md border border-border bg-secondary/20 px-3 py-2">
          <AlertTriangle className="w-3.5 h-3.5 text-yellow-400 flex-shrink-0 mt-px" />
          Couldn't reach the enrichment service.
        </div>
      ) : data && data.providers.length > 0 ? (
        <div className="space-y-2">{data.providers.map((r) => <ProviderCard key={r.providerId} r={r} />)}</div>
      ) : (
        <div className="rounded-md border border-dashed border-border px-3 py-3">
          <p className="text-[11px] text-muted-foreground">
            No enrichment providers configured.
          </p>
          <p className="text-[10px] text-muted-foreground/60 mt-1 leading-relaxed">
            An admin or team lead can add one under <span className="text-muted-foreground/80">Admin → Enrichment</span>
            {' '}(VirusTotal, AbuseIPDB, Shodan, urlscan.io, or a custom HTTP source).
            Nothing is sent to third parties until you enable one.
          </p>
        </div>
      )}
    </section>
  );
}
