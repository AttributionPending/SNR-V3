/**
 * A single Intelligence-dashboard box that fetches its own kind of holdings,
 * paginated and sortable. Scrolls beyond the top N (loads more as you reach the
 * bottom) and exposes a per-box sort control (e.g. Most mentions / Recently
 * added). Renders the shared row markup from HoldingsPanels.
 */
import { useCallback, useEffect, useRef, useState } from 'react';
import { Loader2 } from 'lucide-react';
import * as api from '@/lib/api';
import type { HoldingKind, HoldingItemMap } from '@/lib/api';
import { cn } from '@/lib/utils';
import { Panel, IndicatorRow, ActorRow, TechniqueRow, SessionRow } from './HoldingsPanels';

const PAGE = 20;

interface SortOption { value: string; label: string }

interface Props {
  kind: HoldingKind;
  title: string;
  icon: React.ElementType;
  orders: SortOption[];
  onSelectIoc?: (type: string, value: string) => void;
  onSelectActor?: (id: string, name: string) => void;
  onSelectTechnique?: (id: string) => void;
  onSelectSession?: (id: string) => void;
}

export default function HoldingsCard({ kind, title, icon, orders, onSelectIoc, onSelectActor, onSelectTechnique, onSelectSession }: Props) {
  const [order, setOrder] = useState(orders[0].value);
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const [items, setItems] = useState<any[]>([]);
  const [hasMore, setHasMore] = useState(false);
  const [loading, setLoading] = useState(true);
  const loadingRef = useRef(false);
  const scrollRef = useRef<HTMLDivElement>(null);

  const loadPage = useCallback(async (ord: string, offset: number) => {
    if (loadingRef.current) return;
    loadingRef.current = true;
    setLoading(true);
    try {
      const { items: batch, hasMore: more } = await api.fetchHoldings(kind, ord, PAGE, offset);
      setItems((prev) => (offset === 0 ? batch : [...prev, ...batch]));
      setHasMore(more);
    } catch {
      if (offset === 0) { setItems([]); setHasMore(false); }
    } finally {
      loadingRef.current = false;
      setLoading(false);
    }
  }, [kind]);

  // (Re)load from the top whenever the sort order changes.
  useEffect(() => {
    if (scrollRef.current) scrollRef.current.scrollTop = 0;
    void loadPage(order, 0);
  }, [order, loadPage]);

  const onScroll = useCallback((e: React.UIEvent<HTMLDivElement>) => {
    if (!hasMore || loadingRef.current) return;
    const el = e.currentTarget;
    if (el.scrollHeight - el.scrollTop - el.clientHeight < 48) {
      void loadPage(order, items.length);
    }
  }, [hasMore, loadPage, order, items.length]);

  const sortControl = orders.length > 1 ? (
    <div className="flex items-center gap-0.5 bg-secondary/50 rounded p-0.5">
      {orders.map((o) => (
        <button
          key={o.value}
          onClick={() => setOrder(o.value)}
          className={cn(
            'text-[9px] px-1.5 py-0.5 rounded transition-colors',
            order === o.value ? 'bg-primary text-primary-foreground font-medium' : 'text-muted-foreground hover:text-foreground',
          )}
        >
          {o.label}
        </button>
      ))}
    </div>
  ) : undefined;

  return (
    <Panel ref={scrollRef} title={title} icon={icon} headerRight={sortControl} onScroll={onScroll} empty={!loading && items.length === 0}>
      <ul>
        {items.map((it, idx) => {
          if (kind === 'indicators') { const i = it as HoldingItemMap['indicators']; return <li key={`${i.type}:${i.norm}`}><IndicatorRow item={i} onSelect={onSelectIoc!} /></li>; }
          if (kind === 'actors') { const a = it as HoldingItemMap['actors']; return <li key={a.id}><ActorRow item={a} onSelect={onSelectActor!} /></li>; }
          if (kind === 'techniques') { const t = it as HoldingItemMap['techniques']; return <li key={`${t.technique_id}:${idx}`}><TechniqueRow item={t} onSelect={onSelectTechnique!} /></li>; }
          const s = it as HoldingItemMap['sessions']; return <li key={s.id}><SessionRow item={s} onSelect={onSelectSession!} /></li>;
        })}
      </ul>
      {loading && (
        <div className="flex items-center justify-center py-3 text-muted-foreground/60"><Loader2 className="w-3.5 h-3.5 animate-spin" /></div>
      )}
    </Panel>
  );
}
