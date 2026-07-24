/**
 * CoverageView — aggregate detection coverage across every analysed incident,
 * mapped to ATT&CK. Backed by GET /api/detections/coverage.
 *
 * Each technique carries two independent signals, shown together because their
 * disagreement is the useful part:
 *   - rules we have written that map to it (detection_rule_observations)
 *   - the analysis verdict on whether controls would catch it (attack_chain)
 * `partial` means rules exist yet a gap is still reported.
 */
import { useState, useEffect, useCallback, useMemo } from 'react';
import { ShieldCheck, Loader2, RefreshCw, Download, FileText, X, AlertTriangle, Eye } from 'lucide-react';
import { cn } from '@/lib/utils';
import RuleViewer from './RuleViewer';
import * as api from '@/lib/api';
import type { DetectionCoverage, CoverageTechnique, CoverageRule, CoverageStatus } from '@/lib/api';
import ATTACK_TECHNIQUES from '@/data/attack-techniques.json';

interface Props {
  onSelectSession: (id: string) => void;
}

const STATUS: Record<CoverageStatus, { label: string; dot: string; chip: string; help: string }> = {
  covered: { label: 'Covered', dot: 'bg-emerald-400', chip: 'border-emerald-500/40 text-emerald-300', help: 'A rule maps to this and no analysis reported a gap.' },
  partial: { label: 'Partial', dot: 'bg-yellow-400', chip: 'border-yellow-500/40 text-yellow-300', help: 'Rules exist, but an analysis still reported a detection gap.' },
  gap: { label: 'Gap', dot: 'bg-red-400', chip: 'border-red-500/40 text-red-300', help: 'No rule maps to this and an analysis reported a gap.' },
  unknown: { label: 'Unknown', dot: 'bg-muted-foreground/50', chip: 'border-border text-muted-foreground', help: 'Seen, but with no rule and no verdict either way.' },
};
const STATUS_ORDER: CoverageStatus[] = ['gap', 'partial', 'covered', 'unknown'];

const RULE_TYPE_COLOR: Record<string, string> = { sigma: 'text-purple-400', yara: 'text-orange-400', suricata: 'text-cyan-400' };

/** Tactic/name lookup for techniques that have rules but were never observed. */
const CATALOG = new Map((ATTACK_TECHNIQUES as Array<{ id: string; name: string; tactic: string }>).map((t) => [t.id, t]));

function Tile({ label, value, tone }: { label: string; value: number; tone?: string }) {
  return (
    <div className="bg-navy-800 border border-border rounded-lg px-3 py-2.5">
      <div className="text-[10px] uppercase tracking-wide text-muted-foreground/70">{label}</div>
      <div className={cn('text-xl font-semibold mt-0.5', tone ?? 'text-foreground')}>{value.toLocaleString()}</div>
    </div>
  );
}

export default function CoverageView({ onSelectSession }: Props) {
  const [data, setData] = useState<DetectionCoverage | null>(null);
  const [loading, setLoading] = useState(true);
  const [statusFilter, setStatusFilter] = useState<CoverageStatus | 'all'>('all');
  const [selected, setSelected] = useState<CoverageTechnique | null>(null);
  const [rules, setRules] = useState<CoverageRule[] | null>(null);
  const [openRule, setOpenRule] = useState<CoverageRule | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    try { setData(await api.fetchDetectionCoverage()); } catch { setData(null); } finally { setLoading(false); }
  }, []);
  useEffect(() => { void load(); }, [load]);

  // Fill tactic/name from the bundled catalog for rule-only techniques.
  const techniques = useMemo(() => (data?.techniques ?? []).map((t) => {
    const cat = CATALOG.get(t.technique_id) ?? CATALOG.get(t.technique_id.split('.')[0]!);
    return {
      ...t,
      technique_name: t.technique_name && t.technique_name !== t.technique_id ? t.technique_name : (cat?.name ?? t.technique_id),
      tactic: t.tactic ?? cat?.tactic ?? null,
    };
  }), [data]);

  const shown = useMemo(
    () => techniques.filter((t) => statusFilter === 'all' || t.status === statusFilter),
    [techniques, statusFilter],
  );

  /** Group into ATT&CK tactic columns, gaps first within each. */
  const byTactic = useMemo(() => {
    const m = new Map<string, CoverageTechnique[]>();
    for (const t of shown) {
      const key = t.tactic ?? 'Unmapped';
      const list = m.get(key) ?? [];
      list.push(t);
      m.set(key, list);
    }
    for (const list of m.values()) {
      list.sort((a, b) => STATUS_ORDER.indexOf(a.status) - STATUS_ORDER.indexOf(b.status) || b.sessions - a.sessions);
    }
    return [...m.entries()].sort((a, b) => b[1].length - a[1].length);
  }, [shown]);

  const openTechnique = async (t: CoverageTechnique) => {
    setSelected(t);
    setRules(null);
    try { setRules(await api.fetchDetectionRules(t.technique_id)); } catch { setRules([]); }
  };

  const counts = useMemo(() => {
    const c = { covered: 0, partial: 0, gap: 0, unknown: 0 } as Record<CoverageStatus, number>;
    for (const t of techniques) c[t.status]++;
    return c;
  }, [techniques]);

  return (
    <main className="flex-1 h-full overflow-hidden bg-background flex flex-col">
      <div className="px-5 py-4 border-b border-border flex items-start gap-3">
        <div className="w-9 h-9 rounded-lg bg-emerald-500/15 flex items-center justify-center flex-shrink-0">
          <ShieldCheck className="w-4.5 h-4.5 text-emerald-400" />
        </div>
        <div className="flex-1 min-w-0">
          <h1 className="text-base font-semibold text-foreground">Detection coverage</h1>
          <p className="text-xs text-muted-foreground mt-0.5">
            Detection rules aggregated across every analysed incident, mapped to ATT&CK.
          </p>
        </div>
        <button onClick={() => void load()} className="p-1.5 rounded-md border border-border text-muted-foreground hover:text-foreground hover:bg-secondary/50" title="Refresh"><RefreshCw className="w-3.5 h-3.5" /></button>
        <button
          onClick={() => void api.downloadCoverageNavigator()}
          className="inline-flex items-center gap-1.5 text-xs px-3 py-1.5 rounded-md border border-border text-foreground hover:bg-secondary/50"
          title="Download as an ATT&CK Navigator layer"
        >
          <Download className="w-3.5 h-3.5" /> Navigator layer
        </button>
      </div>

      {loading && !data ? (
        <div className="flex-1 flex items-center justify-center gap-2 text-sm text-muted-foreground"><Loader2 className="w-4 h-4 animate-spin" />Loading coverage…</div>
      ) : !data ? (
        <div className="flex-1 flex items-center justify-center text-sm text-muted-foreground">Couldn't load detection coverage.</div>
      ) : techniques.length === 0 ? (
        <div className="flex-1 flex items-center justify-center text-sm text-muted-foreground px-6 text-center">
          No techniques or detection rules yet — analyse an incident and its rules will appear here.
        </div>
      ) : (
        <div className="flex-1 min-h-0 flex">
          <div className="flex-1 min-w-0 overflow-y-auto px-5 py-4">
            <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-2">
              <Tile label="Techniques" value={data.summary.techniques_observed} />
              <Tile label="With rules" value={data.summary.techniques_with_rules} tone="text-emerald-400" />
              <Tile label="Gaps" value={data.summary.techniques_gap} tone="text-red-400" />
              <Tile label="Partial" value={data.summary.techniques_partial} tone="text-yellow-400" />
              <Tile label="Rules" value={data.summary.rules_total} />
              <Tile label="Distinct rules" value={data.summary.rules_distinct} />
            </div>

            <div className="flex flex-wrap items-center gap-1.5 mt-4 mb-3">
              <button
                onClick={() => setStatusFilter('all')}
                className={cn('text-[11px] px-2 py-0.5 rounded-full border transition-colors',
                  statusFilter === 'all' ? 'border-primary/40 bg-primary/15 text-foreground' : 'border-border text-muted-foreground hover:text-foreground')}
              >
                All {techniques.length}
              </button>
              {STATUS_ORDER.map((s) => (
                <button
                  key={s}
                  onClick={() => setStatusFilter(statusFilter === s ? 'all' : s)}
                  title={STATUS[s].help}
                  className={cn('inline-flex items-center gap-1.5 text-[11px] px-2 py-0.5 rounded-full border transition-colors',
                    statusFilter === s ? 'bg-secondary/60 text-foreground' : 'text-muted-foreground hover:text-foreground', STATUS[s].chip)}
                >
                  <span className={cn('w-1.5 h-1.5 rounded-full', STATUS[s].dot)} />
                  {STATUS[s].label} {counts[s]}
                </button>
              ))}
              {data.summary.unmapped_rules > 0 && (
                <button
                  onClick={() => void openTechnique({
                    technique_id: 'UNMAPPED', technique_name: 'Rules with no ATT&CK mapping', tactic: null,
                    sessions: 0, rule_count: data.summary.unmapped_rules,
                    rules_by_type: { sigma: 0, yara: 0, suricata: 0 },
                    detected_votes: 0, gap_votes: 0, status: 'unknown',
                  })}
                  className="inline-flex items-center gap-1 text-[11px] px-2 py-0.5 rounded-full border border-border text-muted-foreground hover:text-foreground ml-auto"
                  title="Detection rules that carry no related_technique"
                >
                  <AlertTriangle className="w-3 h-3" /> {data.summary.unmapped_rules} unmapped rules
                </button>
              )}
            </div>

            {/* ATT&CK matrix: a column per tactic, cells coloured by coverage. */}
            <div className="flex gap-2 overflow-x-auto pb-2">
              {byTactic.map(([tactic, list]) => (
                <div key={tactic} className="min-w-[190px] w-[190px] flex-shrink-0">
                  <div className="text-[10px] uppercase tracking-wide text-muted-foreground/70 px-1 pb-1 border-b border-border mb-1.5 truncate" title={tactic}>
                    {tactic} <span className="text-muted-foreground/50">{list.length}</span>
                  </div>
                  <div className="space-y-1">
                    {list.map((t) => (
                      <button
                        key={t.technique_id}
                        onClick={() => void openTechnique(t)}
                        className={cn(
                          'w-full text-left px-2 py-1.5 rounded border bg-navy-800 hover:bg-secondary/50 transition-colors',
                          selected?.technique_id === t.technique_id ? 'border-primary/50' : 'border-border',
                        )}
                      >
                        <div className="flex items-center gap-1.5">
                          <span className={cn('w-1.5 h-1.5 rounded-full flex-shrink-0', STATUS[t.status].dot)} />
                          <span className="font-mono text-[10px] text-cyan-400 flex-shrink-0">{t.technique_id}</span>
                          <span className="text-[9px] text-muted-foreground/60 ml-auto flex-shrink-0">{t.rule_count} rule{t.rule_count !== 1 ? 's' : ''}</span>
                        </div>
                        <div className="text-[11px] text-foreground/90 truncate mt-0.5">{t.technique_name}</div>
                        {t.gap_votes > 0 && (
                          <div className="text-[9px] text-red-400/80 mt-0.5">{t.gap_votes} gap verdict{t.gap_votes !== 1 ? 's' : ''}</div>
                        )}
                      </button>
                    ))}
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Detail: the rules behind the selected technique. */}
          {selected && (
            <div className="w-[420px] flex-shrink-0 border-l border-border overflow-y-auto bg-navy-950/40">
              <div className="px-4 py-3 border-b border-border flex items-start gap-2 sticky top-0 bg-navy-950">
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-1.5">
                    <span className={cn('w-1.5 h-1.5 rounded-full', STATUS[selected.status].dot)} />
                    <span className="font-mono text-[11px] text-cyan-400">{selected.technique_id}</span>
                    <span className={cn('text-[9px] uppercase px-1 py-px rounded border', STATUS[selected.status].chip)}>{STATUS[selected.status].label}</span>
                  </div>
                  <h2 className="text-sm text-foreground mt-0.5 truncate">{selected.technique_name}</h2>
                  <p className="text-[10px] text-muted-foreground mt-0.5">
                    {selected.sessions} incident{selected.sessions !== 1 ? 's' : ''} ·
                    {' '}{selected.detected_votes} likely detected · {selected.gap_votes} gap
                  </p>
                </div>
                <button onClick={() => setSelected(null)} className="text-muted-foreground hover:text-foreground p-1 -m-1"><X className="w-4 h-4" /></button>
              </div>

              <div className="px-4 py-3">
                {selected.status === 'gap' && (
                  <div className="mb-3 text-[11px] text-red-300 bg-red-500/10 border border-red-500/20 rounded px-2.5 py-2">
                    No detection rule maps to this technique, and it was reported as a gap.
                  </div>
                )}
                {selected.status === 'partial' && (
                  <div className="mb-3 text-[11px] text-yellow-300 bg-yellow-500/10 border border-yellow-500/20 rounded px-2.5 py-2">
                    Rules exist, but an analysis still reported this as a detection gap — worth reviewing whether the rules actually fire.
                  </div>
                )}

                {rules === null ? (
                  <div className="flex items-center gap-2 text-xs text-muted-foreground py-4"><Loader2 className="w-3.5 h-3.5 animate-spin" />Loading rules…</div>
                ) : rules.length === 0 ? (
                  <p className="text-xs text-muted-foreground py-2">No detection rules for this technique yet.</p>
                ) : (
                  <ul className="space-y-2">
                    {rules.map((r) => (
                      <li key={r.id} className="border border-border rounded-md bg-navy-800/60 hover:border-border/80 transition-colors">
                        <button
                          onClick={() => setOpenRule(r)}
                          className="w-full text-left group"
                          title="View the full rule"
                        >
                          <div className="px-2.5 py-1.5 border-b border-border flex items-center gap-1.5">
                            <span className={cn('text-[9px] uppercase font-mono flex-shrink-0', RULE_TYPE_COLOR[r.rule_type] ?? 'text-muted-foreground')}>{r.rule_type}</span>
                            <span className="text-[11px] text-foreground truncate flex-1 group-hover:text-cyan-300 transition-colors">{r.rule_name}</span>
                            <Eye className="w-3 h-3 text-muted-foreground/40 group-hover:text-cyan-300 flex-shrink-0 transition-colors" />
                          </div>
                          {r.description && <p className="px-2.5 pt-1.5 text-[10px] text-muted-foreground">{r.description}</p>}
                        </button>
                        <button
                          onClick={() => onSelectSession(r.session_id)}
                          className="w-full flex items-center gap-1.5 px-2.5 py-1.5 text-[10px] text-muted-foreground hover:text-cyan-300 transition-colors"
                          title="Open the incident this rule came from"
                        >
                          <FileText className="w-3 h-3 flex-shrink-0" />
                          <span className="truncate">{r.session_name}</span>
                        </button>
                      </li>
                    ))}
                  </ul>
                )}
              </div>
            </div>
          )}
        </div>
      )}

      {openRule && (
        <RuleViewer rule={openRule} onClose={() => setOpenRule(null)} onSelectSession={onSelectSession} />
      )}
    </main>
  );
}
