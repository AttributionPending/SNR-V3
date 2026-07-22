import { useState, useEffect } from 'react';
import {
  ResponsiveContainer,
  AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip,
  PieChart, Pie, Cell,
  BarChart, Bar,
} from 'recharts';
import { BarChart2, X as XIcon, ChevronRight } from 'lucide-react';
import { cn } from '@/lib/utils';
import { formatTimestamp } from '@/lib/utils';
import * as api from '@/lib/api';
import { useTheme } from '@/lib/theme';
import type { AnalyticsData, TechniqueEntry } from '@/lib/api';

// ── Color constants ───────────────────────────────────────────────────────────

const SEVERITY_COLORS: Record<string, string> = {
  Critical:      '#f87171',
  High:          '#fb923c',
  Medium:        '#facc15',
  Low:           '#4ade80',
  Informational: '#94a3b8',
  Unknown:       '#475569',
};

const IOC_COLORS: Record<string, string> = {
  ipv4:       '#3f83e6',
  ipv6:       '#8fb6f2',
  domain:     '#2f66c4',
  url:        '#274f9c',
  email:      '#0e7490',
  sha256:     '#fb923c',
  md5:        '#fdba74',
  sha1:       '#fed7aa',
  filename:   '#f97316',
  registry:   '#ea580c',
  user_agent: '#c2410c',
};

const AUDIENCE_COLORS: Record<string, string> = {
  soc:         '#3f83e6',
  purple_team: '#a78bfa',
  red_team:    '#f87171',
  dr:          '#34d399',
  general:     '#94a3b8',
  unknown:     '#475569',
};

const EXPORT_COLORS: Record<string, string> = {
  stix:      '#fb923c',
  eml:       '#4ade80',
  report:    '#60a5fa',
  navigator: '#a78bfa',
  zip:       '#facc15',
};

const TOOLTIP_STYLE: React.CSSProperties = {
  background: 'hsl(var(--card))',
  border: '1px solid hsl(var(--n-600))',
  borderRadius: 6,
  fontSize: 11,
};

const TACTIC_ORDER = [
  'Reconnaissance', 'Resource Development', 'Initial Access', 'Execution',
  'Persistence', 'Privilege Escalation', 'Defense Evasion', 'Credential Access',
  'Discovery', 'Lateral Movement', 'Collection', 'Command and Control',
  'Exfiltration', 'Impact',
];

const AUDIENCE_LABELS: Record<string, string> = {
  soc:         'SOC',
  purple_team: 'Purple Team',
  red_team:    'Red Team',
  dr:          'D&R',
  general:     'General',
  unknown:     'Unknown',
};

const IOC_LABELS: Record<string, string> = {
  ipv4:       'IPv4',
  ipv6:       'IPv6',
  domain:     'Domain',
  url:        'URL',
  email:      'Email',
  sha256:     'SHA-256',
  md5:        'MD5',
  sha1:       'SHA-1',
  filename:   'Filename',
  registry:   'Registry',
  user_agent: 'User Agent',
};

const EXPORT_LABELS: Record<string, string> = {
  stix:      'STIX',
  eml:       'Email',
  report:    'Report',
  navigator: 'Navigator',
  zip:       'ZIP',
};

// ── Helpers ───────────────────────────────────────────────────────────────────

type TimeRange = 7 | 30 | 90 | 0;

function fillDateRange(
  rows: { date: string; count: number }[],
  days: TimeRange,
): { date: string; count: number }[] {
  const map = new Map(rows.map((r) => [r.date, r.count]));

  if (days === 0) {
    if (rows.length === 0) return [];
    const result: { date: string; count: number }[] = [];
    const start = new Date(rows[0].date + 'T00:00:00');
    const end   = new Date(rows[rows.length - 1].date + 'T00:00:00');
    const cur   = new Date(start);
    while (cur <= end) {
      const key = cur.toISOString().slice(0, 10);
      result.push({ date: key, count: map.get(key) ?? 0 });
      cur.setDate(cur.getDate() + 1);
    }
    return result;
  }

  const result: { date: string; count: number }[] = [];
  const today = new Date();
  for (let i = days - 1; i >= 0; i--) {
    const d = new Date(today);
    d.setDate(d.getDate() - i);
    const key = d.toISOString().slice(0, 10);
    result.push({ date: key, count: map.get(key) ?? 0 });
  }
  return result;
}

function formatDateTick(dateStr: string): string {
  const parts = dateStr.split('-').map(Number);
  return new Date(parts[0], parts[1] - 1, parts[2]).toLocaleDateString('en-US', {
    month: 'short', day: 'numeric',
  });
}

function chipClass(count: number): string {
  if (count >= 4) return 'bg-cyan-400/30 border-cyan-400/60 text-cyan-200 hover:bg-cyan-400/40';
  if (count >= 2) return 'bg-cyan-400/20 border-cyan-400/40 text-cyan-300 hover:bg-cyan-400/30';
  return 'bg-cyan-400/10 border-cyan-400/20 text-cyan-400/80 hover:bg-cyan-400/20';
}

// ── Sub-components ────────────────────────────────────────────────────────────

function ChartCard({
  title,
  children,
  action,
  fullWidth,
}: {
  title: string;
  children: React.ReactNode;
  action?: React.ReactNode;
  fullWidth?: boolean;
}) {
  return (
    <div className={cn(
      'bg-navy-900 border border-border rounded-lg p-4 flex flex-col gap-3',
      fullWidth && 'col-span-2',
    )}>
      <div className="flex items-center justify-between">
        <span className="text-[10px] font-semibold text-muted-foreground uppercase tracking-widest">
          {title}
        </span>
        {action}
      </div>
      {children}
    </div>
  );
}

function ChartSkeleton() {
  return <div className="h-48 rounded-md bg-secondary/30 animate-pulse" />;
}

function NoData() {
  return (
    <div className="h-48 flex items-center justify-center text-muted-foreground/40 text-xs">
      No data
    </div>
  );
}

function TimeRangeToggle({
  value,
  onChange,
}: {
  value: TimeRange;
  onChange: (v: TimeRange) => void;
}) {
  return (
    <div className="flex items-center gap-0.5 bg-secondary/50 rounded p-0.5">
      {([7, 30, 90, 0] as TimeRange[]).map((r) => (
        <button
          key={r}
          onClick={() => onChange(r)}
          className={cn(
            'px-1.5 py-0.5 text-[10px] rounded font-medium transition-colors',
            value === r
              ? 'bg-cyan-500/20 text-cyan-400 border border-cyan-500/30'
              : 'text-muted-foreground hover:text-foreground',
          )}
        >
          {r === 0 ? 'All' : `${r}d`}
        </button>
      ))}
    </div>
  );
}

// ── Main component ────────────────────────────────────────────────────────────

interface Props {
  open: boolean;
  onSelectSession: (id: string) => void;
  onClose: () => void;
}

export default function AnalyticsTab({ open, onSelectSession, onClose }: Props) {
  const [data, setData] = useState<AnalyticsData | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [timeRange, setTimeRange] = useState<TimeRange>(30);
  const [selectedTechnique, setSelectedTechnique] = useState<TechniqueEntry | null>(null);

  // Theme-aware chart structural colors (grid/axis/tooltip) so charts flip.
  const { theme } = useTheme();
  const chart = theme === 'dark'
    ? { grid: '#2a2f3a', tick: '#8b9096', tipBg: 'hsl(var(--card))', tipBorder: '#2a2f3a', tipText: '#e6e8eb', dot: 'hsl(var(--card))' }
    : { grid: '#e4e8ec', tick: '#6b7280', tipBg: '#ffffff', tipBorder: '#dfe3e8', tipText: '#1f2937', dot: '#ffffff' };
  const tooltipStyle: React.CSSProperties = { ...TOOLTIP_STYLE, background: chart.tipBg, border: `1px solid ${chart.tipBorder}`, color: chart.tipText };

  useEffect(() => {
    if (!open) return;
    setLoading(true);
    setError(null);
    api.fetchAnalytics(timeRange)
      .then(setData)
      .catch(() => setError('Failed to load analytics data.'))
      .finally(() => setLoading(false));
  }, [open, timeRange]);

  useEffect(() => {
    if (!open) setSelectedTechnique(null);
  }, [open]);

  const isEmpty =
    !data ||
    (data.sessionsOverTime.length === 0 &&
     data.severityDistribution.length === 0 &&
     data.iocDistribution.length === 0 &&
     data.techniqueMap.length === 0);

  const filledData = data ? fillDateRange(data.sessionsOverTime, timeRange) : [];

  const xInterval =
    timeRange === 7 ? 0
    : timeRange === 30 ? 4
    : timeRange === 90 ? 13
    : ('preserveStartEnd' as const);

  // Pre-process chart data with display labels
  const iocData = data?.iocDistribution.map((d) => ({
    ...d,
    label: IOC_LABELS[d.ioc_type] ?? d.ioc_type,
  })) ?? [];

  const audienceData = data?.audienceBreakdown.map((d) => ({
    ...d,
    label: AUDIENCE_LABELS[d.audience] ?? d.audience,
  })) ?? [];

  const exportData = data?.exportActivity.map((d) => ({
    ...d,
    label: EXPORT_LABELS[d.export_type] ?? d.export_type.toUpperCase(),
  })) ?? [];

  // Group techniques by tactic, sorted by ATT&CK phase order
  const groupedTactics: [string, TechniqueEntry[]][] = data
    ? Object.entries(
        data.techniqueMap.reduce<Record<string, TechniqueEntry[]>>((acc, t) => {
          const tac = t.tactic || 'Unknown';
          (acc[tac] ??= []).push(t);
          return acc;
        }, {}),
      ).sort(([a], [b]) => {
        const ai = TACTIC_ORDER.indexOf(a);
        const bi = TACTIC_ORDER.indexOf(b);
        return (ai === -1 ? 999 : ai) - (bi === -1 ? 999 : bi);
      })
    : [];

  return (
    <div className="relative h-full">
      {/* ── Scrollable chart area ── */}
      <div className="h-full overflow-y-auto px-5 pb-4">

        {/* Error state */}
        {error && (
          <div className="mt-3 p-3 rounded-md bg-red-500/10 border border-red-500/30 text-red-400 text-xs">
            {error}
          </div>
        )}

        {/* Empty state */}
        {!error && isEmpty && !loading && (
          <div className="flex flex-col items-center justify-center py-24 gap-3 text-muted-foreground">
            <BarChart2 className="w-10 h-10 opacity-20" />
            <p className="text-sm">No analytics data yet.</p>
            <p className="text-xs opacity-50">Complete your first analysis to populate charts.</p>
          </div>
        )}

        {/* Charts grid */}
        {!error && (!isEmpty || loading) && (
          <div className="grid grid-cols-2 gap-4 mt-3">

            {/* ── Sessions Over Time ── */}
            <ChartCard
              title="Sessions Over Time"
              action={
                <TimeRangeToggle value={timeRange} onChange={setTimeRange} />
              }
            >
              {loading ? <ChartSkeleton /> : (
                <div className="h-48">
                  <ResponsiveContainer width="100%" height="100%">
                    <AreaChart data={filledData} margin={{ top: 4, right: 8, bottom: 0, left: -16 }}>
                      <defs>
                        <linearGradient id="sessionGradient" x1="0" y1="0" x2="0" y2="1">
                          <stop offset="5%"  stopColor="#3f83e6" stopOpacity={0.25} />
                          <stop offset="95%" stopColor="#3f83e6" stopOpacity={0.02} />
                        </linearGradient>
                      </defs>
                      <CartesianGrid stroke={chart.grid} strokeDasharray="3 3" vertical={false} />
                      <XAxis
                        dataKey="date"
                        tick={{ fill: chart.tick, fontSize: 9 }}
                        tickFormatter={formatDateTick}
                        interval={xInterval}
                        tickLine={false}
                        axisLine={false}
                      />
                      <YAxis
                        tick={{ fill: chart.tick, fontSize: 9 }}
                        allowDecimals={false}
                        tickLine={false}
                        axisLine={false}
                      />
                      <Tooltip
                        contentStyle={tooltipStyle}
                        labelStyle={{ color: '#e2e8f0', marginBottom: 4 }}
                        itemStyle={{ color: '#3f83e6' }}
                        labelFormatter={(l) => formatDateTick(l as string)}
                        formatter={(v) => [v, 'Sessions']}
                      />
                      <Area
                        type="monotone"
                        dataKey="count"
                        stroke="#3f83e6"
                        strokeWidth={2}
                        fill="url(#sessionGradient)"
                        dot={false}
                        activeDot={{ r: 3, fill: '#3f83e6', stroke: chart.dot, strokeWidth: 2 }}
                      />
                    </AreaChart>
                  </ResponsiveContainer>
                </div>
              )}
            </ChartCard>

            {/* ── Severity Distribution ── */}
            <ChartCard title="Severity Distribution">
              {loading ? <ChartSkeleton /> : !data?.severityDistribution.length ? <NoData /> : (
                <>
                  <div className="h-40">
                    <ResponsiveContainer width="100%" height="100%">
                      <PieChart>
                        <Pie
                          data={data.severityDistribution}
                          dataKey="count"
                          nameKey="severity"
                          innerRadius="55%"
                          outerRadius="80%"
                          paddingAngle={2}
                          strokeWidth={0}
                        >
                          {data.severityDistribution.map((entry) => (
                            <Cell
                              key={entry.severity}
                              fill={SEVERITY_COLORS[entry.severity] ?? '#475569'}
                            />
                          ))}
                        </Pie>
                        <Tooltip
                          contentStyle={tooltipStyle}
                          itemStyle={{ color: '#e2e8f0' }}
                          formatter={(v, n) => [v, n]}
                        />
                      </PieChart>
                    </ResponsiveContainer>
                  </div>
                  <div className="flex flex-wrap gap-x-3 gap-y-1.5 justify-center">
                    {data.severityDistribution.map((entry) => (
                      <div key={entry.severity} className="flex items-center gap-1">
                        <div
                          className="w-2 h-2 rounded-full flex-shrink-0"
                          style={{ backgroundColor: SEVERITY_COLORS[entry.severity] ?? '#475569' }}
                        />
                        <span className="text-[10px] text-muted-foreground">{entry.severity}</span>
                        <span className="text-[10px] text-foreground font-mono font-semibold">{entry.count}</span>
                      </div>
                    ))}
                  </div>
                </>
              )}
            </ChartCard>

            {/* ── IOC Type Distribution ── */}
            <ChartCard title="IOC Type Distribution">
              {loading ? <ChartSkeleton /> : !iocData.length ? <NoData /> : (
                <div className="h-48">
                  <ResponsiveContainer width="100%" height="100%">
                    <BarChart data={iocData} layout="vertical" margin={{ top: 0, right: 16, bottom: 0, left: 4 }}>
                      <CartesianGrid stroke={chart.grid} horizontal={false} />
                      <XAxis
                        type="number"
                        tick={{ fill: chart.tick, fontSize: 9 }}
                        tickLine={false}
                        axisLine={false}
                        allowDecimals={false}
                      />
                      <YAxis
                        type="category"
                        dataKey="label"
                        tick={{ fill: chart.tick, fontSize: 9 }}
                        tickLine={false}
                        axisLine={false}
                        width={72}
                      />
                      <Tooltip
                        contentStyle={tooltipStyle}
                        itemStyle={{ color: '#e2e8f0' }}
                        cursor={{ fill: 'rgba(255,255,255,0.03)' }}
                        formatter={(v) => [v, 'IOCs']}
                      />
                      <Bar dataKey="count" radius={[0, 3, 3, 0]}>
                        {iocData.map((entry) => (
                          <Cell key={entry.ioc_type} fill={IOC_COLORS[entry.ioc_type] ?? '#64748b'} />
                        ))}
                      </Bar>
                    </BarChart>
                  </ResponsiveContainer>
                </div>
              )}
            </ChartCard>

            {/* ── Sessions by Audience ── */}
            <ChartCard title="Sessions by Audience">
              {loading ? <ChartSkeleton /> : !audienceData.length ? <NoData /> : (
                <div className="h-48">
                  <ResponsiveContainer width="100%" height="100%">
                    <BarChart data={audienceData} layout="vertical" margin={{ top: 0, right: 16, bottom: 0, left: 4 }}>
                      <CartesianGrid stroke={chart.grid} horizontal={false} />
                      <XAxis
                        type="number"
                        tick={{ fill: chart.tick, fontSize: 9 }}
                        tickLine={false}
                        axisLine={false}
                        allowDecimals={false}
                      />
                      <YAxis
                        type="category"
                        dataKey="label"
                        tick={{ fill: chart.tick, fontSize: 9 }}
                        tickLine={false}
                        axisLine={false}
                        width={82}
                      />
                      <Tooltip
                        contentStyle={tooltipStyle}
                        itemStyle={{ color: '#e2e8f0' }}
                        cursor={{ fill: 'rgba(255,255,255,0.03)' }}
                        formatter={(v) => [v, 'Sessions']}
                      />
                      <Bar dataKey="count" radius={[0, 3, 3, 0]}>
                        {audienceData.map((entry) => (
                          <Cell key={entry.audience} fill={AUDIENCE_COLORS[entry.audience] ?? '#64748b'} />
                        ))}
                      </Bar>
                    </BarChart>
                  </ResponsiveContainer>
                </div>
              )}
            </ChartCard>

            {/* ── Export Activity (full width) ── */}
            <ChartCard title="Export Activity" fullWidth>
              {loading ? <ChartSkeleton /> : !exportData.length ? (
                <div className="h-32 flex items-center justify-center text-muted-foreground/40 text-xs">
                  No exports yet
                </div>
              ) : (
                <div className="h-40">
                  <ResponsiveContainer width="100%" height="100%">
                    <BarChart data={exportData} layout="vertical" margin={{ top: 0, right: 24, bottom: 0, left: 4 }}>
                      <CartesianGrid stroke={chart.grid} horizontal={false} />
                      <XAxis
                        type="number"
                        tick={{ fill: chart.tick, fontSize: 9 }}
                        tickLine={false}
                        axisLine={false}
                        allowDecimals={false}
                      />
                      <YAxis
                        type="category"
                        dataKey="label"
                        tick={{ fill: chart.tick, fontSize: 9 }}
                        tickLine={false}
                        axisLine={false}
                        width={72}
                      />
                      <Tooltip
                        contentStyle={tooltipStyle}
                        itemStyle={{ color: '#e2e8f0' }}
                        cursor={{ fill: 'rgba(255,255,255,0.03)' }}
                        formatter={(v) => [v, 'Exports']}
                      />
                      <Bar dataKey="count" radius={[0, 3, 3, 0]}>
                        {exportData.map((entry) => (
                          <Cell key={entry.export_type} fill={EXPORT_COLORS[entry.export_type] ?? '#64748b'} />
                        ))}
                      </Bar>
                    </BarChart>
                  </ResponsiveContainer>
                </div>
              )}
            </ChartCard>

            {/* ── ATT&CK Technique Coverage (full width) ── */}
            <ChartCard title="ATT&CK Coverage" fullWidth>
              {loading ? <ChartSkeleton /> : !data?.techniqueMap.length ? (
                <div className="py-10 flex items-center justify-center text-muted-foreground/40 text-xs">
                  No techniques identified yet
                </div>
              ) : (
                <div className="space-y-4">
                  {groupedTactics.map(([tactic, techniques]) => (
                    <div key={tactic}>
                      <div className="flex items-center gap-2 mb-2">
                        <span className="text-[9px] text-muted-foreground/60 uppercase tracking-widest font-semibold">
                          {tactic}
                        </span>
                        <span className="text-[9px] text-muted-foreground/40 bg-secondary/40 rounded px-1 py-0.5">
                          {techniques.length}
                        </span>
                      </div>
                      <div className="flex flex-wrap gap-1.5">
                        {techniques.map((tech) => (
                          <button
                            key={tech.technique_id}
                            onClick={() =>
                              setSelectedTechnique(
                                selectedTechnique?.technique_id === tech.technique_id ? null : tech,
                              )
                            }
                            className={cn(
                              'text-[10px] font-mono px-1.5 py-0.5 rounded border transition-all cursor-pointer',
                              chipClass(tech.sessions.length),
                              selectedTechnique?.technique_id === tech.technique_id &&
                                'ring-1 ring-cyan-400 ring-offset-1 ring-offset-navy-900',
                            )}
                          >
                            <span className="font-semibold">{tech.technique_id}</span>
                            <span className="opacity-60 mx-0.5">·</span>
                            {tech.technique_name}
                            <span className="ml-1 opacity-50">({tech.sessions.length})</span>
                          </button>
                        ))}
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </ChartCard>

          </div>
        )}
      </div>

      {/* ── Technique Detail Panel (slide-in from right) ── */}
      <div
        className="absolute inset-y-0 right-0 w-80 bg-navy-950 border-l border-border flex flex-col shadow-2xl z-10 transition-transform duration-200"
        style={{ transform: selectedTechnique ? 'translateX(0)' : 'translateX(100%)' }}
      >
        {selectedTechnique && (
          <>
            {/* Panel header */}
            <div className="flex items-start justify-between p-4 border-b border-border flex-shrink-0">
              <div className="flex-1 min-w-0 pr-2">
                <div className="flex items-center gap-1.5 mb-1">
                  <span className="text-[10px] font-mono font-bold text-cyan-400">
                    {selectedTechnique.technique_id}
                  </span>
                  <span className="text-[9px] text-muted-foreground/50 bg-secondary/50 rounded px-1 py-0.5">
                    {selectedTechnique.tactic}
                  </span>
                </div>
                <p className="text-xs font-medium text-foreground leading-snug">
                  {selectedTechnique.technique_name}
                </p>
                <p className="text-[10px] text-muted-foreground/60 mt-0.5">
                  {selectedTechnique.sessions.length} session{selectedTechnique.sessions.length !== 1 ? 's' : ''}
                </p>
              </div>
              <button
                onClick={() => setSelectedTechnique(null)}
                className="text-muted-foreground hover:text-foreground transition-colors flex-shrink-0"
                aria-label="Close panel"
              >
                <XIcon className="w-3.5 h-3.5" />
              </button>
            </div>

            {/* Session list */}
            <div className="flex-1 overflow-y-auto">
              <div className="p-2 space-y-0.5">
                {selectedTechnique.sessions
                  .slice()
                  .sort((a, b) => b.created_at - a.created_at)
                  .map((session) => (
                    <button
                      key={session.id}
                      onClick={() => { onSelectSession(session.id); onClose(); }}
                      className="w-full flex items-center gap-2 px-2.5 py-2 rounded-md hover:bg-secondary/40 transition-colors cursor-pointer text-left group"
                    >
                      <ChevronRight className="w-3 h-3 text-muted-foreground/40 group-hover:text-cyan-400 flex-shrink-0 transition-colors" />
                      <div className="flex-1 min-w-0">
                        <p className="text-xs font-medium text-foreground truncate">{session.name}</p>
                        <p className="text-[10px] text-muted-foreground/60">
                          {formatTimestamp(session.created_at)}
                        </p>
                      </div>
                      {session.severity && (
                        <div
                          className="w-2 h-2 rounded-full flex-shrink-0"
                          style={{ backgroundColor: SEVERITY_COLORS[session.severity] ?? '#475569' }}
                          title={session.severity}
                        />
                      )}
                    </button>
                  ))}
              </div>
            </div>
          </>
        )}
      </div>
    </div>
  );
}
