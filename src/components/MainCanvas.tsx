import { useState } from 'react';
import { ChevronDown, ChevronUp, Activity, AlertCircle, NotebookPen } from 'lucide-react';
import InputPanel from './InputPanel';
import AttackChainView from './AttackChainView';
import IOCTable from './IOCTable';
import DetectionRulesTable from './DetectionRulesTable';
import TechniqueDetail from './TechniqueDetail';
import { Badge } from './ui/badge';
import { cn } from '@/lib/utils';
import type { AnalysisResult, AttackTechnique, AudienceType } from '@/types';
import { SEVERITY_COLORS } from '@/types';

interface Props {
  result: AnalysisResult | null;
  isAnalyzing: boolean;
  streamChunks: string;
  streamPhase: 1 | 2;
  statusMessage: string;
  sessionName: string;
  onSessionNameChange: (name: string) => void;
  onAnalyze: (params: {
    siemInput: string;
    textInput: string;
    logFile: File | null;
    audience: string;
    redactedStrings: string[];
  }) => void;
  error: string | null;
  analystNote: string;
  onNoteChange: (note: string) => void;
  noteSaving: boolean;
  onRegisterCapture?: (fn: () => Promise<string | null>) => void;
}

export default function MainCanvas({
  result, isAnalyzing, streamChunks, streamPhase, statusMessage,
  sessionName, onSessionNameChange, onAnalyze, error,
  analystNote, onNoteChange, noteSaving, onRegisterCapture,
}: Props) {
  const [selectedTechnique, setSelectedTechnique] = useState<AttackTechnique | null>(null);
  const [showInput, setShowInput] = useState(true);
  const [iocExpanded, setIocExpanded] = useState(true);
  const [rulesExpanded, setRulesExpanded] = useState(true);
  const [notesExpanded, setNotesExpanded] = useState(true);

  const severityBadgeVariantMap: Record<string, 'critical' | 'high' | 'medium' | 'low' | 'info'> = {
    Critical: 'critical', High: 'high', Medium: 'medium', Low: 'low', Informational: 'info',
  };
  const severityBadgeVariant = severityBadgeVariantMap[result?.incident_summary.severity ?? ''];

  // Stable key for ReactFlow — forces remount when the technique set changes (session switch)
  const chainKey = result?.attack_chain.map(t => `${t.technique_id}:${t.order}`).join(',') ?? '';

  return (
    <main className="flex-1 min-w-0 flex flex-col h-full overflow-hidden">
      {/* Input section (collapsible once we have results) */}
      <div className={cn(
        'border-b border-border transition-all',
        result ? 'flex-shrink-0' : 'flex-1'
      )}>
        {result && (
          <button
            className="w-full flex items-center justify-between px-4 py-2 text-xs text-muted-foreground hover:bg-secondary/20 transition-colors"
            onClick={() => setShowInput(!showInput)}
          >
            <span>Input Data {isAnalyzing && <span className="text-cyan-400 ml-1 animate-pulse">● Analyzing…</span>}</span>
            {showInput ? <ChevronUp className="w-3.5 h-3.5" /> : <ChevronDown className="w-3.5 h-3.5" />}
          </button>
        )}
        {(!result || showInput) && (
          <div className={cn('p-4', result ? 'py-3' : 'h-full')}>
            <InputPanel
              onAnalyze={onAnalyze}
              isAnalyzing={isAnalyzing}
              sessionName={sessionName}
              onSessionNameChange={onSessionNameChange}
            />
          </div>
        )}
      </div>

      {/* 2-phase streaming progress */}
      {isAnalyzing && (
        <div className="px-4 py-2.5 bg-navy-950 border-b border-border">
          <div className="flex items-center gap-3 mb-2">
            <PhaseStep n={1} active={streamPhase === 1} done={streamPhase === 2} label="ATT&CK + IOC Extraction" />
            <div className="flex-1 h-px bg-border" />
            <PhaseStep n={2} active={streamPhase === 2} done={false} label="Stakeholder Brief" />
          </div>
          {statusMessage && (
            <div className="text-[10px] text-cyan-400 mb-1">{statusMessage}</div>
          )}
          {streamChunks && (
            <div className="text-[10px] text-muted-foreground font-mono max-h-10 overflow-hidden">
              <div className="line-clamp-2 streaming-cursor">{streamChunks.slice(-300)}</div>
            </div>
          )}
        </div>
      )}

      {/* Error state */}
      {error && (
        <div className="mx-4 mt-3 p-3 rounded-lg bg-red-900/20 border border-red-700/40 flex items-start gap-2">
          <AlertCircle className="w-4 h-4 text-red-400 flex-shrink-0 mt-0.5" />
          <p className="text-xs text-red-300">{error}</p>
        </div>
      )}

      {/* Results */}
      {result && (
        <div className="flex-1 overflow-y-auto min-h-0">
          {/* Incident header */}
          <div className="px-4 py-3 border-b border-border bg-navy-900/50">
            <div className="flex items-start justify-between gap-4">
              <div className="min-w-0">
                <h2 className="text-sm font-semibold text-foreground">{result.incident_summary.title}</h2>
                <p className="text-xs text-muted-foreground mt-0.5 line-clamp-2">{result.incident_summary.description}</p>
              </div>
              <div className="flex-shrink-0 flex flex-col items-end gap-1">
                {severityBadgeVariant && (
                  <Badge variant={severityBadgeVariant}>{result.incident_summary.severity}</Badge>
                )}
                <span className="text-[10px] text-muted-foreground">
                  Confidence: {result.incident_summary.confidence}
                </span>
              </div>
            </div>
            {result.threat_actor?.name && (
              <div className="mt-2 text-xs text-muted-foreground">
                <span className="text-red-400">⚠ Suspected Actor:</span> {result.threat_actor.name}
                {result.threat_actor.aliases?.length > 0 && ` (${result.threat_actor.aliases.join(', ')})`}
              </div>
            )}
          </div>

          {/* ATT&CK Chain */}
          <div className="border-b border-border">
            <div className="px-4 py-2 flex items-center gap-2">
              <Activity className="w-3.5 h-3.5 text-cyan-400" />
              <span className="text-xs font-semibold text-foreground">ATT&CK Chain</span>
              <span className="text-[10px] text-muted-foreground">
                {result.attack_chain.length} technique{result.attack_chain.length !== 1 ? 's' : ''} · Click node for details
              </span>
            </div>
            <div className="h-72">
              {result.attack_chain.length > 0 ? (
                // key forces ReactFlow to remount when the technique set changes (session switch fix)
                <AttackChainView
                  key={chainKey}
                  techniques={result.attack_chain}
                  onSelectTechnique={setSelectedTechnique}
                  onRegisterCapture={onRegisterCapture}
                />
              ) : (
                <div className="h-full flex items-center justify-center text-muted-foreground text-sm">
                  No ATT&CK techniques identified.
                </div>
              )}
            </div>
          </div>

          {/* IOC Table */}
          <div className="px-4 py-3 border-b border-border">
            <button
              className="w-full flex items-center justify-between mb-3"
              onClick={() => setIocExpanded(!iocExpanded)}
            >
              <div className="flex items-center gap-2">
                <span className="text-xs font-semibold text-foreground">Indicators of Compromise</span>
                <span className="text-[10px] text-muted-foreground">({result.iocs.length})</span>
              </div>
              {iocExpanded ? <ChevronUp className="w-3.5 h-3.5 text-muted-foreground" /> : <ChevronDown className="w-3.5 h-3.5 text-muted-foreground" />}
            </button>
            {iocExpanded && <IOCTable iocs={result.iocs} />}
          </div>

          {/* Detection Rules */}
          {result.detection_rules && result.detection_rules.length > 0 && (
            <div className="px-4 py-3 border-b border-border">
              <button
                className="w-full flex items-center justify-between mb-3"
                onClick={() => setRulesExpanded(!rulesExpanded)}
              >
                <div className="flex items-center gap-2">
                  <span className="text-xs font-semibold text-foreground">Detection Rules</span>
                  <span className="text-[10px] text-muted-foreground">({result.detection_rules.length})</span>
                  <span className="text-[9px] text-purple-400/70">
                    {result.detection_rules.filter(r => r.source === 'extracted').length} extracted · {result.detection_rules.filter(r => r.source === 'generated').length} generated
                  </span>
                </div>
                {rulesExpanded
                  ? <ChevronUp className="w-3.5 h-3.5 text-muted-foreground" />
                  : <ChevronDown className="w-3.5 h-3.5 text-muted-foreground" />}
              </button>
              {rulesExpanded && <DetectionRulesTable rules={result.detection_rules} />}
            </div>
          )}

          {/* AI Analyst Notes (from Claude) */}
          {result.incident_summary.analyst_notes && (
            <div className="px-4 pt-3 pb-2">
              <div className="text-xs font-semibold text-foreground mb-1.5">AI Analyst Notes</div>
              <div className="bg-yellow-900/10 border border-yellow-700/30 rounded-lg p-3 text-xs text-yellow-200/80 leading-relaxed">
                {result.incident_summary.analyst_notes}
              </div>
            </div>
          )}

          {/* Analyst Notebook (editable, persisted per session) */}
          <div className="px-4 pb-4 pt-2">
            <button
              className="w-full flex items-center justify-between mb-2"
              onClick={() => setNotesExpanded(!notesExpanded)}
            >
              <div className="flex items-center gap-2">
                <NotebookPen className="w-3.5 h-3.5 text-cyan-400/70" />
                <span className="text-xs font-semibold text-foreground">Analyst Notebook</span>
                <span className="text-[10px] text-muted-foreground">
                  {notesExpanded ? '— your notes, saved automatically' : '— click to expand'}
                </span>
              </div>
              <div className="flex items-center gap-2">
                {noteSaving && (
                  <span className="text-[9px] text-cyan-400 animate-pulse">saving…</span>
                )}
                {!noteSaving && analystNote && (
                  <span className="text-[9px] text-green-400">✓ saved</span>
                )}
                {notesExpanded ? <ChevronUp className="w-3.5 h-3.5 text-muted-foreground" /> : <ChevronDown className="w-3.5 h-3.5 text-muted-foreground" />}
              </div>
            </button>
            {notesExpanded && (
              <textarea
                value={analystNote}
                onChange={(e) => onNoteChange(e.target.value)}
                placeholder={`Add your analysis notes here — caveats, additional context, follow-up actions, open questions.\n\nExamples:\n• Corroborated by IR ticket INC-2024-1182\n• PROD-WEB-01 has been isolated, awaiting reimaging\n• Follow up: check if T1053 was used for persistence on other hosts`}
                rows={6}
                className="w-full bg-navy-950 border border-border rounded-lg p-3 text-xs text-foreground placeholder:text-muted-foreground/40 resize-none focus:outline-none focus:ring-1 focus:ring-cyan-500 leading-relaxed"
                spellCheck={false}
              />
            )}
          </div>
        </div>
      )}

      {/* Technique detail modal */}
      {selectedTechnique && (
        <TechniqueDetail
          technique={selectedTechnique}
          onClose={() => setSelectedTechnique(null)}
        />
      )}
    </main>
  );
}

// ── Phase step indicator ───────────────────────────────────────────────────────
function PhaseStep({ n, active, done, label }: { n: number; active: boolean; done: boolean; label: string }) {
  return (
    <div className={cn(
      'flex items-center gap-1.5 text-[10px]',
      active ? 'text-cyan-400' : done ? 'text-green-400' : 'text-muted-foreground/40'
    )}>
      <div className={cn(
        'w-4 h-4 rounded-full border flex items-center justify-center text-[9px] font-bold flex-shrink-0',
        active ? 'border-cyan-400 bg-cyan-400/10' : done ? 'border-green-400 bg-green-400/10' : 'border-muted-foreground/30'
      )}>
        {done ? '✓' : n}
      </div>
      <span>{label}</span>
    </div>
  );
}
