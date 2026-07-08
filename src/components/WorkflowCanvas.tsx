import { useState, useEffect, useRef, useCallback, lazy, Suspense } from 'react';
import ReactMarkdown from 'react-markdown';
import {
  ChevronLeft, Activity, AlertCircle, NotebookPen, Download, Package, Save,
  Mail, Map, Shield, Pencil, Eye, RotateCcw, ChevronDown, ChevronUp, FileText,
  Maximize2, X, PenLine,
} from 'lucide-react';
import InputPanel from './InputPanel';
import AttackChainView from './AttackChainView';
import AttackFlowView from './AttackFlowView';
import IOCTable from './IOCTable';
import DetectionRulesTable from './DetectionRulesTable';
import TechniqueDetail from './TechniqueDetail';
import TagEditor from './TagEditor';
import ThreatActorAssignDialog from './ThreatActorAssignDialog';
import ConfirmDialog from './ConfirmDialog';
import RichTextEditor from './RichTextEditor';
// Large on-demand overlay — split into its own chunk.
const EmailStudio = lazy(() => import('./EmailStudio'));
import { Badge } from './ui/badge';
import { Button } from './ui/button';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from './ui/select';
import { cn } from '@/lib/utils';
import { TLP_BAND_COLORS, SEVERITY_BAND } from '@/lib/constants';
import type { AnalysisResult, AttackTechnique, AudienceType, TLPLevel, EmailContent, CustomAudience, BriefSection } from '@/types';
import { AUDIENCE_LABELS, SEVERITY_COLORS } from '@/types';
import * as api from '@/lib/api';
import { parseSections, DEFAULT_SECTIONS, AUTO_TYPES } from '@/lib/sections';

// ── Constants ────────────────────────────────────────────────────────────────

const TLP_OPTIONS: TLPLevel[] = ['CLEAR', 'GREEN', 'AMBER', 'AMBER+STRICT', 'RED'];

const TLP_COLORS: Record<TLPLevel, string> = {
  CLEAR: 'text-white',
  GREEN: 'text-green-400',
  AMBER: 'text-yellow-400',
  'AMBER+STRICT': 'text-orange-400',
  RED: 'text-red-400',
};


const SEVERITY_BADGE_MAP: Record<string, 'critical' | 'high' | 'medium' | 'low' | 'info'> = {
  Critical: 'critical', High: 'high', Medium: 'medium', Low: 'low', Informational: 'info',
};

// ── Props ────────────────────────────────────────────────────────────────────

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
  // Output config
  sessionId: string | null;
  audience: string;
  onAudienceChange: (a: string) => void;
  onShowToast?: (message: string, type?: 'success' | 'error' | 'info') => void;
  captureAttackChain?: () => Promise<string | null>;
  customAudiences?: CustomAudience[];
  onResultUpdate?: (result: AnalysisResult) => void;
  onSaveComplete?: () => void;
  sessionTags?: string[];
  allTags?: string[];
  onUpdateTags?: (tags: string[]) => void;
  linkedThreatActor?: { id: string; name: string } | null;
  threatActors?: import('@/types').ThreatActorSummary[];
  onActorAssigned?: () => void;
  sessionStatus?: string | null;
  onReanalyze?: (audienceOverride?: string) => void;
  analystOverrides?: Record<string, string>;
  onOpenWorkbench?: () => void;
}

// ── WorkflowCanvas ────────────────────────────────────────────────────────────

export default function WorkflowCanvas({
  result, isAnalyzing, streamChunks, streamPhase, statusMessage,
  sessionName, onSessionNameChange, onAnalyze, error,
  analystNote, onNoteChange, noteSaving, onRegisterCapture,
  sessionId, audience, onAudienceChange, onShowToast,
  captureAttackChain, customAudiences = [], onResultUpdate, onSaveComplete,
  sessionTags = [], allTags = [], onUpdateTags,
  linkedThreatActor, threatActors = [], onActorAssigned,
  sessionStatus, onReanalyze, analystOverrides = {}, onOpenWorkbench,
}: Props) {
  // ── Workflow step ────────────────────────────────────────────────────────
  const [step, setStep] = useState<'input' | 'results'>('input');

  // Auto-advance to results when analysis completes
  useEffect(() => {
    if (result && !isAnalyzing) setStep('results');
  }, [result, isAnalyzing]);

  // Return to input when session is cleared
  useEffect(() => {
    if (!result && !isAnalyzing) setStep('input');
  }, [result, isAnalyzing]);

  // Threat actor assign dialog
  const [showActorAssign, setShowActorAssign] = useState(false);

  // Re-analyze confirmation dialog
  const [showReanalyzeConfirm, setShowReanalyzeConfirm] = useState(false);

  // ── Output config state (was in RightPanel) ──────────────────────────────
  const [tlp, setTlp] = useState<TLPLevel>('AMBER');
  const [attachStix, setAttachStix] = useState(false);
  const [attachNav, setAttachNav] = useState(false);
  const [attachIocs, setAttachIocs] = useState(false);
  const [attachRules, setAttachRules] = useState(false);
  const [attachDiagram, setAttachDiagram] = useState(false);
  const [exporting, setExporting] = useState<string | null>(null);
  const [isEditingEmail, setIsEditingEmail] = useState(false);
  const [emailStudioOpen, setEmailStudioOpen] = useState(false);
  const [editedEmail, setEditedEmail] = useState<EmailContent | null>(null);
  const [sections, setSections] = useState<BriefSection[]>(DEFAULT_SECTIONS);
  const [severityOverride, setSeverityOverride] = useState<string | null>(null);

  // Sync editedEmail + clear severity override when result changes
  useEffect(() => {
    if (result?.email_content) {
      setEditedEmail({ ...result.email_content });
      setIsEditingEmail(false);
      setSeverityOverride(null);
    } else {
      setEditedEmail(null);
      setSeverityOverride(null);
    }
  }, [result]);

  // Load sections from settings on mount
  useEffect(() => {
    api.fetchSettings().then(s => {
      setSections(parseSections(s['report_sections'] || ''));
    }).catch(() => {});
  }, []);

  // IOC false positives — persisted in analyst_overrides under 'ioc_false_positives'.
  // savedOverridesRef mirrors the last-persisted overrides JSON so partial saves
  // never wipe other saved keys (the server replaces the whole overrides object).
  const [iocFalsePositives, setIocFalsePositives] = useState<string[]>([]);
  const savedOverridesRef = useRef<Record<string, string>>({});

  useEffect(() => {
    savedOverridesRef.current = { ...analystOverrides };
    try {
      const parsed = JSON.parse(analystOverrides['ioc_false_positives'] || '[]') as string[];
      setIocFalsePositives(Array.isArray(parsed) ? parsed : []);
    } catch {
      setIocFalsePositives([]);
    }
  }, [analystOverrides]);

  const toggleFalsePositive = useCallback(async (key: string) => {
    if (!sessionId) return;
    const next = iocFalsePositives.includes(key)
      ? iocFalsePositives.filter((k) => k !== key)
      : [...iocFalsePositives, key];
    setIocFalsePositives(next);
    const merged = { ...savedOverridesRef.current, ioc_false_positives: JSON.stringify(next) };
    try {
      await api.saveOverrides(sessionId, merged);
      savedOverridesRef.current = merged;
    } catch {
      onShowToast?.('Failed to save false-positive state', 'error');
    }
  }, [sessionId, iocFalsePositives, onShowToast]);

  const hasEdits = (editedEmail && result?.email_content
    ? JSON.stringify(editedEmail) !== JSON.stringify(result.email_content)
    : false) || severityOverride !== null;

  const setEmailField = (key: string, value: string) => {
    setEditedEmail((prev) => prev ? { ...prev, [key]: value } : prev);
  };

  const handleResetEmail = () => {
    if (result?.email_content) {
      setEditedEmail({ ...result.email_content });
      setSeverityOverride(null);
    }
  };

  // ── View state ───────────────────────────────────────────────────────────
  const [activeTab, setActiveTab] = useState<'email' | 'stix' | 'navigator'>('email');
  const [chainViewMode, setChainViewMode] = useState<'chain' | 'flow'>('chain');
  const [graphExpanded, setGraphExpanded] = useState(false);
  const [selectedTechnique, setSelectedTechnique] = useState<AttackTechnique | null>(null);
  const [iocExpanded, setIocExpanded] = useState(true);
  const [rulesExpanded, setRulesExpanded] = useState(true);
  const [notesExpanded, setNotesExpanded] = useState(true);
  const [reportMarkdown, setReportMarkdown] = useState<string | null>(null);
  const [reportLoading, setReportLoading] = useState(false);
  const [isEditingReport, setIsEditingReport] = useState(false);
  const [editedReportMarkdown, setEditedReportMarkdown] = useState<string | null>(null);
  const [editsSaving, setEditsSaving] = useState(false);

  // ── Export helpers ───────────────────────────────────────────────────────
  const exportAction = async (action: string, label: string, fn: () => Promise<void>) => {
    setExporting(action);
    try {
      await fn();
      onShowToast?.(`${label} downloaded successfully`, 'success');
    } catch (e) {
      onShowToast?.(`Export failed: ${e instanceof Error ? e.message : 'Unknown error'}`, 'error');
    } finally {
      setExporting(null);
    }
  };

  const getDiagramB64 = async (): Promise<string | undefined> => {
    if (!attachDiagram || !captureAttackChain) return undefined;
    const dataUrl = await captureAttackChain();
    if (!dataUrl) return undefined;
    return dataUrl.replace(/^data:image\/[^;]+;base64,/, '');
  };

  const getEmailOverrides = (): EmailContent | undefined => {
    if (!editedEmail || !result?.email_content) return undefined;
    const orig = result.email_content;
    const editableKeys = ['subject', ...sections.filter(s => s.enabled && !AUTO_TYPES.has(s.type)).map(s => s.key)];
    const overrides: EmailContent = { subject: editedEmail.subject as string, severity_badge: editedEmail.severity_badge as string };
    let hasChanges = (editedEmail['severity_badge'] as string) !== (orig['severity_badge'] as string);
    for (const key of editableKeys) {
      if (editedEmail[key] !== orig[key]) {
        overrides[key] = editedEmail[key];
        hasChanges = true;
      }
    }
    return hasChanges ? overrides : undefined;
  };

  // Stable primitive key — changes only when report-relevant overrides change
  const reportOverridesKey = JSON.stringify(getEmailOverrides() ?? null);


  const SEVERITY_OPTIONS = ['Critical', 'High', 'Medium', 'Low', 'Informational'];

  const handleSeverityChange = (newSeverity: string) => {
    setSeverityOverride(newSeverity);
    setEditedEmail(prev => {
      if (!prev) return prev;
      // Also update the severity segment inside the subject line.
      // Subject format: TLP:{LEVEL} | {Severity} | {Category} | {Date}
      const oldSubject = (prev.subject as string) ?? '';
      const parts = oldSubject.split('|').map(s => s.trim());
      if (parts.length >= 2) {
        parts[1] = newSeverity;
      }
      return { ...prev, severity_badge: newSeverity, subject: parts.join(' | ') };
    });
  };

  const handleSaveEdits = async () => {
    if (!sessionId || !hasEdits) return;
    const overrides = getEmailOverrides();
    if (!overrides) return;
    setEditsSaving(true);
    try {
      // Merge with previously saved overrides — the server replaces the whole
      // overrides JSON, so sending only the new diff would wipe older saves
      // (including ioc_false_positives).
      const mergedOverrides = { ...savedOverridesRef.current, ...(overrides as Record<string, string>) };
      await api.saveOverrides(sessionId, mergedOverrides);
      savedOverridesRef.current = mergedOverrides;
      // Update the result baseline so hasEdits resets
      if (result && onResultUpdate) {
        const updated = {
          ...result,
          email_content: { ...result.email_content, ...overrides },
          // Sync incident_summary.severity so the dropdown stays correct after save
          incident_summary: overrides.severity_badge
            ? { ...result.incident_summary, severity: overrides.severity_badge as 'Critical' | 'High' | 'Medium' | 'Low' | 'Informational' }
            : result.incident_summary,
        };
        onResultUpdate(updated);
      }
      setSeverityOverride(null);
      onSaveComplete?.();
      onShowToast?.('Edits saved', 'success');
    } catch (e) {
      onShowToast?.(`Save failed: ${e instanceof Error ? e.message : 'Unknown error'}`, 'error');
    } finally {
      setEditsSaving(false);
    }
  };

  const effectiveSeverity = severityOverride ?? result?.incident_summary.severity ?? '';
  const chainKey = result?.attack_chain.map(t => `${t.technique_id}:${t.order}`).join(',') ?? '';
  const hasAttackFlow = !!result?.attack_flow && (result.attack_flow.nodes?.length ?? 0) >= 2;
  const disabled = !sessionId || !result;
  const displayEmail = editedEmail ?? result?.email_content;
  const severityBadgeVariant = SEVERITY_BADGE_MAP[effectiveSeverity];

  // Two-phase streaming progress — shown during any analysis (fresh or re-run),
  // in both the input step and the results view so re-analysis is always visible.
  const analyzingProgress = isAnalyzing ? (
    <div className="px-4 py-2.5 bg-navy-950 border-b border-border flex-shrink-0">
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
  ) : null;

  // ── Step 1: Input ────────────────────────────────────────────────────────
  if (step === 'input') {
    return (
      <main className="flex-1 min-w-0 flex flex-col h-full overflow-hidden">
        {/* Step indicator */}
        <div className="flex-shrink-0 px-4 py-2 border-b border-border bg-navy-900/50 flex items-center gap-3">
          <StepDot n={1} active label="Configure & Analyze" />
          <div className="flex-1 h-px bg-border/40" />
          <StepDot n={2} active={false} label="Review & Export" />
        </div>

        {/* 2-phase streaming progress */}
        {analyzingProgress}

        {/* Error */}
        {error && (
          <div className="mx-4 mt-3 p-3 rounded-lg bg-red-900/20 border border-red-700/40 flex items-start gap-2 flex-shrink-0">
            <AlertCircle className="w-4 h-4 text-red-400 flex-shrink-0 mt-0.5" />
            <p className="text-xs text-red-300">{error}</p>
          </div>
        )}

        {/* Failed analysis — offer retry from stored inputs */}
        {sessionId && sessionStatus === 'failed' && onReanalyze && !isAnalyzing && (
          <div className="mx-4 mt-3 p-3 rounded-lg bg-red-900/20 border border-red-700/40 flex items-center gap-3 flex-shrink-0">
            <AlertCircle className="w-4 h-4 text-red-400 flex-shrink-0" />
            <div className="flex-1 min-w-0">
              <p className="text-xs text-red-300 font-medium">This analysis failed or was interrupted.</p>
              <p className="text-[10px] text-red-300/70">The original inputs are saved — you can retry without re-entering them.</p>
            </div>
            <Button
              size="sm"
              className="h-7 px-3 text-xs bg-red-500/20 text-red-300 hover:bg-red-500/30 border border-red-500/30 flex-shrink-0"
              onClick={() => onReanalyze()}
            >
              <RotateCcw className="w-3 h-3 mr-1" />
              Retry Analysis
            </Button>
          </div>
        )}

        <div className="flex-1 overflow-y-auto p-4">
          <InputPanel
            onAnalyze={onAnalyze}
            isAnalyzing={isAnalyzing}
            sessionName={sessionName}
            onSessionNameChange={onSessionNameChange}
            customAudiences={customAudiences}
          />
        </div>
      </main>
    );
  }

  // ── Step 2: Results & Export ─────────────────────────────────────────────
  return (
    <main className="flex-1 min-w-0 flex flex-col h-full overflow-hidden">
      {/* Re-analysis progress — pinned at top so progress is visible in place */}
      {analyzingProgress}

      {/* Sticky header */}
      <div className="flex-shrink-0 border-b border-border bg-navy-900">
        {/* Row 1: Navigation + session info */}
        <div className="px-4 py-2.5 flex items-center gap-3 border-b border-border/50">
          <button
            onClick={() => setStep('input')}
            className="flex items-center gap-1 text-xs text-muted-foreground hover:text-foreground transition-colors"
          >
            <ChevronLeft className="w-3.5 h-3.5" />
            New Analysis
          </button>
          <div className="w-px h-4 bg-border" />
          <div className="flex-1 min-w-0">
            <h2 className="text-sm font-semibold text-foreground truncate">
              {result?.incident_summary.title ?? sessionName}
            </h2>
            {sessionId && onActorAssigned ? (
              <button
                onClick={() => setShowActorAssign(true)}
                className={cn(
                  'text-[10px] truncate transition-colors text-left',
                  linkedThreatActor && linkedThreatActor.name !== 'Unattributed'
                    ? 'text-red-400/80 hover:text-red-300'
                    : 'text-muted-foreground/50 hover:text-muted-foreground',
                )}
                title="Click to assign or change threat actor"
              >
                {linkedThreatActor && linkedThreatActor.name !== 'Unattributed'
                  ? `⚠ ${linkedThreatActor.name}`
                  : '+ Assign Threat Actor'}
              </button>
            ) : result?.threat_actor?.name ? (
              <div className="text-[10px] text-red-400/80 truncate">
                ⚠ Suspected: {result.threat_actor.name}
              </div>
            ) : null}
            {sessionId && onUpdateTags && (
              <div className="mt-1">
                <TagEditor
                  tags={sessionTags}
                  allTags={allTags}
                  onChange={onUpdateTags}
                  compact
                />
              </div>
            )}
          </div>
          <div className="flex items-center gap-2 flex-shrink-0">
            {result && (
              <div className="flex items-center gap-1">
                <Select value={effectiveSeverity} onValueChange={handleSeverityChange}>
                  <SelectTrigger className={cn(
                    'h-6 text-[11px] font-semibold border-0 px-2 py-0 focus:ring-0 w-auto gap-1',
                    severityBadgeVariant === 'critical' && 'bg-red-900/60 text-red-200 hover:bg-red-900/80',
                    severityBadgeVariant === 'high'     && 'bg-red-800/50 text-red-300 hover:bg-red-800/70',
                    severityBadgeVariant === 'medium'   && 'bg-orange-800/50 text-orange-300 hover:bg-orange-800/70',
                    severityBadgeVariant === 'low'      && 'bg-green-800/50 text-green-300 hover:bg-green-800/70',
                    severityBadgeVariant === 'info'     && 'bg-blue-800/50 text-blue-300 hover:bg-blue-800/70',
                    !severityBadgeVariant               && 'bg-secondary/60 text-muted-foreground',
                  )}>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {SEVERITY_OPTIONS.map(s => (
                      <SelectItem key={s} value={s} className="text-xs">{s}</SelectItem>
                    ))}
                  </SelectContent>
                </Select>
                {severityOverride && (
                  <span className="text-[9px] text-yellow-400 border border-yellow-400/30 rounded px-1 py-0.5">
                    Overridden
                  </span>
                )}
              </div>
            )}
            {result && (
              <span className="text-[10px] text-muted-foreground hidden sm:inline">
                Confidence: {result.incident_summary.confidence}
              </span>
            )}
          </div>
        </div>

        {/* Row 2: Controls + tabs */}
        <div className="px-4 py-2 flex items-center gap-3 flex-wrap">
          {/* Audience */}
          <div className="flex items-center gap-1.5">
            <span className="text-[10px] text-muted-foreground">Audience</span>
            <Select value={audience} onValueChange={onAudienceChange}>
              <SelectTrigger className="h-7 text-xs bg-secondary/50 border-border w-36">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {(Object.entries(AUDIENCE_LABELS) as [AudienceType, string][]).map(([k, v]) => (
                  <SelectItem key={k} value={k} className="text-xs">{v}</SelectItem>
                ))}
                {customAudiences.length > 0 && (
                  <>
                    <div className="px-2 py-1 text-[10px] text-muted-foreground/50 uppercase tracking-widest">Custom</div>
                    {customAudiences.map((a) => (
                      <SelectItem key={a.id} value={a.id} className="text-xs">{a.label}</SelectItem>
                    ))}
                  </>
                )}
              </SelectContent>
            </Select>
          </div>

          {/* Re-analyze */}
          {result && sessionId && onReanalyze && (
            <Button
              variant="ghost"
              size="sm"
              className="h-7 px-2 text-xs text-muted-foreground hover:text-cyan-400"
              onClick={() => setShowReanalyzeConfirm(true)}
              disabled={isAnalyzing}
              title="Re-run analysis using this session's stored inputs and the selected audience"
            >
              <RotateCcw className="w-3 h-3 mr-1" />
              Re-analyze
            </Button>
          )}

          {/* Edit in Workbench */}
          {result && sessionId && onOpenWorkbench && (
            <Button
              variant="ghost"
              size="sm"
              className="h-7 px-2 text-xs text-muted-foreground hover:text-cyan-400"
              onClick={onOpenWorkbench}
              disabled={isAnalyzing}
              title="Hand-edit this report's techniques, IOCs, rules and narrative in the Analyst Workbench"
            >
              <PenLine className="w-3 h-3 mr-1" />
              Workbench
            </Button>
          )}

          {/* TLP */}
          <div className="flex items-center gap-1.5">
            <span className="text-[10px] text-muted-foreground">TLP</span>
            <Select value={tlp} onValueChange={(v) => setTlp(v as TLPLevel)}>
              <SelectTrigger className="h-7 text-xs bg-secondary/50 border-border w-36">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {TLP_OPTIONS.map((t) => (
                  <SelectItem key={t} value={t} className={cn('text-xs', TLP_COLORS[t])}>TLP:{t}</SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>

          <div className="w-px h-4 bg-border/60 hidden sm:block" />

          {/* Output tabs */}
          <div className="flex items-center gap-1 bg-secondary/40 rounded-md p-0.5">
            {(['email', 'stix', 'navigator'] as const).map((tab) => (
              <button
                key={tab}
                onClick={() => setActiveTab(tab)}
                className={cn(
                  'flex items-center gap-1.5 px-2.5 py-1 rounded text-xs transition-colors',
                  activeTab === tab
                    ? 'bg-background text-foreground shadow-sm'
                    : 'text-muted-foreground hover:text-foreground'
                )}
              >
                {tab === 'email' && <Mail className="w-3 h-3" />}
                {tab === 'stix' && <Shield className="w-3 h-3" />}
                {tab === 'navigator' && <Map className="w-3 h-3" />}
                {tab === 'email' ? 'Email' : tab.charAt(0).toUpperCase() + tab.slice(1)}
              </button>
            ))}
          </div>

          {/* Email edit controls */}
          {activeTab === 'email' && !disabled && (
            <div className="flex items-center gap-1 ml-auto">
              {hasEdits && (
                <span className="text-[9px] text-yellow-400 border border-yellow-400/30 rounded px-1.5 py-0.5">
                  Edited
                </span>
              )}
              {hasEdits && !isEditingEmail && (
                <>
                  <button
                    onClick={handleSaveEdits}
                    disabled={editsSaving}
                    className="flex items-center gap-1 text-[10px] text-green-400 hover:text-green-300 border border-green-400/30 rounded px-1.5 py-0.5 transition-colors hover:bg-green-400/5"
                  >
                    <Save className="w-2.5 h-2.5" />{editsSaving ? 'Saving…' : 'Save'}
                  </button>
                  <button
                    onClick={handleResetEmail}
                    className="flex items-center gap-1 text-[10px] text-muted-foreground hover:text-foreground transition-colors px-1.5 py-0.5 rounded hover:bg-secondary/50"
                  >
                    <RotateCcw className="w-2.5 h-2.5" />Reset
                  </button>
                </>
              )}
              <button
                onClick={() => setIsEditingEmail(!isEditingEmail)}
                className={cn(
                  'flex items-center gap-1 text-[10px] px-2 py-0.5 rounded border transition-colors',
                  isEditingEmail
                    ? 'bg-cyan-500/10 border-cyan-500/30 text-cyan-400'
                    : 'border-border text-muted-foreground hover:text-foreground hover:bg-secondary/50'
                )}
              >
                {isEditingEmail
                  ? <><Eye className="w-2.5 h-2.5" />Preview</>
                  : <><Pencil className="w-2.5 h-2.5" />Edit</>}
              </button>
              <button
                onClick={() => setEmailStudioOpen(true)}
                className="flex items-center gap-1 text-[10px] px-2 py-0.5 rounded border border-cyan-500/30 bg-cyan-500/10 text-cyan-400 hover:bg-cyan-500/20 transition-colors"
                title="Open the full-screen Email Studio — live preview + edit content, layout, branding, and sections"
              >
                <Maximize2 className="w-2.5 h-2.5" />Email Studio
              </button>
            </div>
          )}

        </div>
      </div>

      {/* Scrollable body */}
      <div className="flex-1 overflow-y-auto min-h-0">

        {/* ATT&CK Chain / Attack Flow */}
        <div className="border-b border-border">
          <div className="px-4 py-2 flex items-center gap-2">
            <Activity className="w-3.5 h-3.5 text-cyan-400" />
            <span className="text-xs font-semibold text-foreground">
              {chainViewMode === 'flow' && hasAttackFlow ? 'Attack Flow' : 'ATT&CK Chain'}
            </span>
            {result && (
              <span className="text-[10px] text-muted-foreground">
                {chainViewMode === 'flow' && hasAttackFlow
                  ? `${result.attack_flow!.nodes.length} nodes · Click an action for details`
                  : `${result.attack_chain.length} technique${result.attack_chain.length !== 1 ? 's' : ''} · Click node for details`}
              </span>
            )}
            {/* Chain/Flow segmented toggle + expand */}
            {result && result.attack_chain.length > 0 && (
              <div className="ml-auto flex items-center gap-1.5">
                {hasAttackFlow ? (
                  <div className="flex items-center rounded-md border border-border overflow-hidden">
                    <button
                      onClick={() => setChainViewMode('chain')}
                      className={cn('px-2 py-0.5 text-[10px] transition-colors',
                        chainViewMode === 'chain' ? 'bg-cyan-500/20 text-cyan-300' : 'text-muted-foreground hover:text-foreground')}
                    >
                      Chain
                    </button>
                    <button
                      onClick={() => setChainViewMode('flow')}
                      className={cn('px-2 py-0.5 text-[10px] transition-colors border-l border-border',
                        chainViewMode === 'flow' ? 'bg-cyan-500/20 text-cyan-300' : 'text-muted-foreground hover:text-foreground')}
                    >
                      Flow
                    </button>
                  </div>
                ) : (
                  <span className="text-[9px] text-muted-foreground/50 italic">Re-analyze to generate attack flow</span>
                )}
                <button
                  onClick={() => setGraphExpanded(true)}
                  title="Expand view"
                  aria-label="Expand view"
                  className="p-1 rounded text-muted-foreground hover:text-cyan-300 hover:bg-secondary/60 transition-colors"
                >
                  <Maximize2 className="w-3.5 h-3.5" />
                </button>
              </div>
            )}
          </div>
          <div className="h-72">
            {result?.attack_chain && result.attack_chain.length > 0 ? (
              chainViewMode === 'flow' && hasAttackFlow ? (
                <AttackFlowView
                  key={`flow-${chainKey}`}
                  flow={result.attack_flow!}
                  attackChain={result.attack_chain}
                  onExpand={setSelectedTechnique}
                />
              ) : (
                <AttackChainView
                  key={chainKey}
                  techniques={result.attack_chain}
                  onSelectTechnique={setSelectedTechnique}
                  onRegisterCapture={onRegisterCapture}
                />
              )
            ) : (
              <div className="h-full flex items-center justify-center text-muted-foreground text-sm">
                No ATT&CK techniques identified.
              </div>
            )}
          </div>
        </div>

        {/* Output tab content (full width) */}
        <div className="border-b border-border px-4 py-3">
          {activeTab === 'email' && (
            disabled ? (
              <EmptyState message="Run an analysis to generate stakeholder emails." />
            ) : isEditingEmail && editedEmail ? (
              <EmailEditor email={editedEmail} onChange={setEmailField} audience={audience} tlp={tlp} sections={sections} />
            ) : displayEmail ? (
              <EmailPreview email={displayEmail} audience={audience} tlp={tlp} sections={sections} result={result} />
            ) : (
              <EmptyState message="No email content generated yet." />
            )
          )}
          {activeTab === 'stix' && (
            disabled ? (
              <EmptyState message="Run an analysis to generate STIX 2.1 bundle." />
            ) : (
              <StixPreview result={result!} />
            )
          )}
          {activeTab === 'navigator' && (
            disabled ? (
              <EmptyState message="Run an analysis to generate ATT&CK Navigator layer." />
            ) : (
              <NavigatorPreview result={result!} />
            )
          )}
        </div>

        {/* IOC Table */}
        <div className="px-4 py-3 border-b border-border">
          <button
            className="w-full flex items-center justify-between mb-3"
            onClick={() => setIocExpanded(!iocExpanded)}
          >
            <div className="flex items-center gap-2">
              <span className="text-xs font-semibold text-foreground">Indicators of Compromise</span>
              {result && <span className="text-[10px] text-muted-foreground">({result.iocs.length})</span>}
            </div>
            {iocExpanded
              ? <ChevronUp className="w-3.5 h-3.5 text-muted-foreground" />
              : <ChevronDown className="w-3.5 h-3.5 text-muted-foreground" />}
          </button>
          {iocExpanded && result && (
            <>
              <IOCTable
                iocs={result.iocs}
                falsePositives={iocFalsePositives}
                onToggleFalsePositive={sessionId ? toggleFalsePositive : undefined}
              />
              {result.iocs.length > 0 && (
                <Button
                  variant="outline"
                  className="w-full text-xs h-7 mt-2 gap-1.5"
                  disabled={disabled || !!exporting}
                  onClick={() => exportAction('iocs-csv', 'IOCs (.csv)', () => api.exportIocsCsv(sessionId!, tlp))}
                >
                  <Download className="w-3 h-3" />
                  {exporting === 'iocs-csv' ? 'Exporting…' : 'Download CSV'}
                </Button>
              )}
            </>
          )}
        </div>

        {/* Detection Rules */}
        {result && result.detection_rules && result.detection_rules.length > 0 && (
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

        {/* AI Analyst Notes */}
        {result?.incident_summary.analyst_notes && (
          <div className="px-4 pt-3 pb-2 border-b border-border">
            <div className="text-xs font-semibold text-foreground mb-1.5">AI Analyst Notes</div>
            <div className="bg-yellow-900/10 border border-yellow-700/30 rounded-lg p-3 text-xs text-yellow-200/80 leading-relaxed">
              {result.incident_summary.analyst_notes}
            </div>
          </div>
        )}

        {/* Analyst Notebook */}
        <div className="px-4 pb-4 pt-3 border-b border-border">
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
              {noteSaving && <span className="text-[9px] text-cyan-400 animate-pulse">saving…</span>}
              {!noteSaving && analystNote && <span className="text-[9px] text-green-400">✓ saved</span>}
              {notesExpanded
                ? <ChevronUp className="w-3.5 h-3.5 text-muted-foreground" />
                : <ChevronDown className="w-3.5 h-3.5 text-muted-foreground" />}
            </div>
          </button>
          {notesExpanded && (
            <textarea
              value={analystNote}
              onChange={(e) => onNoteChange(e.target.value)}
              placeholder={`Add your analysis notes here — caveats, context, follow-up actions.\n\nExamples:\n• Corroborated by IR ticket INC-2024-1182\n• PROD-WEB-01 has been isolated\n• Follow up: check T1053 persistence on other hosts`}
              rows={5}
              className="w-full bg-navy-950 border border-border rounded-lg p-3 text-xs text-foreground placeholder:text-muted-foreground/40 resize-none focus:outline-none focus:ring-1 focus:ring-cyan-500 leading-relaxed"
              spellCheck={false}
            />
          )}
        </div>

        {/* Export actions */}
        <div className="px-4 py-4">
          <div className="text-[10px] uppercase tracking-widest text-muted-foreground/60 mb-3">Export Options</div>

          {/* Attachment toggles */}
          <div className="flex flex-wrap gap-x-5 gap-y-1.5 text-xs text-muted-foreground mb-3">
            <label className="flex items-center gap-1.5 cursor-pointer">
              <input type="checkbox" checked={attachStix} onChange={(e) => setAttachStix(e.target.checked)} className="rounded border-border" />
              Attach STIX
            </label>
            <label className="flex items-center gap-1.5 cursor-pointer">
              <input type="checkbox" checked={attachNav} onChange={(e) => setAttachNav(e.target.checked)} className="rounded border-border" />
              Attach Navigator
            </label>
            {result?.iocs && result.iocs.length > 0 && (
              <label className="flex items-center gap-1.5 cursor-pointer">
                <input type="checkbox" checked={attachIocs} onChange={(e) => setAttachIocs(e.target.checked)} className="rounded border-border" />
                Attach IOC list (.txt)
              </label>
            )}
            {result?.detection_rules && result.detection_rules.length > 0 && (
              <label className="flex items-center gap-1.5 cursor-pointer">
                <input type="checkbox" checked={attachRules} onChange={(e) => setAttachRules(e.target.checked)} className="rounded border-border" />
                Attach detection rules (.txt)
              </label>
            )}
            {captureAttackChain && result?.attack_chain && result.attack_chain.length > 0 && (
              <label className="flex items-center gap-1.5 cursor-pointer">
                <input type="checkbox" checked={attachDiagram} onChange={(e) => setAttachDiagram(e.target.checked)} className="rounded border-border" />
                Attach chain diagram (.png)
              </label>
            )}
          </div>

          {/* Export buttons */}
          <div className="flex flex-wrap gap-2">
            <Button
              variant="outline"
              className="text-xs h-8 gap-1.5"
              disabled={disabled || !!exporting}
              onClick={() => exportAction('eml', 'Email brief (.eml)', async () => {
                const diagramB64 = await getDiagramB64();
                await api.exportEml({
                  session_id: sessionId!,
                  audience, tlp,
                  attach_stix: attachStix,
                  attach_navigator: attachNav,
                  attach_iocs: attachIocs || undefined,
                  attach_detection_rules: attachRules || undefined,
                  diagram_jpg_b64: diagramB64,
                  email_content_overrides: getEmailOverrides(),
                });
              })}
            >
              <Download className="w-3.5 h-3.5" />
              {exporting === 'eml' ? 'Exporting…' : 'Download .eml'}
            </Button>
            <Button
              variant="outline"
              className="text-xs h-8 gap-1.5"
              disabled={disabled || !!exporting}
              onClick={() => exportAction('report', 'CTI Report (.md)', () =>
                api.exportReport({ session_id: sessionId!, audience, tlp, email_content_overrides: getEmailOverrides() })
              )}
            >
              <Download className="w-3.5 h-3.5" />
              {exporting === 'report' ? 'Generating…' : 'Download CTI Report (.md)'}
            </Button>
            <Button
              variant="outline"
              className="text-xs h-8 gap-1.5"
              disabled={disabled}
              onClick={async () => {
                if (!result) return;
                // jsPDF is heavy — load it only when the analyst actually exports.
                const { exportPdf } = await import('../lib/pdf-export');
                exportPdf(result, tlp, editedEmail ?? undefined, sections);
              }}
            >
              <Download className="w-3.5 h-3.5" />
              Download PDF
            </Button>
            <Button
              variant="outline"
              className="text-xs h-8 gap-1.5"
              disabled={disabled || !!exporting}
              onClick={() => exportAction('stix', 'STIX bundle', () => api.exportStix(sessionId!, tlp))}
            >
              <Download className="w-3.5 h-3.5" />
              {exporting === 'stix' ? 'Exporting…' : 'Download STIX'}
            </Button>
            <Button
              variant="outline"
              className="text-xs h-8 gap-1.5"
              disabled={disabled || !!exporting}
              onClick={() => exportAction('navigator', 'Navigator layer', () => api.exportNavigator(sessionId!))}
            >
              <Download className="w-3.5 h-3.5" />
              {exporting === 'navigator' ? 'Exporting…' : 'Download Layer'}
            </Button>
            {hasAttackFlow && (
              <Button
                variant="outline"
                className="text-xs h-8 gap-1.5"
                disabled={disabled || !!exporting}
                title="Download as MITRE Attack Flow Builder (.afb) file"
                onClick={() => exportAction('afb', 'Attack Flow (.afb)', () => api.exportAttackFlow(sessionId!))}
              >
                <Download className="w-3.5 h-3.5" />
                {exporting === 'afb' ? 'Exporting…' : 'Attack Flow (.afb)'}
              </Button>
            )}
            {result?.detection_rules && result.detection_rules.length > 0 && (
              <Button
                variant="outline"
                className="text-xs h-8 gap-1.5"
                disabled={disabled || !!exporting}
                onClick={() => exportAction('rules', 'Detection rules', () => api.exportDetectionRules(sessionId!, tlp))}
              >
                <Download className="w-3.5 h-3.5" />
                {exporting === 'rules' ? 'Exporting…' : 'Download Rules'}
              </Button>
            )}
            <Button
              variant="cyan"
              className="text-xs h-8 gap-1.5"
              disabled={disabled || !!exporting}
              onClick={() => exportAction('zip', 'Export package (.zip)', async () => {
                const diagramB64 = await getDiagramB64();
                await api.exportZip({
                  session_id: sessionId!,
                  audience, tlp,
                  attach_iocs: attachIocs || undefined,
                  diagram_jpg_b64: diagramB64,
                  email_content_overrides: getEmailOverrides(),
                });
              })}
            >
              <Package className="w-3.5 h-3.5" />
              {exporting === 'zip' ? 'Packaging…' : 'Export All (.zip)'}
            </Button>
          </div>
        </div>
      </div>

      {/* Expanded graph view (Chain or Flow) */}
      {graphExpanded && result?.attack_chain && result.attack_chain.length > 0 && (
        <div
          className="fixed inset-0 z-40 flex items-center justify-center p-6 bg-black/80 backdrop-blur-sm"
          onClick={() => setGraphExpanded(false)}
        >
          <div
            className="bg-navy-950 border border-border rounded-lg shadow-2xl w-[92vw] h-[88vh] flex flex-col overflow-hidden"
            onClick={(e) => e.stopPropagation()}
          >
            <div className="px-4 py-2.5 border-b border-border flex items-center gap-2 flex-shrink-0">
              <Activity className="w-3.5 h-3.5 text-cyan-400" />
              <span className="text-xs font-semibold text-foreground">
                {chainViewMode === 'flow' && hasAttackFlow ? 'Attack Flow' : 'ATT&CK Chain'}
              </span>
              <span className="text-[10px] text-muted-foreground">
                {chainViewMode === 'flow' && hasAttackFlow
                  ? `${result.attack_flow!.nodes.length} nodes`
                  : `${result.attack_chain.length} techniques`} · scroll to zoom, drag to pan
              </span>
              {hasAttackFlow && (
                <div className="ml-auto flex items-center rounded-md border border-border overflow-hidden">
                  <button
                    onClick={() => setChainViewMode('chain')}
                    className={cn('px-2 py-0.5 text-[10px] transition-colors',
                      chainViewMode === 'chain' ? 'bg-cyan-500/20 text-cyan-300' : 'text-muted-foreground hover:text-foreground')}
                  >
                    Chain
                  </button>
                  <button
                    onClick={() => setChainViewMode('flow')}
                    className={cn('px-2 py-0.5 text-[10px] transition-colors border-l border-border',
                      chainViewMode === 'flow' ? 'bg-cyan-500/20 text-cyan-300' : 'text-muted-foreground hover:text-foreground')}
                  >
                    Flow
                  </button>
                </div>
              )}
              <button
                onClick={() => setGraphExpanded(false)}
                aria-label="Close expanded view"
                className={cn('p-1 rounded text-muted-foreground hover:text-foreground hover:bg-secondary/60 transition-colors', !hasAttackFlow && 'ml-auto')}
              >
                <X className="w-4 h-4" />
              </button>
            </div>
            <div className="flex-1 min-h-0">
              {chainViewMode === 'flow' && hasAttackFlow ? (
                <AttackFlowView
                  key={`flow-expanded-${chainKey}`}
                  flow={result.attack_flow!}
                  attackChain={result.attack_chain}
                  onExpand={setSelectedTechnique}
                />
              ) : (
                <AttackChainView
                  key={`chain-expanded-${chainKey}`}
                  techniques={result.attack_chain}
                  onSelectTechnique={setSelectedTechnique}
                />
              )}
            </div>
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

      {/* Threat actor assign dialog */}
      {sessionId && onActorAssigned && (
        <ThreatActorAssignDialog
          open={showActorAssign}
          onClose={() => setShowActorAssign(false)}
          sessionIds={[sessionId]}
          actors={threatActors}
          onAssigned={onActorAssigned}
          mode="assign"
        />
      )}

      {/* Re-analyze confirmation */}
      <ConfirmDialog
        open={showReanalyzeConfirm}
        title="Re-run analysis?"
        message={`This re-analyzes the stored inputs with the currently selected audience. A new result version will be created and this view will update. This uses LLM tokens.`}
        confirmLabel="Re-analyze"
        onConfirm={() => { setShowReanalyzeConfirm(false); onReanalyze?.(audience); }}
        onCancel={() => setShowReanalyzeConfirm(false)}
      />

      {/* Full-screen Email Studio */}
      {emailStudioOpen && sessionId && result && editedEmail && (
        <Suspense fallback={null}>
          <EmailStudio
            open={emailStudioOpen}
            onClose={() => setEmailStudioOpen(false)}
            sessionId={sessionId}
            result={result}
            audience={audience}
            tlp={tlp}
            email={editedEmail}
            onContentChange={setEmailField}
            onShowToast={onShowToast}
          />
        </Suspense>
      )}
    </main>
  );
}

// ── Sub-components ────────────────────────────────────────────────────────────

function StepDot({ n, active, label }: { n: number; active: boolean; label: string }) {
  return (
    <div className={cn('flex items-center gap-1.5 text-[10px]', active ? 'text-cyan-400' : 'text-muted-foreground/40')}>
      <div className={cn(
        'w-4 h-4 rounded-full border flex items-center justify-center text-[9px] font-bold flex-shrink-0',
        active ? 'border-cyan-400 bg-cyan-400/10' : 'border-muted-foreground/30'
      )}>
        {n}
      </div>
      <span className="font-medium">{label}</span>
    </div>
  );
}

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

function EmptyState({ message }: { message: string }) {
  return (
    <div className="flex items-center justify-center text-center text-muted-foreground text-xs p-8 border border-dashed border-border rounded-lg">
      {message}
    </div>
  );
}

function EmailPreview({ email, audience, tlp, sections, result }: {
  email: AnalysisResult['email_content'];
  audience: string;
  tlp: TLPLevel;
  sections: BriefSection[];
  result: AnalysisResult | null;
}) {
  return (
    <div className="rounded-lg border border-border bg-navy-950 text-xs overflow-hidden">
      <div className={cn('py-1 text-center text-[10px] font-bold tracking-widest', TLP_BAND_COLORS[tlp],
        tlp === 'CLEAR' ? 'text-gray-900' : 'text-white')}>
        TLP:{tlp}
      </div>
      <div className="px-4 py-3 bg-navy-800 border-b border-border">
        <div className="flex items-start justify-between gap-3">
          <div>
            <div className="text-[9px] text-muted-foreground uppercase tracking-wide">Subject</div>
            <div className="text-sm text-foreground font-semibold leading-tight mt-0.5">{email.subject as string}</div>
          </div>
          <div className={cn('text-[10px] px-2 py-0.5 rounded font-bold flex-shrink-0', SEVERITY_BAND[email.severity_badge as string])}>
            {email.severity_badge as string}
          </div>
        </div>
        <div className="mt-2 text-[10px] text-muted-foreground">
          FOR: {AUDIENCE_LABELS[audience as AudienceType] ?? audience}
        </div>
      </div>
      <div className="p-4 space-y-4">
        {sections.filter(s => s.enabled).map(section => {
          if (section.type === 'techniques') {
            const chain = result?.attack_chain ?? [];
            if (chain.length === 0) return null;
            return (
              <div key={section.key}>
                <div className="text-[9px] uppercase tracking-wide text-cyan-400/80 mb-2">{section.label}</div>
                <div className="rounded border border-border/60 overflow-hidden">
                  <table className="w-full text-[10px]">
                    <thead>
                      <tr className="bg-navy-800 border-b border-border/60">
                        <th className="text-left px-3 py-1.5 text-muted-foreground/60 font-medium w-24">ID</th>
                        <th className="text-left px-3 py-1.5 text-muted-foreground/60 font-medium w-40">Technique</th>
                        <th className="text-left px-3 py-1.5 text-muted-foreground/60 font-medium">Evidence</th>
                      </tr>
                    </thead>
                    <tbody>
                      {chain.map((t, i) => (
                        <tr key={i} className="border-b border-border/40 last:border-0 align-top">
                          <td className="px-3 py-1.5 font-mono text-cyan-400 whitespace-nowrap">{t.technique_id}</td>
                          <td className="px-3 py-1.5 text-foreground/80 font-medium">{t.technique_name}</td>
                          <td className="px-3 py-1.5 text-muted-foreground/70">{t.evidence}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            );
          }
          if (section.type === 'iocs') {
            const iocs = result?.iocs?.slice(0, 15) ?? [];
            if (iocs.length === 0) return null;
            return (
              <div key={section.key}>
                <div className="text-[9px] uppercase tracking-wide text-cyan-400/80 mb-2">{section.label} ({iocs.length})</div>
                <div className="rounded border border-border/60 overflow-hidden">
                  <table className="w-full text-[10px]">
                    <thead>
                      <tr className="bg-navy-800 border-b border-border/60">
                        <th className="text-left px-3 py-1.5 text-muted-foreground/60 font-medium w-20">Type</th>
                        <th className="text-left px-3 py-1.5 text-muted-foreground/60 font-medium w-64">Value</th>
                        <th className="text-left px-3 py-1.5 text-muted-foreground/60 font-medium">Context</th>
                      </tr>
                    </thead>
                    <tbody>
                      {iocs.map((ioc, i) => (
                        <tr key={i} className="border-b border-border/40 last:border-0">
                          <td className="px-3 py-1.5 font-mono font-semibold text-orange-400 uppercase">{ioc.type}</td>
                          <td className="px-3 py-1.5 font-mono text-foreground/80 max-w-[240px] truncate" title={ioc.value}>{ioc.value}</td>
                          <td className="px-3 py-1.5 text-muted-foreground/60 truncate" title={ioc.context}>{ioc.context}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            );
          }
          const content = (email[section.key] as string) ?? '';
          if (!content) return null;
          return <EmailSection key={section.key} title={section.label} content={content} />;
        })}
      </div>
    </div>
  );
}

function EmailSection({ title, content }: { title: string; content: string }) {
  return (
    <div>
      <div className="text-[9px] uppercase tracking-wide text-cyan-400/80 mb-1">{title}</div>
      <div className="snr-email-section text-foreground/80 leading-relaxed text-xs">
        <ReactMarkdown>{content}</ReactMarkdown>
      </div>
    </div>
  );
}

function EmailEditor({
  email, onChange, audience, tlp, sections,
}: {
  email: EmailContent;
  onChange: (key: string, value: string) => void;
  audience: string;
  tlp: TLPLevel;
  sections: BriefSection[];
}) {
  const EDITOR_TLP_BAND: Record<string, string> = {
    CLEAR: 'bg-gray-200 text-gray-900',
    GREEN: 'bg-green-600 text-white',
    AMBER: 'bg-yellow-500 text-white',
    'AMBER+STRICT': 'bg-orange-500 text-white',
    RED: 'bg-red-600 text-white',
  };
  const hasAutoSections = sections.some(s => s.enabled && AUTO_TYPES.has(s.type));
  return (
    <div className="rounded-lg border border-cyan-500/30 bg-navy-950 text-xs overflow-hidden">
      <div className={cn('py-1 text-center text-[10px] font-bold tracking-widest', EDITOR_TLP_BAND[tlp])}>
        TLP:{tlp}
      </div>
      <div className="px-3 py-2 bg-navy-800 border-b border-border text-[9px] text-muted-foreground flex items-center justify-between">
        <span className="text-cyan-400 font-medium">✏ Edit Mode — changes apply to exported .eml and .zip</span>
        <span>FOR: {AUDIENCE_LABELS[audience as AudienceType] ?? audience}</span>
      </div>
      <div className="p-4 space-y-3">
        <EditField label="Subject">
          <input type="text" value={email.subject as string ?? ''} onChange={(e) => onChange('subject', e.target.value)}
            className="w-full bg-secondary/30 border border-border rounded px-2 py-1 text-xs text-foreground focus:outline-none focus:ring-1 focus:ring-cyan-500/50" />
        </EditField>
        {sections.filter(s => s.enabled && !AUTO_TYPES.has(s.type)).map(section => (
          <EditField key={section.key} label={section.label}>
            <RichTextEditor
              value={(email[section.key] as string) ?? ''}
              onChange={(md) => onChange(section.key, md)}
              minHeight={section.type === 'text' ? 64 : 110}
            />
          </EditField>
        ))}
        {hasAutoSections && (
          <p className="text-[9px] text-muted-foreground/60 pb-1">
            Auto-populated sections (techniques and IOCs) are generated from the analysis and cannot be edited here.
          </p>
        )}
      </div>
    </div>
  );
}

function EditField({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="space-y-1">
      <div className="text-[9px] uppercase tracking-wide text-cyan-400/70 font-medium">{label}</div>
      {children}
    </div>
  );
}

function StixPreview({ result }: { result: AnalysisResult }) {
  return (
    <div className="rounded-lg border border-border bg-navy-950 p-4 space-y-2 text-xs">
      <div className="text-[9px] text-muted-foreground uppercase tracking-wide mb-3">Bundle Contents</div>
      <StixRow label="Attack Patterns" count={result.attack_chain.length} color="text-cyan-400" />
      <StixRow label="Indicators (IOCs)" count={result.iocs.length} color="text-orange-400" />
      <StixRow label="Affected Assets" count={result.affected_assets.length} color="text-yellow-400" />
      {result.threat_actor?.name && (
        <StixRow label="Threat Actor" count={1} color="text-red-400" extra={result.threat_actor.name} />
      )}
      <div className="mt-3 pt-3 border-t border-border">
        <div className="text-[9px] text-muted-foreground">STIX 2.1 compliant · Will be validated on download</div>
      </div>
    </div>
  );
}

function StixRow({ label, count, color, extra }: { label: string; count: number; color: string; extra?: string }) {
  return (
    <div className="flex items-center justify-between">
      <span className="text-muted-foreground">{label}</span>
      <div className="flex items-center gap-2">
        {extra && <span className="text-muted-foreground/60 text-[10px]">{extra}</span>}
        <span className={cn('font-mono font-semibold', color)}>{count}</span>
      </div>
    </div>
  );
}

function NavigatorPreview({ result }: { result: AnalysisResult }) {
  const byTactic: Record<string, number> = {};
  for (const t of result.attack_chain) {
    byTactic[t.tactic] = (byTactic[t.tactic] ?? 0) + 1;
  }
  return (
    <div className="rounded-lg border border-border bg-navy-950 p-4 space-y-2 text-xs">
      <div className="text-[9px] text-muted-foreground uppercase tracking-wide mb-1">Layer Preview</div>
      <div className="text-muted-foreground text-[10px] mb-3">
        {result.attack_chain.length} techniques across {Object.keys(byTactic).length} tactics
      </div>
      <div className="space-y-1">
        {Object.entries(byTactic).map(([tactic, count]) => (
          <div key={tactic} className="flex items-center gap-2">
            <div className="flex-1 text-[10px] text-foreground/70">{tactic}</div>
            <div className="text-[10px] font-mono text-cyan-400">{count} technique{count !== 1 ? 's' : ''}</div>
          </div>
        ))}
      </div>
      <div className="mt-3 pt-3 border-t border-border text-[9px] text-muted-foreground">
        Color-coded by confidence · Compatible with ATT&CK Navigator v4.9
      </div>
    </div>
  );
}
