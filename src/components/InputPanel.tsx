import { useState, useRef } from 'react';
import { Upload, X, Eye, EyeOff, Terminal, AlignLeft, HelpCircle, ChevronDown, ChevronUp, FileText } from 'lucide-react';
import { Button } from './ui/button';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from './ui/select';
import { Tooltip, TooltipContent, TooltipTrigger } from './ui/tooltip';
import { cn } from '@/lib/utils';
import type { AudienceType, CustomAudience } from '@/types';
import { AUDIENCE_LABELS } from '@/types';

interface Props {
  onAnalyze: (params: {
    siemInput: string;
    textInput: string;
    logFile: File | null;
    audience: AudienceType | string;
    redactedStrings: string[];
  }) => void;
  isAnalyzing: boolean;
  sessionName: string;
  onSessionNameChange: (name: string) => void;
  customAudiences?: CustomAudience[];
}

const BUILTIN_HELP: Record<string, string> = {
  purple_team: 'Full TTP chain, detection gap analysis, and emulation recommendations.',
  soc: 'Containment steps, IOC watchlists, and triage priority. Action-first.',
  red_team: 'Adversary behavior patterns, C2 infrastructure, and exploitation paths.',
  dr: 'Detection gaps, Sigma/YARA recommendations, and log source guidance.',
  general: 'Plain-language threat narrative and business impact summary.',
};

function HelpTip({ text }: { text: string }) {
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <span className="cursor-help text-muted-foreground/50 hover:text-muted-foreground transition-colors">
          <HelpCircle className="w-3 h-3 inline" />
        </span>
      </TooltipTrigger>
      <TooltipContent className="max-w-xs text-xs">{text}</TooltipContent>
    </Tooltip>
  );
}

function SectionHeader({
  icon,
  label,
  hint,
  collapsed,
  onToggle,
  badge,
}: {
  icon: React.ReactNode;
  label: string;
  hint: string;
  collapsed: boolean;
  onToggle: () => void;
  badge?: string;
}) {
  return (
    <button
      type="button"
      onClick={onToggle}
      className="w-full flex items-center gap-2 text-left group"
    >
      <span className="text-cyan-400/70">{icon}</span>
      <span className="text-[10px] font-semibold text-muted-foreground uppercase tracking-wide group-hover:text-foreground transition-colors">
        {label}
      </span>
      {badge && (
        <span className="text-[9px] bg-cyan-500/20 text-cyan-400 px-1.5 py-0.5 rounded-full">
          {badge}
        </span>
      )}
      <span className="ml-auto text-muted-foreground/40 group-hover:text-muted-foreground transition-colors">
        {collapsed
          ? <ChevronDown className="w-3 h-3" />
          : <ChevronUp className="w-3 h-3" />}
      </span>
      <HelpTip text={hint} />
    </button>
  );
}

export default function InputPanel({
  onAnalyze,
  isAnalyzing,
  sessionName,
  onSessionNameChange,
  customAudiences = [],
}: Props) {
  const [siemInput, setSiemInput] = useState('');
  const [textInput, setTextInput] = useState('');
  const [logFile, setLogFile] = useState<File | null>(null);
  const [audience, setAudience] = useState<string>('soc');
  const [redactStr, setRedactStr] = useState('');
  const [redactedList, setRedactedList] = useState<string[]>([]);
  const [showRedact, setShowRedact] = useState(false);
  const [siemCollapsed, setSiemCollapsed] = useState(false);
  const [textCollapsed, setTextCollapsed] = useState(false);
  const fileRef = useRef<HTMLInputElement>(null);

  // Merge built-in + custom audiences for the dropdown
  const builtinEntries = Object.entries(AUDIENCE_LABELS) as [AudienceType, string][];
  const customEntries = customAudiences.map((a) => ({ id: a.id, label: a.label }));

  const audienceHelp =
    BUILTIN_HELP[audience] ??
    customAudiences.find((a) => a.id === audience)?.prompt.slice(0, 100) ??
    'Custom audience prompt';

  const addRedact = () => {
    const trimmed = redactStr.trim();
    if (trimmed && !redactedList.includes(trimmed)) {
      setRedactedList([...redactedList, trimmed]);
    }
    setRedactStr('');
  };

  const removeRedact = (s: string) => setRedactedList(redactedList.filter((r) => r !== s));

  const canAnalyze = (siemInput.trim() || textInput.trim() || logFile) && !isAnalyzing;

  const handleAnalyze = () => {
    if (!canAnalyze) return;
    onAnalyze({ siemInput, textInput, logFile, audience, redactedStrings: redactedList });
  };

  const inputSize = siemInput.length + textInput.length + (logFile?.size ?? 0);

  return (
    <div className="flex flex-col gap-4 h-full">

      {/* Session name */}
      <div className="space-y-1.5">
        <div className="flex items-center gap-1 text-[10px] font-semibold text-muted-foreground uppercase tracking-wide">
          Session Name
          <HelpTip text="A label for this analysis session. Use the incident ID or a brief description." />
        </div>
        <input
          value={sessionName}
          onChange={(e) => onSessionNameChange(e.target.value)}
          placeholder="e.g. Cobalt Strike beaconing — PROD-WEB-01 — 2026-03-07"
          className="w-full bg-secondary/50 border border-border rounded-md px-3 py-1.5 text-sm text-foreground placeholder:text-muted-foreground/50 focus:outline-none focus:ring-1 focus:ring-cyan-500"
        />
      </div>

      {/* Audience */}
      <div className="space-y-1.5">
        <div className="flex items-center gap-1 text-[10px] font-semibold text-muted-foreground uppercase tracking-wide">
          Target Audience
          {audience && (
            <span className="ml-1 text-cyan-400/70 normal-case tracking-normal font-normal truncate max-w-[220px]">
              — {audienceHelp}
            </span>
          )}
        </div>
        <Select value={audience} onValueChange={setAudience}>
          <SelectTrigger className="w-full bg-secondary/50 border-border text-sm h-9">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            {builtinEntries.map(([k, v]) => (
              <SelectItem key={k} value={k}>
                <div className="flex flex-col">
                  <span>{v}</span>
                  <span className="text-[10px] text-muted-foreground">{BUILTIN_HELP[k]}</span>
                </div>
              </SelectItem>
            ))}
            {customEntries.length > 0 && (
              <>
                <div className="px-2 py-1 text-[10px] text-muted-foreground/50 uppercase tracking-widest">Custom</div>
                {customEntries.map((a) => (
                  <SelectItem key={a.id} value={a.id}>
                    {a.label}
                  </SelectItem>
                ))}
              </>
            )}
          </SelectContent>
        </Select>
      </div>

      {/* ── Intelligence Input — unified single-pane ── */}
      <div className="flex-1 flex flex-col gap-3 min-h-0 border border-border/60 rounded-lg p-3 bg-secondary/10">
        <div className="text-[10px] font-semibold text-muted-foreground uppercase tracking-wide">
          Intelligence Input
          <span className="ml-1.5 text-muted-foreground/40 normal-case tracking-normal font-normal">
            — combine any or all sources
          </span>
        </div>

        {/* SIEM / Alert Data */}
        <div className="flex flex-col gap-1.5">
          <SectionHeader
            icon={<Terminal className="w-3 h-3" />}
            label="SIEM / Alert Data"
            hint="Paste raw alert output from Splunk, Sentinel, QRadar, Elastic SIEM, etc. JSON, key-value, or plain text — malformed payloads tolerated."
            collapsed={siemCollapsed}
            onToggle={() => setSiemCollapsed(!siemCollapsed)}
            badge={siemInput.trim() ? `${siemInput.length.toLocaleString()}c` : undefined}
          />
          {!siemCollapsed && (
            <textarea
              value={siemInput}
              onChange={(e) => setSiemInput(e.target.value)}
              placeholder={'{\n  "alert_name": "Suspicious PowerShell execution",\n  "host": "PROD-WEB-01",\n  "cmdline": "powershell.exe -enc JABzAD..."\n}'}
              className="min-h-[100px] bg-navy-950 border border-border rounded-md p-2.5 text-xs font-mono text-foreground placeholder:text-muted-foreground/40 resize-y focus:outline-none focus:ring-1 focus:ring-cyan-500"
              spellCheck={false}
            />
          )}
        </div>

        {/* Log File */}
        <div className="flex flex-col gap-1.5">
          <div className="flex items-center gap-2 text-[10px] font-semibold text-muted-foreground uppercase tracking-wide">
            <FileText className="w-3 h-3 text-cyan-400/70" />
            Log File
            <HelpTip text="Upload a log bundle from your EDR, firewall, or SIEM. Accepts .csv, .txt, .log, .json up to 10 MB." />
            {logFile && (
              <span className="ml-1 text-[9px] bg-cyan-500/20 text-cyan-400 px-1.5 py-0.5 rounded-full">
                {logFile.name}
              </span>
            )}
          </div>
          <div
            className={cn(
              'flex items-center justify-center gap-2 border-2 border-dashed rounded-md cursor-pointer transition-colors py-3',
              logFile
                ? 'border-cyan-500/40 bg-cyan-500/5 text-cyan-400'
                : 'border-border hover:border-cyan-500/30 text-muted-foreground/50'
            )}
            onClick={() => fileRef.current?.click()}
            onDragOver={(e) => e.preventDefault()}
            onDrop={(e) => {
              e.preventDefault();
              const file = e.dataTransfer.files[0];
              if (file) setLogFile(file);
            }}
          >
            {logFile ? (
              <>
                <FileText className="w-3.5 h-3.5" />
                <span className="text-xs truncate max-w-[200px]">{logFile.name}</span>
                <span className="text-[10px] text-muted-foreground">({(logFile.size / 1024).toFixed(1)} KB)</span>
                <button
                  onClick={(e) => { e.stopPropagation(); setLogFile(null); }}
                  className="text-muted-foreground hover:text-red-400 transition-colors ml-1"
                  aria-label="Remove file"
                >
                  <X className="w-3 h-3" />
                </button>
              </>
            ) : (
              <>
                <Upload className="w-3.5 h-3.5" />
                <span className="text-xs">Drop file or click to browse</span>
                <span className="text-[10px] text-muted-foreground/50">.csv .txt .log .json · max 10 MB</span>
              </>
            )}
          </div>
          <input
            ref={fileRef}
            type="file"
            accept=".csv,.txt,.log,.json"
            className="hidden"
            onChange={(e) => setLogFile(e.target.files?.[0] ?? null)}
          />
        </div>

        {/* Freeform Notes */}
        <div className="flex flex-col gap-1.5 flex-1 min-h-0">
          <SectionHeader
            icon={<AlignLeft className="w-3 h-3" />}
            label="Freeform Notes & Intel"
            hint="Paste unstructured intel — threat report excerpts, email body text, analyst notes, CTI feed entries, or any incident description."
            collapsed={textCollapsed}
            onToggle={() => setTextCollapsed(!textCollapsed)}
            badge={textInput.trim() ? `${textInput.length.toLocaleString()}c` : undefined}
          />
          {!textCollapsed && (
            <textarea
              value={textInput}
              onChange={(e) => setTextInput(e.target.value)}
              placeholder={"Paste analyst notes, threat intel report excerpts, or email body text here.\n\nExamples:\n• 'Lateral movement from PROD-WEB-01 to DC-01 via PsExec at 14:22 UTC'\n• CTI feed report body\n• Threat hunting notes"}
              className="flex-1 min-h-[100px] bg-navy-950 border border-border rounded-md p-2.5 text-sm text-foreground placeholder:text-muted-foreground/40 resize-y focus:outline-none focus:ring-1 focus:ring-cyan-500"
            />
          )}
        </div>
      </div>

      {/* Redaction panel */}
      <div className="border border-border/50 rounded-lg overflow-hidden">
        <button
          className="w-full flex items-center justify-between px-3 py-2 text-xs text-muted-foreground hover:bg-secondary/30 transition-colors"
          onClick={() => setShowRedact(!showRedact)}
          aria-expanded={showRedact}
        >
          <span className="flex items-center gap-1.5">
            {showRedact ? <EyeOff className="w-3 h-3" /> : <Eye className="w-3 h-3" />}
            Redact Sensitive Strings
            {redactedList.length > 0 && (
              <span className="bg-red-900/40 text-red-300 text-[9px] px-1.5 py-0.5 rounded-full ml-1">
                {redactedList.length} active
              </span>
            )}
          </span>
          <HelpTip text="Enter hostnames, usernames, or IP addresses to mask before the API call. Redacted values appear as [REDACTED] in all outputs." />
        </button>

        {showRedact && (
          <div className="px-3 pb-3 pt-1 bg-secondary/10 space-y-2">
            <p className="text-[10px] text-muted-foreground">
              Values appear as <code className="text-red-300">[REDACTED]</code> in all outputs.
            </p>
            <div className="flex gap-2">
              <input
                value={redactStr}
                onChange={(e) => setRedactStr(e.target.value)}
                onKeyDown={(e) => e.key === 'Enter' && addRedact()}
                placeholder="e.g. PROD-WEB-01, jsmith, 192.168.1.0/24"
                className="flex-1 bg-secondary/50 border border-border rounded px-2 py-1 text-xs focus:outline-none focus:ring-1 focus:ring-cyan-500"
              />
              <Button size="sm" variant="outline" onClick={addRedact} className="text-xs h-7">Add</Button>
            </div>
            {redactedList.length > 0 && (
              <div className="flex flex-wrap gap-1">
                {redactedList.map((s) => (
                  <span key={s} className="bg-red-900/30 border border-red-700/40 text-red-300 text-[10px] px-2 py-0.5 rounded-full flex items-center gap-1">
                    {s}
                    <button onClick={() => removeRedact(s)} className="hover:text-red-100 ml-0.5" aria-label={`Remove ${s}`}>
                      <X className="w-2.5 h-2.5" />
                    </button>
                  </span>
                ))}
              </div>
            )}
          </div>
        )}
      </div>

      {/* Footer */}
      <div className="flex items-center justify-between">
        <div className="text-xs text-muted-foreground">
          {inputSize > 0 ? (
            <span className={cn(inputSize > 8000 ? 'text-yellow-400' : '')}>
              ~{(inputSize / 1024).toFixed(1)} KB input
              {inputSize > 8000 && ' · Large — analysis may take up to 90s'}
            </span>
          ) : (
            <span className="text-muted-foreground/50">Paste data above to begin</span>
          )}
        </div>
        <Button
          variant="cyan"
          onClick={handleAnalyze}
          disabled={!canAnalyze}
          className="h-9 px-6 font-semibold"
          aria-label="Run intelligence analysis"
        >
          {isAnalyzing ? (
            <>
              <span className="w-3 h-3 border-2 border-navy-950/30 border-t-navy-950 rounded-full animate-spin" />
              Analyzing…
            </>
          ) : (
            '⚡ Analyze'
          )}
        </Button>
      </div>
    </div>
  );
}
