import { useState, useEffect, useCallback } from 'react';
import { X, PenLine, Save, Loader2, FileText, Crosshair, Bug, ShieldCheck, Users, AlignLeft, Plus, Trash2, Sparkles } from 'lucide-react';
import { cn } from '@/lib/utils';
import * as api from '@/lib/api';
import { parseSections } from '@/lib/sections';
import RichTextEditor from './RichTextEditor';
import { Button } from './ui/button';
import type { AnalysisResult, AttackTechnique, IOC, DetectionRule, AffectedAsset, BriefSection } from '@/types';

// MITRE enterprise tactics, in kill-chain order.
const TACTICS = [
  'Reconnaissance', 'Resource Development', 'Initial Access', 'Execution', 'Persistence',
  'Privilege Escalation', 'Defense Evasion', 'Credential Access', 'Discovery',
  'Lateral Movement', 'Collection', 'Command and Control', 'Exfiltration', 'Impact',
];
const IOC_TYPES: IOC['type'][] = ['ipv4', 'ipv6', 'domain', 'url', 'md5', 'sha1', 'sha256', 'email', 'filename', 'registry', 'user_agent'];
const RULE_TYPES: DetectionRule['rule_type'][] = ['sigma', 'yara', 'suricata'];
const CONFIDENCE = ['High', 'Medium', 'Low'] as const;
const COVERAGE: AttackTechnique['detection_coverage'][] = ['Likely Detected', 'Detection Gap', 'Unknown'];
const SEVERITY = ['Critical', 'High', 'Medium', 'Low', 'Informational'] as const;

/** A blank result to seed a new authored report. */
export function blankResult(): AnalysisResult {
  return {
    incident_summary: { title: '', severity: 'Medium', confidence: 'Medium', description: '', analyst_notes: '' },
    attack_chain: [],
    iocs: [],
    detection_rules: [],
    threat_actor: { name: null, aliases: [], motivation: null, attribution_confidence: null, intrusion_set: null, campaign_name: null, malware_families: [] },
    affected_assets: [],
    email_content: { subject: '', severity_badge: 'Medium' },
  };
}

type Tab = 'summary' | 'attack' | 'iocs' | 'rules' | 'context' | 'narrative';

interface Props {
  open: boolean;
  onClose: () => void;
  sessionId: string;
  initial: AnalysisResult;
  expectedVersion?: number;
  onSaved: (version: number) => void;
  onShowToast?: (message: string, type?: 'success' | 'error' | 'info') => void;
  onOpenEmailStudio?: () => void;
}

export default function Workbench({ open, onClose, sessionId, initial, expectedVersion, onSaved, onShowToast, onOpenEmailStudio }: Props) {
  const [tab, setTab] = useState<Tab>('summary');
  const [draft, setDraft] = useState<AnalysisResult>(initial);
  const [sections, setSections] = useState<BriefSection[]>([]);
  const [saving, setSaving] = useState(false);

  // Reseed when opened with a (possibly different) session/result.
  useEffect(() => { if (open) { setDraft(initial); setTab('summary'); } }, [open, initial]);

  // Narrative section fields come from the team's brief-section config (same as Email Studio).
  useEffect(() => {
    if (!open) return;
    api.fetchSettings()
      .then((s) => setSections(parseSections(s.report_sections ?? '')))
      .catch(() => setSections([]));
  }, [open]);

  // ── typed updaters ─────────────────────────────────────────────────────────
  const setSummary = (k: keyof AnalysisResult['incident_summary'], v: string) =>
    setDraft((d) => ({ ...d, incident_summary: { ...d.incident_summary, [k]: v } }));
  const setActor = (k: keyof AnalysisResult['threat_actor'], v: string) =>
    setDraft((d) => ({ ...d, threat_actor: { ...d.threat_actor, [k]: v || null } }));
  const setEmail = (k: string, v: string) =>
    setDraft((d) => ({ ...d, email_content: { ...d.email_content, [k]: v } }));

  function mutList<K extends 'attack_chain' | 'iocs' | 'detection_rules' | 'affected_assets'>(
    key: K, fn: (arr: AnalysisResult[K]) => AnalysisResult[K],
  ) {
    setDraft((d) => ({ ...d, [key]: fn(d[key]) }));
  }
  const updateAt = <T,>(arr: T[], i: number, patch: Partial<T>): T[] => arr.map((x, j) => (j === i ? { ...x, ...patch } : x));
  const removeAt = <T,>(arr: T[], i: number): T[] => arr.filter((_, j) => j !== i);

  const addTechnique = () => mutList('attack_chain', (a) => [...a, {
    technique_id: '', technique_name: '', tactic: TACTICS[2], tactic_id: '', sub_technique_id: null,
    sub_technique_name: null, evidence: '', confidence: 'Medium', detection_coverage: 'Unknown',
    detection_recommendation: '', order: a.length,
  }]);
  const addIoc = () => mutList('iocs', (a) => [...a, { type: 'ipv4', value: '', context: '', confidence: 'Medium' }]);
  const addRule = () => mutList('detection_rules', (a) => [...a, {
    rule_type: 'sigma', rule_name: '', rule_content: '', description: '', source: 'extracted', confidence: 'Medium', related_technique: null,
  }]);
  const addAsset = () => mutList('affected_assets', (a) => [...a, { hostname: '', ip: '', role: '', compromise_confidence: 'Medium' }]);

  const handleSave = useCallback(async () => {
    if (!draft.incident_summary.title.trim()) { onShowToast?.('Add an incident title first', 'error'); setTab('summary'); return; }
    setSaving(true);
    try {
      // Keep the email severity badge in sync with the assessed severity.
      const toSave: AnalysisResult = {
        ...draft,
        email_content: { ...draft.email_content, severity_badge: (draft.email_content.severity_badge as string) || draft.incident_summary.severity },
      };
      const version = await api.saveSessionResult(sessionId, toSave, expectedVersion);
      onShowToast?.('Report saved', 'success');
      onSaved(version);
    } catch (e) {
      onShowToast?.(e instanceof Error ? e.message : 'Save failed', 'error');
    } finally {
      setSaving(false);
    }
  }, [draft, sessionId, expectedVersion, onSaved, onShowToast]);

  if (!open) return null;

  const textSections = sections.filter((s) => s.type === 'text' || s.type === 'bullets' || s.type === 'numbered');

  return (
    <div className="fixed inset-0 z-50 flex flex-col bg-navy-950">
      {/* Header */}
      <div className="flex items-center justify-between px-4 py-2.5 border-b border-border flex-shrink-0">
        <div className="flex items-center gap-2">
          <PenLine className="w-4 h-4 text-cyan-400" />
          <h2 className="text-sm font-semibold text-foreground">Analyst Workbench</h2>
          <span className="text-[11px] text-muted-foreground">Original research — you author the intelligence; every export uses it.</span>
        </div>
        <div className="flex items-center gap-2">
          {onOpenEmailStudio && (
            <Button variant="outline" size="sm" className="text-xs h-7 gap-1.5" onClick={onOpenEmailStudio} title="Design the email narrative & branding">
              <Sparkles className="w-3.5 h-3.5" /> Email Studio
            </Button>
          )}
          <Button variant="cyan" size="sm" className="text-xs h-7 gap-1.5" onClick={handleSave} disabled={saving}>
            {saving ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Save className="w-3.5 h-3.5" />} Save report
          </Button>
          <button onClick={onClose} className="text-muted-foreground hover:text-foreground transition-colors ml-1" aria-label="Close">
            <X className="w-4 h-4" />
          </button>
        </div>
      </div>

      {/* Tabs */}
      <div className="grid grid-cols-6 border-b border-border flex-shrink-0">
        {([
          ['summary', 'Summary', FileText],
          ['attack', 'ATT&CK', Crosshair],
          ['iocs', 'IOCs', Bug],
          ['rules', 'Detections', ShieldCheck],
          ['context', 'Actor & Assets', Users],
          ['narrative', 'Narrative', AlignLeft],
        ] as const).map(([id, label, Icon]) => (
          <button key={id} onClick={() => setTab(id)}
            className={cn('flex items-center justify-center gap-1 py-2 text-[11px] transition-colors',
              tab === id ? 'text-cyan-300 border-b-2 border-cyan-500 bg-cyan-500/5' : 'text-muted-foreground hover:text-foreground')}>
            <Icon className="w-3 h-3" />{label}
          </button>
        ))}
      </div>

      <div className="flex-1 overflow-y-auto p-4 max-w-5xl w-full mx-auto space-y-4">
        {tab === 'summary' && (
          <>
            <Field label="Incident Title *">
              <TextInput value={draft.incident_summary.title} onChange={(v) => setSummary('title', v)} placeholder="e.g. TinyRCT backdoor targeting SEA energy sector" />
            </Field>
            <div className="grid grid-cols-2 gap-3">
              <Field label="Severity">
                <Select value={draft.incident_summary.severity} onChange={(v) => setSummary('severity', v)} options={SEVERITY as unknown as string[]} />
              </Field>
              <Field label="Confidence">
                <Select value={draft.incident_summary.confidence} onChange={(v) => setSummary('confidence', v)} options={CONFIDENCE as unknown as string[]} />
              </Field>
            </div>
            <Field label="Description">
              <TextArea value={draft.incident_summary.description} onChange={(v) => setSummary('description', v)} rows={4} placeholder="What happened and why it matters." />
            </Field>
            <Field label="Analyst Notes" hint="Add Reference:/Source: lines or URLs here — they populate the References section.">
              <TextArea value={draft.incident_summary.analyst_notes} onChange={(v) => setSummary('analyst_notes', v)} rows={3} placeholder={'Internal notes.\nReference: https://your-source…'} />
            </Field>
          </>
        )}

        {tab === 'attack' && (
          <Section title="ATT&CK Techniques" onAdd={addTechnique} addLabel="Add technique" empty={draft.attack_chain.length === 0}>
            {draft.attack_chain.map((t, i) => (
              <Card key={i} onRemove={() => mutList('attack_chain', (a) => removeAt(a, i))}>
                <div className="grid grid-cols-4 gap-2">
                  <LabeledInput label="Technique ID" value={t.technique_id} onChange={(v) => mutList('attack_chain', (a) => updateAt(a, i, { technique_id: v }))} placeholder="T1059" />
                  <div className="col-span-2"><LabeledInput label="Technique Name" value={t.technique_name} onChange={(v) => mutList('attack_chain', (a) => updateAt(a, i, { technique_name: v }))} placeholder="Command and Scripting Interpreter" /></div>
                  <LabeledSelect label="Tactic" value={t.tactic} onChange={(v) => mutList('attack_chain', (a) => updateAt(a, i, { tactic: v }))} options={TACTICS} />
                  <LabeledInput label="Sub-technique ID" value={t.sub_technique_id ?? ''} onChange={(v) => mutList('attack_chain', (a) => updateAt(a, i, { sub_technique_id: v || null }))} placeholder="T1059.001" />
                  <div className="col-span-3"><LabeledInput label="Sub-technique Name" value={t.sub_technique_name ?? ''} onChange={(v) => mutList('attack_chain', (a) => updateAt(a, i, { sub_technique_name: v || null }))} placeholder="PowerShell" /></div>
                  <div className="col-span-4"><LabeledInput label="Evidence" value={t.evidence} onChange={(v) => mutList('attack_chain', (a) => updateAt(a, i, { evidence: v }))} placeholder="How this technique was applied in the incident." /></div>
                  <LabeledSelect label="Confidence" value={t.confidence} onChange={(v) => mutList('attack_chain', (a) => updateAt(a, i, { confidence: v as AttackTechnique['confidence'] }))} options={CONFIDENCE as unknown as string[]} />
                  <div className="col-span-1"><LabeledSelect label="Coverage" value={t.detection_coverage} onChange={(v) => mutList('attack_chain', (a) => updateAt(a, i, { detection_coverage: v as AttackTechnique['detection_coverage'] }))} options={COVERAGE} /></div>
                  <div className="col-span-2"><LabeledInput label="Detection Recommendation" value={t.detection_recommendation} onChange={(v) => mutList('attack_chain', (a) => updateAt(a, i, { detection_recommendation: v }))} placeholder="Sigma/log source suggestion." /></div>
                </div>
              </Card>
            ))}
          </Section>
        )}

        {tab === 'iocs' && (
          <Section title="Indicators of Compromise" onAdd={addIoc} addLabel="Add IOC" empty={draft.iocs.length === 0}>
            {draft.iocs.map((ioc, i) => (
              <Card key={i} onRemove={() => mutList('iocs', (a) => removeAt(a, i))}>
                <div className="grid grid-cols-6 gap-2">
                  <LabeledSelect label="Type" value={ioc.type} onChange={(v) => mutList('iocs', (a) => updateAt(a, i, { type: v as IOC['type'] }))} options={IOC_TYPES} />
                  <div className="col-span-3"><LabeledInput label="Value" value={ioc.value} onChange={(v) => mutList('iocs', (a) => updateAt(a, i, { value: v }))} placeholder="1.2.3.4 / evil.com / hash…" mono /></div>
                  <div className="col-span-1"><LabeledSelect label="Confidence" value={ioc.confidence} onChange={(v) => mutList('iocs', (a) => updateAt(a, i, { confidence: v as IOC['confidence'] }))} options={CONFIDENCE as unknown as string[]} /></div>
                  <div className="col-span-6"><LabeledInput label="Context" value={ioc.context} onChange={(v) => mutList('iocs', (a) => updateAt(a, i, { context: v }))} placeholder="Where/how observed." /></div>
                </div>
              </Card>
            ))}
          </Section>
        )}

        {tab === 'rules' && (
          <Section title="Detection Rules" onAdd={addRule} addLabel="Add rule" empty={draft.detection_rules.length === 0}>
            {draft.detection_rules.map((r, i) => (
              <Card key={i} onRemove={() => mutList('detection_rules', (a) => removeAt(a, i))}>
                <div className="grid grid-cols-4 gap-2">
                  <LabeledSelect label="Type" value={r.rule_type} onChange={(v) => mutList('detection_rules', (a) => updateAt(a, i, { rule_type: v as DetectionRule['rule_type'] }))} options={RULE_TYPES} />
                  <div className="col-span-2"><LabeledInput label="Rule Name" value={r.rule_name} onChange={(v) => mutList('detection_rules', (a) => updateAt(a, i, { rule_name: v }))} /></div>
                  <LabeledInput label="Related Technique" value={r.related_technique ?? ''} onChange={(v) => mutList('detection_rules', (a) => updateAt(a, i, { related_technique: v || null }))} placeholder="T1059.001" />
                  <div className="col-span-3"><LabeledInput label="Description" value={r.description} onChange={(v) => mutList('detection_rules', (a) => updateAt(a, i, { description: v }))} /></div>
                  <LabeledSelect label="Confidence" value={r.confidence} onChange={(v) => mutList('detection_rules', (a) => updateAt(a, i, { confidence: v as DetectionRule['confidence'] }))} options={CONFIDENCE as unknown as string[]} />
                  <div className="col-span-4">
                    <label className="text-[10px] uppercase tracking-wide text-cyan-400/70 font-medium">Rule Content</label>
                    <textarea value={r.rule_content} onChange={(e) => mutList('detection_rules', (a) => updateAt(a, i, { rule_content: e.target.value }))} rows={6}
                      className="w-full mt-1 bg-secondary/40 border border-border rounded px-2 py-1.5 text-xs font-mono text-foreground resize-y focus:outline-none focus:ring-1 focus:ring-cyan-500/50" placeholder="title: …" />
                  </div>
                </div>
              </Card>
            ))}
          </Section>
        )}

        {tab === 'context' && (
          <>
            <SectionLabel>Threat Actor</SectionLabel>
            <div className="grid grid-cols-2 gap-3">
              <Field label="Name"><TextInput value={draft.threat_actor.name ?? ''} onChange={(v) => setActor('name', v)} placeholder="e.g. CL-STA-1062 (leave blank if unknown)" /></Field>
              <Field label="Aliases (comma-sep)"><TextInput value={draft.threat_actor.aliases.join(', ')} onChange={(v) => setDraft((d) => ({ ...d, threat_actor: { ...d.threat_actor, aliases: v.split(',').map((x) => x.trim()).filter(Boolean) } }))} /></Field>
              <Field label="Motivation"><TextInput value={draft.threat_actor.motivation ?? ''} onChange={(v) => setActor('motivation', v)} placeholder="Espionage / financial…" /></Field>
              <Field label="Attribution Confidence"><TextInput value={draft.threat_actor.attribution_confidence ?? ''} onChange={(v) => setActor('attribution_confidence', v)} placeholder="High / Medium / Low" /></Field>
              <Field label="Malware Families (comma-sep)"><TextInput value={(draft.threat_actor.malware_families ?? []).join(', ')} onChange={(v) => setDraft((d) => ({ ...d, threat_actor: { ...d.threat_actor, malware_families: v.split(',').map((x) => x.trim()).filter(Boolean) } }))} /></Field>
            </div>

            <div className="pt-2">
              <Section title="Affected Assets" onAdd={addAsset} addLabel="Add asset" empty={draft.affected_assets.length === 0}>
                {draft.affected_assets.map((a, i) => (
                  <Card key={i} onRemove={() => mutList('affected_assets', (arr) => removeAt(arr, i))}>
                    <div className="grid grid-cols-4 gap-2">
                      <LabeledInput label="Hostname" value={a.hostname ?? ''} onChange={(v) => mutList('affected_assets', (arr) => updateAt(arr, i, { hostname: v || null }))} />
                      <LabeledInput label="IP" value={a.ip ?? ''} onChange={(v) => mutList('affected_assets', (arr) => updateAt(arr, i, { ip: v || null }))} mono />
                      <LabeledInput label="Role" value={a.role} onChange={(v) => mutList('affected_assets', (arr) => updateAt(arr, i, { role: v }))} placeholder="Domain controller…" />
                      <LabeledSelect label="Compromise Confidence" value={a.compromise_confidence} onChange={(v) => mutList('affected_assets', (arr) => updateAt(arr, i, { compromise_confidence: v as AffectedAsset['compromise_confidence'] }))} options={CONFIDENCE as unknown as string[]} />
                    </div>
                  </Card>
                ))}
              </Section>
            </div>
          </>
        )}

        {tab === 'narrative' && (
          <>
            <Field label="Email Subject">
              <TextInput value={(draft.email_content.subject as string) ?? ''} onChange={(v) => setEmail('subject', v)} placeholder="TLP:AMBER | High | Threat brief | 2026-07-06" />
            </Field>
            {textSections.length === 0 ? (
              <p className="text-[11px] text-muted-foreground">Loading narrative sections…</p>
            ) : (
              textSections.map((s) => (
                <Field key={s.key} label={s.label} hint={!s.enabled ? 'hidden in current sections' : undefined}>
                  <RichTextEditor value={(draft.email_content[s.key] as string) ?? ''} onChange={(v) => setEmail(s.key, v)} />
                </Field>
              ))
            )}
            <p className="text-[10px] text-muted-foreground/60">
              Techniques &amp; IOC tables render automatically from the tabs above. Use <strong className="text-foreground/70">Email Studio</strong> for branding and per-audience polish.
            </p>
          </>
        )}
      </div>
    </div>
  );
}

// ── small building blocks ──────────────────────────────────────────────────────
function Field({ label, hint, children }: { label: string; hint?: string; children: React.ReactNode }) {
  return (
    <div className="space-y-1">
      <div className="flex items-center justify-between gap-2">
        <div className="text-[10px] uppercase tracking-wide text-cyan-400/70 font-medium">{label}</div>
        {hint && <span className="text-[9px] text-muted-foreground/60 text-right">{hint}</span>}
      </div>
      {children}
    </div>
  );
}
function SectionLabel({ children }: { children: React.ReactNode }) {
  return <div className="text-[10px] font-semibold uppercase tracking-wider text-muted-foreground border-b border-border/50 pb-1 pt-1">{children}</div>;
}
function Section({ title, onAdd, addLabel, empty, children }: { title: string; onAdd: () => void; addLabel: string; empty: boolean; children: React.ReactNode }) {
  return (
    <div className="space-y-2">
      <div className="flex items-center justify-between">
        <SectionLabel>{title}</SectionLabel>
        <button onClick={onAdd} className="flex items-center gap-1 text-[11px] text-cyan-400 hover:text-cyan-300"><Plus className="w-3 h-3" />{addLabel}</button>
      </div>
      {empty ? <p className="text-[11px] text-muted-foreground/60 py-3 text-center">None yet — click "{addLabel}".</p> : children}
    </div>
  );
}
function Card({ onRemove, children }: { onRemove: () => void; children: React.ReactNode }) {
  return (
    <div className="relative border border-border rounded p-3 bg-navy-900/40">
      <button onClick={onRemove} className="absolute top-2 right-2 text-red-400/60 hover:text-red-400" title="Remove"><Trash2 className="w-3.5 h-3.5" /></button>
      {children}
    </div>
  );
}
const inputCls = 'w-full bg-secondary/40 border border-border rounded px-2 py-1.5 text-xs text-foreground focus:outline-none focus:ring-1 focus:ring-cyan-500/50';
function TextInput({ value, onChange, placeholder, mono }: { value: string; onChange: (v: string) => void; placeholder?: string; mono?: boolean }) {
  return <input type="text" value={value} placeholder={placeholder} onChange={(e) => onChange(e.target.value)} className={cn(inputCls, mono && 'font-mono')} />;
}
function TextArea({ value, onChange, placeholder, rows = 3 }: { value: string; onChange: (v: string) => void; placeholder?: string; rows?: number }) {
  return <textarea value={value} placeholder={placeholder} rows={rows} onChange={(e) => onChange(e.target.value)} className={cn(inputCls, 'resize-y')} />;
}
function Select({ value, onChange, options }: { value: string; onChange: (v: string) => void; options: string[] }) {
  return <select value={value} onChange={(e) => onChange(e.target.value)} className={inputCls}>{options.map((o) => <option key={o} value={o}>{o}</option>)}</select>;
}
function LabeledInput({ label, ...rest }: { label: string } & Parameters<typeof TextInput>[0]) {
  return <div><label className="text-[9px] uppercase tracking-wide text-muted-foreground">{label}</label><div className="mt-0.5"><TextInput {...rest} /></div></div>;
}
function LabeledSelect({ label, ...rest }: { label: string } & Parameters<typeof Select>[0]) {
  return <div><label className="text-[9px] uppercase tracking-wide text-muted-foreground">{label}</label><div className="mt-0.5"><Select {...rest} /></div></div>;
}
